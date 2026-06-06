import time
import threading
import ipaddress
import datetime
import gc
from collections import defaultdict, deque

from netguard import SCAPY_AVAILABLE, PSUTIL_AVAILABLE, C
from netguard.models import (
    DNS_WHITELIST_SUFFIXES, MALICIOUS_DOMAINS, CHILD_BLOCK_DOMAINS,
    CHILD_SAFESEARCH_DOMAINS, _expand_blocked, TOR_EXIT_NODES
)


class PacketAnalyzer:
    def __init__(self, cfg: dict = None, cprint_func=None, db=None, scanner=None):
        self.cfg = cfg or {}
        self.cprint = cprint_func or (lambda *a: None)
        self.db = db
        self.scanner = scanner
        self.dns_queries = defaultdict(lambda: deque(maxlen=1000))
        self.connections = defaultdict(lambda: deque(maxlen=1000))
        self.port_access = defaultdict(dict)
        self._last_cleanup = 0.0
        self._last_deep_cleanup = 0.0
        self.arp_table = {}
        self.alerts_queue = deque(maxlen=100)
        self.running = False
        self.interface = None
        self.port_counts = defaultdict(int)
        self.port_devices = defaultdict(lambda: defaultdict(int))
        self.device_bytes = defaultdict(int)
        self.traffic_samples = deque(maxlen=60)
        self.child_online = defaultdict(dict)
        self.child_dns_hist = defaultdict(lambda: defaultdict(int))
        self.child_dns_date = {}
        self.child_night_alerted = {}
        self.child_night_pkt = {}
        self._last_io = None
        self.iot_devices = {}
        self._health = {
            "last_packet_time": 0,
            "packets_captured": 0,
            "errors_last_hour": 0,
            "running": False,
            "start_time": time.time(),
        }
        self.iot_traffic = defaultdict(lambda: defaultdict(int))

    def start(self, interface: str):
        if not SCAPY_AVAILABLE:
            self.cprint("WARN", "Scapy niedostepne — analiza pakietow wylaczona")
            return
        self.running = True
        self._health["running"] = True
        self.interface = interface
        t = threading.Thread(target=self._capture_loop, daemon=True)
        t.start()
        t2 = threading.Thread(target=self._io_sampler_loop, daemon=True)
        t2.start()
        self.cprint("OK", f"Przechwytywanie pakietow uruchomione na {interface}")

    def _io_sampler_loop(self):
        iface = self.interface
        while self.running:
            try:
                if PSUTIL_AVAILABLE:
                    import psutil
                    counters = psutil.net_io_counters(pernic=True)
                    data = counters.get(iface)
                    if data:
                        recv = data.bytes_recv
                        sent = data.bytes_sent
                        if self._last_io is not None:
                            last_recv, last_sent = self._last_io
                            self.traffic_samples.append({
                                "t": int(time.time()),
                                "down": max(0, recv - last_recv),
                                "up": max(0, sent - last_sent),
                            })
                        self._last_io = (recv, sent)
            except Exception:
                pass
            time.sleep(10)

    def stop(self):
        self.running = False

    def _safesearch_dns(self, pkt, query_name, safesearch_ip):
        try:
            if SCAPY_AVAILABLE:
                from scapy.all import IP, UDP, DNS, DNSRR, scapy_send
                if UDP in pkt and IP in pkt:
                    resp = (
                        IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                        UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                        DNS(id=pkt[DNS].id, qr=1, aa=1, rcode=0,
                            qd=pkt[DNS].qd,
                            an=DNSRR(rrname=pkt[DNS].qd.qname, type='A',
                                     rdata=safesearch_ip, ttl=60))
                    )
                    scapy_send(resp, iface=self.interface, verbose=0)
        except Exception:
            pass

    def _block_child_dns(self, pkt, query_name, src_ip, src_mac, now):
        try:
            if SCAPY_AVAILABLE and pkt.haslayer('UDP') and pkt.haslayer('IP'):
                from scapy.all import IP, UDP, DNS
                resp = (
                    IP(src=pkt[IP].dst, dst=src_ip) /
                    UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
                    DNS(id=pkt[DNS].id, qr=1, aa=1, rcode=3, qd=pkt[DNS].qd)
                )
                from scapy.all import send as scapy_send
                scapy_send(resp, iface=self.interface, verbose=0)
        except Exception:
            pass
        alert = {"type": "CHILD_BLOCK", "severity": "INFO",
                 "ip": src_ip, "mac": src_mac, "domain": query_name, "time": now}
        if not any(a.get("type") == "CHILD_BLOCK" and a.get("ip") == src_ip
                   and a.get("domain") == query_name
                   and now - a.get("time", 0) < 300 for a in self.alerts_queue):
            self.alerts_queue.append(alert)
            if self.db:
                self.db.add_event("CHILD_BLOCK", "INFO",
                    f"Ochrona dziecieca: zablokowano {query_name} ({src_ip})", alert)
            name = self.cfg.get("device_names", {}).get(src_mac, src_ip)
            self.cprint("INFO", f"Zablokowano: {query_name}", f"Urzadzenie: {name}")

    def _cleanup_stale(self, now: float):
        cutoff_port = now - 600
        stale = [ip for ip, ports in self.port_access.items()
                 if not ports or all(t < cutoff_port for t in ports.values())]
        for ip in stale:
            del self.port_access[ip]
        cutoff_dns = now - 120
        stale = [ip for ip, dq in self.dns_queries.items()
                 if not dq or all(t < cutoff_dns for t, _ in dq)]
        for ip in stale:
            del self.dns_queries[ip]
        cutoff_conn = now - 120
        stale = [ip for ip, cq in self.connections.items()
                 if not cq or all(t < cutoff_conn for t, _ in cq)]
        for ip in stale:
            del self.connections[ip]
        cutoff_arp = now - 3600
        if len(self.arp_table) > 500:
            old = [ip for ip in list(self.arp_table.keys())[:len(self.arp_table)-500]]
            for ip in old:
                del self.arp_table[ip]
        if now - self._last_deep_cleanup > 3600:
            self._last_deep_cleanup = now
            cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=7)).strftime("%Y-%m-%d")
            for mac in list(self.child_online):
                old_dates = [k for k in self.child_online[mac] if k < cutoff_date]
                for d in old_dates:
                    del self.child_online[mac][d]
            cutoff_iot_hour = int(now // 3600) - 48
            for ip in list(self.iot_traffic):
                old_hours = [h for h in self.iot_traffic[ip] if h < cutoff_iot_hour]
                for h in old_hours:
                    del self.iot_traffic[ip][h]
                if not self.iot_traffic[ip]:
                    del self.iot_traffic[ip]
            self.device_bytes.clear()
            self.port_counts.clear()
            self.port_devices.clear()
            gc.collect()
        self._last_cleanup = now

    def _capture_loop(self):
        from scapy.all import conf as scapy_conf, sniff
        scapy_conf.verb = 0
        while self.running:
            try:
                sniff(iface=self.interface, prn=self._process_packet,
                      store=False, stop_filter=lambda _: not self.running)
            except OSError as e:
                if not self.running:
                    break
                self.cprint("WARN", f"Sniffer: utrata interfejsu ({e}), ponowna proba za 10s...")
                time.sleep(10)
            except Exception as e:
                if not self.running:
                    break
                self.cprint("WARN", f"Blad przechwytywania pakietow: {e}, ponowna proba za 10s...")
                time.sleep(10)

    def _process_packet(self, pkt):
        try:
            self._health["last_packet_time"] = time.time()
            self._health["packets_captured"] += 1
            from scapy.all import ARP, IP, TCP, UDP, DNS, DNSQR, Ether
            if ARP in pkt and pkt[ARP].op == 2:
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in self.arp_table and self.arp_table[ip] != mac:
                    alert = {
                        "type": "ARP_SPOOFING", "severity": "CRITICAL",
                        "ip": ip, "original_mac": self.arp_table[ip],
                        "new_mac": mac, "time": time.time()
                    }
                    self.alerts_queue.append(alert)
                    if self.db:
                        self.db.add_event("ARP_SPOOFING", "CRITICAL",
                            f"ARP Spoofing: IP {ip} teraz ma MAC {mac} zamiast {self.arp_table[ip]}", alert)
                    self.cprint("CRIT", f"ARP SPOOFING WYKRYTY! IP {ip}",
                                f"Oryginalny MAC: {self.arp_table[ip]} -> Nowy: {mac}")
                self.arp_table[ip] = mac
            if IP not in pkt:
                return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            now = time.time()
            if now - self._last_cleanup > 300:
                self._cleanup_stale(now)
            if DNS in pkt and DNSQR in pkt:
                query_name = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                self.dns_queries[src_ip].append((now, query_name))
                is_whitelisted = any(query_name.endswith(s) for s in DNS_WHITELIST_SUFFIXES)
                if not is_whitelisted:
                    for domain in MALICIOUS_DOMAINS:
                        if domain in query_name:
                            alert = {"type": "MALICIOUS_DNS", "severity": "CRITICAL",
                                    "ip": src_ip, "domain": query_name, "time": now}
                            self.alerts_queue.append(alert)
                            if self.db:
                                self.db.add_event("MALICIOUS_DNS", "CRITICAL",
                                    f"Zapytanie DNS do zlosliwej domeny: {query_name} z {src_ip}", alert)
                            self.cprint("CRIT", f"Zlosliwa domena: {query_name}", f"Zrodlo: {src_ip}")
                recent = [t for t, _ in self.dns_queries[src_ip] if now - t < 60]
                if len(recent) > self.cfg.get("max_dns_per_min", 300):
                    src_mac_dns = self.arp_table.get(src_ip, "")
                    if not src_mac_dns and self.scanner:
                        for _dm, _dd in self.scanner.active_devices.items():
                            if _dd.get("ip") == src_ip:
                                src_mac_dns = _dm
                                break
                    trusted_macs_lower = {m.lower() for m in self.cfg.get("trusted_macs", [])}
                    is_host_dns = any(d.get("ip") == src_ip and d.get("is_host")
                                      for d in self.scanner.active_devices.values()) if self.scanner else False
                    if src_mac_dns.lower() not in trusted_macs_lower and not is_host_dns:
                        alert = {"type": "DNS_TUNNEL", "severity": "HIGH",
                                "ip": src_ip, "count": len(recent), "time": now}
                        if not any(a.get("type") == "DNS_TUNNEL" and a.get("ip") == src_ip
                                   and now - a.get("time", 0) < 300 for a in self.alerts_queue):
                            self.alerts_queue.append(alert)
                            if self.db:
                                self.db.add_event("DNS_TUNNEL", "HIGH",
                                    f"Anomalia DNS: {len(recent)} zapytan/min z {src_ip}", alert)
                            self.cprint("WARN", f"DNS Tunneling suspect: {src_ip}", f"{len(recent)} queries/min")
                child_macs = self.cfg.get("child_macs", [])
                if child_macs and not is_whitelisted and pkt[DNS].qr == 0:
                    src_mac = self.arp_table.get(src_ip, "").lower()
                    if not src_mac and self.scanner:
                        for _dm, _dd in self.scanner.active_devices.items():
                            if _dd.get("ip") == src_ip:
                                src_mac = _dm.lower()
                                break
                    if src_mac and src_mac in child_macs:
                        safesearch_ip = CHILD_SAFESEARCH_DOMAINS.get(query_name)
                        if safesearch_ip:
                            self._safesearch_dns(pkt, query_name, safesearch_ip)
                        else:
                            parts = query_name.split('.')
                            base = '.'.join(parts[-2:]) if len(parts) >= 2 else query_name
                            custom_blocked = _expand_blocked(self.cfg.get("custom_block_domains", {}).get(src_mac, []))
                            if base in custom_blocked or query_name in custom_blocked:
                                self._block_child_dns(pkt, query_name, src_ip, src_mac, now)
                            elif base in CHILD_BLOCK_DOMAINS:
                                self._block_child_dns(pkt, query_name, src_ip, src_mac, now)
                        _today_dns = datetime.datetime.now().strftime("%Y-%m-%d")
                        if self.child_dns_date.get(src_mac) != _today_dns:
                            self.child_dns_hist[src_mac].clear()
                            self.child_dns_date[src_mac] = _today_dns
                        _parts = query_name.split('.')
                        _base = '.'.join(_parts[-2:]) if len(_parts) >= 2 else query_name
                        self.child_dns_hist[src_mac][_base] += 1
            if Ether in pkt:
                src_mac = pkt[Ether].src.lower()
                pkt_len = len(pkt)
                self.device_bytes[src_mac] += pkt_len
                if src_mac in self.cfg.get("child_macs", []):
                    _dt = datetime.datetime.now()
                    _today = _dt.strftime("%Y-%m-%d")
                    _entry = self.child_online[src_mac]
                    if _today not in _entry:
                        _entry[_today] = {"first": _dt.strftime("%H:%M"),
                                          "last": _dt.strftime("%H:%M"),
                                          "total_minutes": 0.0, "last_ts": now}
                    else:
                        _day = _entry[_today]
                        _gap = now - _day.get("last_ts", now)
                        if _gap < 300:
                            _day["total_minutes"] += _gap / 60
                        _day["last"] = _dt.strftime("%H:%M")
                        _day["last_ts"] = now
                    if _dt.hour >= 22 and self.child_night_alerted.get(src_mac) != _today:
                        _nc = self.child_night_pkt.get(src_mac)
                        if _nc is None or _nc[0] != _today:
                            self.child_night_pkt[src_mac] = (_today, 1, now)
                        else:
                            _cnt = _nc[1] + 1
                            _first_ts = _nc[2]
                            self.child_night_pkt[src_mac] = (_today, _cnt, _first_ts)
                            if _cnt >= 10 and (now - _first_ts) <= 300:
                                self.child_night_alerted[src_mac] = _today
                                _dev = self.scanner.active_devices.get(src_mac, {}) if self.scanner else {}
                                _name = _dev.get("hostname", src_mac)
                                if self.db:
                                    self.db.add_event("CHILD_NIGHT", "HIGH",
                                        f"Aktywnosc nocna: {_name} o {_dt.strftime('%H:%M')}", {"mac": src_mac})
                                self.cprint("WARN", f"Aktywnosc nocna dziecka: {_name}", _dt.strftime("%H:%M"))
                            elif (now - _first_ts) > 300:
                                self.child_night_pkt[src_mac] = (_today, 1, now)
            if TCP in pkt or UDP in pkt:
                dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
                self.port_counts[dst_port] += 1
                if 'src_mac' in dir() and src_mac:
                    self.port_devices[dst_port][src_mac] += 1
                try:
                    _in_lan = ipaddress.ip_address(src_ip) in ipaddress.ip_network(self.cfg["network_range"], strict=False)
                except (ValueError, KeyError):
                    _in_lan = False
                if _in_lan:
                    self.port_access[src_ip][dst_port] = now
                    recent_ports = sum(1 for t in self.port_access[src_ip].values() if now - t < 120)
                    if recent_ports > self.cfg.get("port_scan_threshold", 10):
                        src_mac_ps = self.arp_table.get(src_ip, "")
                        if not src_mac_ps and self.scanner:
                            for _dm, _dd in self.scanner.active_devices.items():
                                if _dd.get("ip") == src_ip:
                                    src_mac_ps = _dm
                                    break
                        trusted_macs_lower = {m.lower() for m in self.cfg.get("trusted_macs", [])}
                        is_host = any(d.get("ip") == src_ip and d.get("is_host")
                                      for d in self.scanner.active_devices.values()) if self.scanner else False
                        if src_mac_ps.lower() not in trusted_macs_lower and not is_host:
                            alert = {"type": "PORT_SCAN", "severity": "HIGH",
                                    "ip": src_ip, "ports": recent_ports, "time": now}
                            if not any(a.get("type") == "PORT_SCAN" and a.get("ip") == src_ip
                                       and now - a.get("time", 0) < 300 for a in self.alerts_queue):
                                self.alerts_queue.append(alert)
                                if self.db:
                                    self.db.add_event("PORT_SCAN", "HIGH",
                                        f"Skanowanie portow z {src_ip}: {recent_ports} portow/2min", alert)
                                self.cprint("WARN", f"Port scan: {src_ip}", f"Skanowane porty: {recent_ports}/2min")
            if dst_ip in TOR_EXIT_NODES or src_ip in TOR_EXIT_NODES:
                alert = {"type": "TOR_CONNECTION", "severity": "HIGH",
                        "src": src_ip, "dst": dst_ip, "time": now}
                if not any(a.get("type") == "TOR_CONNECTION" and
                           (a.get("src") == src_ip or a.get("dst") == dst_ip)
                           and now - a.get("time", 0) < 600 for a in self.alerts_queue):
                    self.alerts_queue.append(alert)
                    if self.db:
                        self.db.add_event("TOR_CONNECTION", "HIGH",
                            f"Polaczenie z wezlem Tor: {src_ip} -> {dst_ip}", alert)
                    self.cprint("WARN", f"Tor connection: {src_ip} -> {dst_ip}")
            self._monitor_iot(src_ip, dst_ip, pkt, now)
        except Exception:
            pass

    def _monitor_iot(self, src_ip: str, dst_ip: str, pkt, now: float):
        from scapy.all import IP
        from netguard.models import _expand_blocked
        iot_ip = None
        iot_cfg = None
        for mac, cfg in self.iot_devices.items():
            if src_ip == cfg.get("ip") or dst_ip == cfg.get("ip"):
                iot_ip = cfg["ip"]
                iot_cfg = cfg
                break
        if not iot_ip or not iot_cfg:
            return
        try:
            local_network = ipaddress.ip_network(self.cfg["network_range"], strict=False)
        except (ValueError, KeyError):
            return
        is_src_iot = (src_ip == iot_ip)
        if iot_cfg.get("alert_on_local_scan") and is_src_iot:
            try:
                dst_addr = ipaddress.ip_address(dst_ip)
                if dst_addr in local_network and dst_ip != self.cfg.get("gateway", "192.168.100.1"):
                    alert = {
                        "type": "IOT_LOCAL_SCAN", "severity": "CRITICAL",
                        "iot": iot_cfg["name"], "src": src_ip, "dst": dst_ip, "time": now
                    }
                    if not any(a.get("type") == "IOT_LOCAL_SCAN" and
                               a.get("dst") == dst_ip and
                               now - a.get("time", 0) < 300 for a in self.alerts_queue):
                        self.alerts_queue.append(alert)
                        if self.db:
                            self.db.add_event("IOT_LOCAL_SCAN", "CRITICAL",
                                f"{iot_cfg['name']} probuje polaczyc sie z {dst_ip} w sieci lokalnej!", alert)
                        self.cprint("CRIT", f"IoT skanuje siec lokalna!",
                                   f"{iot_cfg['name']} ({src_ip}) -> {dst_ip}")
            except Exception:
                pass
        if is_src_iot and IP in pkt:
            pkt_len = len(pkt)
            hour_key = int(now // 3600)
            self.iot_traffic[iot_ip][hour_key] += pkt_len
            mb_this_hour = self.iot_traffic[iot_ip][hour_key] / (1024 * 1024)
            max_mb = iot_cfg.get("max_upload_mb_per_hour", 50)
            if mb_this_hour > max_mb:
                alert = {
                    "type": "IOT_HIGH_UPLOAD", "severity": "HIGH",
                    "iot": iot_cfg["name"], "ip": iot_ip,
                    "mb": round(mb_this_hour, 1), "time": now
                }
                if not any(a.get("type") == "IOT_HIGH_UPLOAD" and
                           a.get("ip") == iot_ip and
                           now - a.get("time", 0) < 3600 for a in self.alerts_queue):
                    self.alerts_queue.append(alert)
                    if self.db:
                        self.db.add_event("IOT_HIGH_UPLOAD", "HIGH",
                            f"{iot_cfg['name']} wyslal {mb_this_hour:.1f} MB w ciagu godziny", alert)
                    self.cprint("WARN", f"IoT nadmierny upload: {iot_cfg['name']}",
                               f"{mb_this_hour:.1f} MB / {max_mb} MB limit")
        if iot_cfg.get("log_all_connections") and is_src_iot:
            try:
                dst_addr = ipaddress.ip_address(dst_ip)
                if dst_addr not in local_network:
                    allowed = iot_cfg.get("allowed_external", [])
                    is_allowed = any(dst_ip.startswith(prefix) for prefix in allowed)
                    if not is_allowed:
                        alert = {
                            "type": "IOT_UNKNOWN_SERVER", "severity": "HIGH",
                            "iot": iot_cfg["name"], "src": src_ip, "dst": dst_ip, "time": now
                        }
                        if not any(a.get("type") == "IOT_UNKNOWN_SERVER" and
                                   a.get("dst") == dst_ip and
                                   now - a.get("time", 0) < 3600 for a in self.alerts_queue):
                            self.alerts_queue.append(alert)
                            if self.db:
                                self.db.add_event("IOT_UNKNOWN_SERVER", "HIGH",
                                    f"{iot_cfg['name']} laczy sie z nieznanym serwerem: {dst_ip}", alert)
                            self.cprint("WARN", f"IoT nieznany serwer: {iot_cfg['name']}",
                                       f"Polaczenie z {dst_ip}")
            except Exception:
                pass

    def get_recent_alerts(self, n: int = 20) -> list:
        return list(self.alerts_queue)[-n:]
