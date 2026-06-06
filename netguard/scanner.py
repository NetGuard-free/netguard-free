import socket
import subprocess
import re
import ipaddress
import concurrent.futures
import time
import logging

logger = logging.getLogger(__name__)

from netguard import IS_WINDOWS, PSUTIL_AVAILABLE, SCAPY_AVAILABLE, C
from netguard.config import save_devices


class NetworkScanner:
    def __init__(self, network: str, interface: str = None,
                 cfg: dict = None, cprint_func=None, get_limits_func=None):
        self.network = network
        self.interface = interface
        self.cfg = cfg or {}
        self.cprint = cprint_func or (lambda *a: None)
        self.get_limits = get_limits_func or (lambda: {"max_devices": None})
        self.active_devices = {}
        self._health = {
            "last_scan_time": 0,
            "scan_count": 0,
            "errors_last_hour": 0,
            "start_time": time.time(),
            "total_devices_found": 0,
        }

    def get_interface(self) -> str:
        if PSUTIL_AVAILABLE:
            import psutil
            gateways = psutil.net_if_stats()
            for iface, stats in gateways.items():
                if stats.isup and iface not in ('lo', 'loopback'):
                    return iface
        if not IS_WINDOWS:
            try:
                result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'],
                                        capture_output=True, text=True)
                m = re.search(r'dev (\S+)', result.stdout)
                if m:
                    return m.group(1)
            except Exception:
                logger.debug("ip route failed, fallback to eno1")
            return 'eno1'
        else:
            try:
                result = subprocess.run(
                    ['netsh', 'interface', 'show', 'interface'],
                    capture_output=True, text=True
                )
                for line in result.stdout.splitlines():
                    if 'Connected' in line or 'Polaczony' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            return ' '.join(parts[3:])
            except Exception:
                logger.debug("netsh interface query failed, fallback to Ethernet")
            return 'Ethernet'

    def _apply_limit(self, devices: dict) -> dict:
        from netguard.license import get_plan
        plan = get_plan(self.cfg)
        limits = self.get_limits()
        max_dev = limits["max_devices"]
        if max_dev is not None and len(devices) > max_dev:
            trusted = {m: d for m, d in devices.items()
                      if d.get("tag") == "trusted" or d.get("is_host")}
            others = {m: d for m, d in devices.items()
                      if m not in trusted}
            allowed = max_dev - len(trusted)
            trimmed = dict(list(others.items())[:max(0, allowed)])
            devices = {**trusted, **trimmed}
            plan_label = "Free" if plan == "free" else "Home"
            self.cprint("WARN",
                f"Plan {plan_label}: pokazuje {max_dev} urzadzen",
                "Przejdz na wyzszy plan — netguardhome.pl")
        self.active_devices = devices
        return devices

    def scan(self) -> dict:
        if not SCAPY_AVAILABLE:
            return self._fallback_scan()
        from scapy.all import ARP, Ether, srp
        iface = self.interface if self.interface and self.interface != 'auto' else self.get_interface()
        self.cprint("INFO", f"Skanowanie sieci {self.network} przez {iface}...")
        try:
            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, iface=iface, verbose=False)[0]
        except Exception as e:
            self.cprint("WARN", f"Blad skanowania ARP: {e}")
            return self._fallback_scan()
        devices = {}
        for sent, received in result:
            mac = received.hwsrc
            ip = received.psrc
            vendor = self._get_vendor(mac)
            hostname = self.cfg.get("device_names", {}).get(mac) or self._resolve_hostname(ip)
            tag = "trusted" if mac in self.cfg.get("trusted_macs", []) else "new"
            devices[mac] = {
                "ip": ip, "mac": mac, "vendor": vendor,
                "hostname": hostname,
                "status": "online",
                "is_host": False,
                "tag": tag,
            }
        host_ip = self._get_own_ip(iface)
        host_mac = self._get_own_mac(iface)
        if host_ip and host_mac and host_mac not in devices:
            devices[host_mac] = {
                "ip": host_ip, "mac": host_mac,
                "vendor": self._get_vendor(host_mac),
                "hostname": self.cfg.get("device_names", {}).get(host_mac) or socket.gethostname(),
                "status": "online",
                "is_host": True,
                "tag": "trusted",
            }
        elif host_mac and host_mac in devices:
            devices[host_mac]["is_host"] = True
            devices[host_mac]["tag"] = "trusted"
            devices[host_mac]["hostname"] = self.cfg.get("device_names", {}).get(host_mac) or socket.gethostname()
        devices = self._apply_limit(devices)
        self.cprint("OK", f"Znaleziono {len(devices)} urzadzen w sieci")
        return devices

    def _get_own_ip(self, iface: str) -> str:
        try:
            if PSUTIL_AVAILABLE:
                import psutil
                addrs = psutil.net_if_addrs().get(iface, [])
                for a in addrs:
                    if a.family == 2:
                        return a.address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            logger.debug("could not determine own IP for %s", iface)
            return ""

    def _get_own_mac(self, iface: str) -> str:
        try:
            if PSUTIL_AVAILABLE:
                import psutil
                addrs = psutil.net_if_addrs().get(iface, [])
                for a in addrs:
                    if a.family == 17:
                        return a.address
            with open(f"/sys/class/net/{iface}/address") as f:
                return f.read().strip()
        except Exception:
            logger.debug("could not determine own MAC for %s", iface)
            return ""

    def _fallback_scan(self) -> dict:
        if IS_WINDOWS:
            return self._scan_via_arp_command()
        try:
            result = subprocess.run(
                ['nmap', '-sn', '-T4', self.network, '--oG', '-'],
                capture_output=True, text=True, timeout=30
            )
            devices = {}
            for line in result.stdout.split('\n'):
                if 'Host:' in line and 'Status: Up' in line:
                    m = re.search(r'Host: (\S+)', line)
                    if m:
                        ip = m.group(1)
                        mac = self._get_mac_for_ip(ip)
                        if mac:
                            devices[mac] = {"ip": ip, "mac": mac, "status": "online",
                                          "vendor": self._get_vendor(mac),
                                          "hostname": self._resolve_hostname(ip)}
            iface = self.interface if self.interface and self.interface != 'auto' else self.get_interface()
            host_ip = self._get_own_ip(iface)
            host_mac = self._get_own_mac(iface)
            if host_ip and host_mac:
                if host_mac not in devices:
                    devices[host_mac] = {
                        "ip": host_ip, "mac": host_mac, "status": "online",
                        "vendor": self._get_vendor(host_mac),
                        "hostname": self.cfg.get("device_names", {}).get(host_mac) or socket.gethostname(),
                        "is_host": True, "tag": "trusted",
                    }
                else:
                    devices[host_mac]["is_host"] = True
                    devices[host_mac]["tag"] = "trusted"
            return self._apply_limit(devices)
        except Exception as e:
            self.cprint("WARN", f"Fallback scan (nmap) failed: {e}")
            return {}

    def _scan_via_arp_command(self) -> dict:
        devices = {}
        try:
            net = ipaddress.ip_network(self.network, strict=False)
            hosts = list(net.hosts())[:254]

            def _ping(ip):
                try:
                    subprocess.run(["ping", "-n", "1", "-w", "300", str(ip)],
                                   capture_output=True, timeout=2)
                except Exception:
                    pass
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                ex.map(_ping, hosts)
        except Exception:
            logger.warning("ping sweep in _scan_via_arp_command failed")
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                mac = parts[1].replace("-", ":").lower()
                if (re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and
                        re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac) and
                        mac != "ff:ff:ff:ff:ff:ff"):
                    tag = "trusted" if mac in self.cfg.get("trusted_macs", []) else "new"
                    devices[mac] = {
                        "ip": ip, "mac": mac, "status": "online",
                        "vendor": self._get_vendor(mac),
                        "hostname": self.cfg.get("device_names", {}).get(mac) or self._resolve_hostname(ip),
                        "is_host": False, "tag": tag,
                    }
        except Exception as e:
            self.cprint("WARN", f"Skan Windows (arp -a): {e}")
        return self._apply_limit(devices)

    def _get_vendor(self, mac: str) -> str:
        try:
            from manuf import manuf as _manuf
            if not hasattr(NetworkScanner, '_manuf_parser'):
                NetworkScanner._manuf_parser = _manuf.MacParser()
            result = NetworkScanner._manuf_parser.get_manuf_long(mac)
            if result:
                return result
        except Exception:
            logger.debug("manuf parser unavailable for %s", mac)
        oui = mac[:8].upper()
        return f"Nieznany ({oui})"

    def _resolve_hostname(self, ip: str) -> str:
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name and name != ip:
                return name.split('.')[0]
        except Exception:
            logger.debug("socket gethostbyaddr failed for %s", ip)
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=2
            )
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'GROUP' not in line:
                    name = line.strip().split()[0]
                    if name and name != '*':
                        return name
        except Exception:
            logger.debug("nmblookup failed for %s", ip)
        try:
            result = subprocess.run(
                ['avahi-resolve', '-a', ip],
                capture_output=True, text=True, timeout=2
            )
            if result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1].rstrip('.')
        except Exception:
            logger.debug("avahi-resolve failed for %s", ip)
        return ""

    def _get_mac_for_ip(self, ip: str) -> str:
        try:
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            m = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', result.stdout)
            return m.group(1) if m else None
        except Exception:
            logger.debug("arp -n failed for %s", ip)
            return None
