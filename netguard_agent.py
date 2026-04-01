#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         NETGUARD AI — Lokalny Agent Sieci Domowej            ║
║         Wersja: 1.0.0  |  Tryb: 100% lokalny                ║
║         Autor: Twój agent prywatności                        ║
╚══════════════════════════════════════════════════════════════╝

URUCHOMIENIE:
  sudo python3 netguard_agent.py                     # tryb podstawowy
  sudo python3 netguard_agent.py --llm               # z Ollama LLM
  sudo python3 netguard_agent.py --email ty@mail.com # z alertami email
  sudo python3 netguard_agent.py --dashboard         # uruchamia web UI

WYMAGANIA:
  pip install scapy psutil flask requests colorama ollama
  (Opcjonalnie) ollama pull llama3.2
"""

import os, sys, json, time, socket, struct, hashlib, logging, threading
import subprocess, ipaddress, re, datetime, signal
from collections import defaultdict, deque
from typing import Optional

# ── Sprawdź uprawnienia ───────────────────────────────────────
if os.geteuid() != 0:
    print("❌ Ten skrypt wymaga uprawnień root/administrator.")
    print("   Uruchom: sudo python3 netguard_agent.py")
    sys.exit(1)

# ── Importy opcjonalne ────────────────────────────────────────
try:
    from scapy.all import (ARP, Ether, srp, sniff, IP, TCP, UDP, DNS,
                           DNSQR, DNSRR, conf as scapy_conf)
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  scapy niedostępne. Instaluj: pip install scapy")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from flask import Flask, jsonify, request, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    C = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "blue": Fore.CYAN, "gray": Fore.WHITE, "bold": Style.BRIGHT, "reset": Style.RESET_ALL
    }
except ImportError:
    C = defaultdict(str)

# ══════════════════════════════════════════════════════════════
# KONFIGURACJA — wczytywana z config.json
# ══════════════════════════════════════════════════════════════

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

CONFIG_DEFAULTS = {
    "network_range": "auto",
    "interface": "auto",
    "scan_interval": 60,
    "packet_capture": True,
    "llm_model": "llama3.2",
    "alert_email": "",
    "dashboard_port": 8767,
    "max_dns_per_min": 300,
    "max_connections_per_min": 200,
    "port_scan_threshold": 10,
    "log_file": "/var/log/netguard.log",
    "db_file": "/var/lib/netguard/devices.json",
    "trusted_macs": [],
    "blocked_macs": [],
    "device_names": {},
    "iot_devices": {},
    "router": {"sync_interval": 60},
    "smtp": {"host": "smtp.gmail.com", "port": 587, "user": "", "password": ""},
}

def _detect_network():
    """Auto-wykryj interfejs i zakres sieci."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r"dev (\S+)", result.stdout)
        iface = m.group(1) if m else "eth0"
        # Znajdź zakres sieci dla interfejsu
        result2 = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show", iface],
            capture_output=True, text=True, timeout=5
        )
        m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", result2.stdout)
        if m2:
            net = str(ipaddress.ip_network(m2.group(1), strict=False))
            return iface, net
    except:
        pass
    return "eth0", "192.168.1.0/24"

def _run_wizard():
    """Wizard pierwszego uruchomienia — zbiera podstawową konfigurację."""
    print("\n" + "═"*60)
    print("  NetGuard AI — Pierwsze uruchomienie")
    print("  Skonfigurujmy agenta dla Twojej sieci")
    print("═"*60 + "\n")

    iface, net = _detect_network()
    print(f"  Wykryto interfejs: {iface}")
    print(f"  Wykryto sieć:      {net}\n")

    cfg = dict(CONFIG_DEFAULTS)

    # Interfejs
    ans = input(f"  Interfejs sieciowy [{iface}]: ").strip()
    cfg["interface"] = ans if ans else iface

    # Sieć
    ans = input(f"  Zakres sieci [{net}]: ").strip()
    cfg["network_range"] = ans if ans else net

    # Email
    ans = input("  Email do powiadomień (Enter aby pominąć): ").strip()
    cfg["alert_email"] = ans
    if ans:
        cfg["smtp"]["user"] = ans
        print("  ℹ Hasło SMTP ustaw później w config.json (smtp.password)")

    # Port dashboardu
    ans = input("  Port dashboardu [8767]: ").strip()
    cfg["dashboard_port"] = int(ans) if ans.isdigit() else 8767

    # Zapisz
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

    print(f"\n  ✓ Konfiguracja zapisana w {CONFIG_FILE}")
    print("  ✓ Możesz ją edytować w dowolnym momencie\n")
    return cfg

def load_config() -> dict:
    """Wczytaj konfigurację z pliku. Uruchom wizard jeśli brak pliku."""
    cfg = dict(CONFIG_DEFAULTS)

    if not os.path.exists(CONFIG_FILE):
        # Pierwsze uruchomienie — wizard
        cfg = _run_wizard()
    else:
        try:
            with open(CONFIG_FILE) as f:
                user_cfg = json.load(f)
            # Scal z domyślnymi (user_cfg nadpisuje defaults)
            cfg.update(user_cfg)
            # Scal zagnieżdżone słowniki
            for key in ("smtp", "router"):
                if key in CONFIG_DEFAULTS:
                    merged = dict(CONFIG_DEFAULTS[key])
                    merged.update(user_cfg.get(key, {}))
                    cfg[key] = merged
        except Exception as e:
            print(f"⚠️  Błąd wczytywania config.json: {e} — używam domyślnych")

    # Auto-wykryj sieć jeśli "auto"
    if cfg.get("network_range") == "auto" or cfg.get("interface") == "auto":
        iface, net = _detect_network()
        if cfg.get("interface") == "auto":
            cfg["interface"] = iface
        if cfg.get("network_range") == "auto":
            cfg["network_range"] = net

    return cfg

def save_config():
    """Zapisz aktualną konfigurację do pliku."""
    try:
        saveable = {k: v for k, v in CONFIG.items()
                    if k not in ("log_file", "db_file")}
        with open(CONFIG_FILE, "w") as f:
            json.dump(saveable, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"⚠️  Błąd zapisu config.json: {e}")

def _get_or_create_token() -> str:
    """Pobierz lub wygeneruj token bezpieczeństwa dashboardu."""
    token_file = os.path.join(os.path.dirname(CONFIG_FILE), ".netguard_token")
    if os.path.exists(token_file):
        try:
            with open(token_file) as f:
                token = f.read().strip()
            if len(token) == 32:
                return token
        except:
            pass
    # Wygeneruj nowy token
    token = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    try:
        with open(token_file, "w") as f:
            f.write(token)
        os.chmod(token_file, 0o600)  # tylko właściciel może czytać
    except:
        pass
    return token

CONFIG = load_config()

# Token bezpieczeństwa — generowany automatycznie, przechowywany lokalnie
DASHBOARD_TOKEN = _get_or_create_token()

# Znane złośliwe domeny (mini-lista — w pełnej wersji pobierana z blocklists)
MALICIOUS_DOMAINS = {
    "phishing-test.com", "malware-c2.net", "eviltracker.xyz",
    "0.0.0.0", "tracking.evil.ru",
}

# Węzły Tor Exit (przykładowe — pełna lista: https://check.torproject.org/torbulkexitlist)
TOR_EXIT_NODES = {
    "185.220.101.0", "185.220.102.0", "45.154.255.0",
}

# ── Konfiguracja monitorowania IoT (wczytywana z config.json) ─
IOT_DEVICES = CONFIG.get("iot_devices", {})

# Liczniki ruchu IoT (ip -> {hour -> bytes})
IOT_TRAFFIC = defaultdict(lambda: defaultdict(int))


# ══════════════════════════════════════════════════════════════
# LOGGER
# ══════════════════════════════════════════════════════════════
os.makedirs(os.path.dirname(CONFIG["log_file"]), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger("netguard")

def cprint(level: str, msg: str, detail: str = ""):
    colors = {"INFO": C["blue"], "WARN": C["yellow"], "CRIT": C["red"], "OK": C["green"]}
    icons  = {"INFO": "ℹ", "WARN": "⚠", "CRIT": "🔴", "OK": "✅"}
    c = colors.get(level, "")
    i = icons.get(level, "●")
    print(f"{c}{C['bold']}{i} [{level}]{C['reset']} {msg}")
    if detail:
        print(f"   {C['gray']}{detail}{C['reset']}")

# ══════════════════════════════════════════════════════════════
# BAZA URZĄDZEŃ (plik JSON lokalny)
# ══════════════════════════════════════════════════════════════
class DeviceDB:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.data = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {"devices": {}, "events": [], "rules": []}

    def save(self):
        with open(self.path, 'w') as f:
            json.dump(self.data, f, indent=2, default=str)

    def get_device(self, mac: str) -> Optional[dict]:
        return self.data["devices"].get(mac)

    def upsert_device(self, mac: str, info: dict):
        existing = self.data["devices"].get(mac, {})
        is_new = not existing
        info["first_seen"] = existing.get("first_seen", datetime.datetime.now().isoformat())
        info["last_seen"] = datetime.datetime.now().isoformat()
        info["seen_count"] = existing.get("seen_count", 0) + 1
        self.data["devices"][mac] = {**existing, **info}
        self.save()
        return is_new

    def add_event(self, event_type: str, severity: str, description: str, data: dict = None):
        event = {
            "id": hashlib.md5(f"{time.time()}{event_type}".encode()).hexdigest()[:8],
            "timestamp": datetime.datetime.now().isoformat(),
            "type": event_type,
            "severity": severity,
            "description": description,
            "data": data or {}
        }
        self.data["events"].insert(0, event)
        self.data["events"] = self.data["events"][:500]  # max 500 eventów
        self.save()
        return event

db = DeviceDB(CONFIG["db_file"])

# ══════════════════════════════════════════════════════════════
# MODUŁ 1: SKANER SIECI (ARP)
# ══════════════════════════════════════════════════════════════
class NetworkScanner:
    def __init__(self, network: str, interface: str = None):
        self.network = network
        self.interface = interface
        self.active_devices = {}

    def get_interface(self) -> str:
        """Automatycznie wykrywa interfejs sieciowy"""
        if PSUTIL_AVAILABLE:
            gateways = psutil.net_if_stats()
            for iface, stats in gateways.items():
                if stats.isup and iface not in ('lo', 'loopback'):
                    return iface
        # Fallback — sprawdź przez routing
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'],
                                    capture_output=True, text=True)
            m = re.search(r'dev (\S+)', result.stdout)
            if m: return m.group(1)
        except:
            pass
        return 'eno1'

    def scan(self) -> dict:
        """Skanuj sieć przez ARP i zwróć listę urządzeń"""
        if not SCAPY_AVAILABLE:
            return self._fallback_scan()

        iface = self.interface if self.interface and self.interface != 'auto' else self.get_interface()
        cprint("INFO", f"Skanowanie sieci {self.network} przez {iface}...")

        try:
            arp = ARP(pdst=self.network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, iface=iface, verbose=False)[0]
        except Exception as e:
            cprint("WARN", f"Błąd skanowania ARP: {e}")
            return self._fallback_scan()

        devices = {}
        for sent, received in result:
            mac = received.hwsrc
            ip  = received.psrc
            vendor = self._get_vendor(mac)
            hostname = CONFIG["device_names"].get(mac) or self._resolve_hostname(ip)
            tag = "trusted" if mac in CONFIG["trusted_macs"] else "new"
            devices[mac] = {
                "ip": ip, "mac": mac, "vendor": vendor,
                "hostname": hostname,
                "status": "online",
                "is_host": False,
                "tag": tag,
            }

        # Dodaj własny komputer (host) jeśli go nie ma
        host_ip = self._get_own_ip(iface)
        host_mac = self._get_own_mac(iface)
        if host_ip and host_mac and host_mac not in devices:
            devices[host_mac] = {
                "ip": host_ip,
                "mac": host_mac,
                "vendor": self._get_vendor(host_mac),
                "hostname": CONFIG["device_names"].get(host_mac) or socket.gethostname(),
                "status": "online",
                "is_host": True,
                "tag": "trusted",
            }
        elif host_mac and host_mac in devices:
            devices[host_mac]["is_host"] = True
            devices[host_mac]["tag"] = "trusted"
            devices[host_mac]["hostname"] = CONFIG["device_names"].get(host_mac) or socket.gethostname()

        self.active_devices = devices
        cprint("OK", f"Znaleziono {len(devices)} urządzeń w sieci")
        return devices

    def _get_own_ip(self, iface: str) -> str:
        """Pobierz własny adres IP na danym interfejsie"""
        try:
            if PSUTIL_AVAILABLE:
                addrs = psutil.net_if_addrs().get(iface, [])
                for a in addrs:
                    if a.family == 2:  # AF_INET
                        return a.address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return ""

    def _get_own_mac(self, iface: str) -> str:
        """Pobierz własny adres MAC"""
        try:
            if PSUTIL_AVAILABLE:
                addrs = psutil.net_if_addrs().get(iface, [])
                for a in addrs:
                    if a.family == 17:  # AF_PACKET (Linux)
                        return a.address
            with open(f"/sys/class/net/{iface}/address") as f:
                return f.read().strip()
        except:
            return ""

    def _fallback_scan(self) -> dict:
        """Skan przez nmap jeśli scapy niedostępne"""
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
            return devices
        except Exception as e:
            cprint("WARN", f"Fallback scan failed: {e}")
            return {}

    def _get_vendor(self, mac: str) -> str:
        """Wyszukaj producenta na podstawie OUI (pierwsze 3 bajty MAC)"""
        # Mini-baza OUI — w produkcji użyj pełnej bazy IEEE
        oui_db = {
            "a4:c3:f0": "Apple", "f0:18:98": "Apple", "3c:15:c2": "Apple",
            "d4:e8:b2": "Samsung", "b4:6f:2a": "Samsung",
            "b8:27:eb": "Raspberry Pi Foundation", "dc:a6:32": "Raspberry Pi",
            "00:50:56": "VMware", "08:00:27": "VirtualBox",
            "44:d9:e7": "Hikvision", "4c:bd:8f": "Hikvision",
            "fc:aa:14": "Dell", "18:66:da": "Dell",
            "90:9a:4a": "TP-Link", "50:c7:bf": "TP-Link",
            "3c:52:a1": "HP", "b4:99:ba": "HP",
        }
        oui = mac[:8].lower()
        return oui_db.get(oui, f"Nieznany ({oui.upper()})")

    def _resolve_hostname(self, ip: str) -> str:
        """Próbuj rozpoznać nazwę urządzenia kilkoma metodami"""
        # 1. Reverse DNS
        try:
            name = socket.gethostbyaddr(ip)[0]
            if name and name != ip:
                return name.split('.')[0]  # tylko hostname bez domeny
        except:
            pass
        # 2. NetBIOS (nmblookup) — działa dla Windows/Samba
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
        except:
            pass
        # 3. avahi-resolve (mDNS) — działa dla Linux/macOS/IoT
        try:
            result = subprocess.run(
                ['avahi-resolve', '-a', ip],
                capture_output=True, text=True, timeout=2
            )
            if result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    return parts[1].rstrip('.')
        except:
            pass
        return ""

    def _get_mac_for_ip(self, ip: str) -> Optional[str]:
        try:
            result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True)
            m = re.search(r'([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', result.stdout)
            return m.group(1) if m else None
        except:
            return None

# ══════════════════════════════════════════════════════════════
# MODUŁ 2: ANALIZA RUCHU PAKIETÓW
# ══════════════════════════════════════════════════════════════
class PacketAnalyzer:
    def __init__(self):
        self.dns_queries = defaultdict(lambda: deque(maxlen=1000))
        self.connections = defaultdict(lambda: deque(maxlen=1000))
        self.port_access = defaultdict(set)    # ip -> set of ports scanned
        self.arp_table = {}                    # ip -> mac mapping (do wykrywania ARP spoof)
        self.alerts_queue = deque(maxlen=100)
        self.running = False

    def start(self, interface: str):
        if not SCAPY_AVAILABLE:
            cprint("WARN", "Scapy niedostępne — analiza pakietów wyłączona")
            return
        self.running = True
        self.interface = interface
        t = threading.Thread(target=self._capture_loop, daemon=True)
        t.start()
        cprint("OK", f"Przechwytywanie pakietów uruchomione na {interface}")

    def stop(self):
        self.running = False

    def _capture_loop(self):
        try:
            scapy_conf.verb = 0
            sniff(iface=self.interface, prn=self._process_packet,
                  store=False, stop_filter=lambda _: not self.running)
        except Exception as e:
            cprint("WARN", f"Błąd przechwytywania pakietów: {e}")

    def _process_packet(self, pkt):
        try:
            # ARP Spoofing Detection
            if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if ip in self.arp_table and self.arp_table[ip] != mac:
                    alert = {
                        "type": "ARP_SPOOFING",
                        "severity": "CRITICAL",
                        "ip": ip,
                        "original_mac": self.arp_table[ip],
                        "new_mac": mac,
                        "time": time.time()
                    }
                    self.alerts_queue.append(alert)
                    db.add_event("ARP_SPOOFING", "CRITICAL",
                        f"ARP Spoofing: IP {ip} teraz ma MAC {mac} zamiast {self.arp_table[ip]}", alert)
                    cprint("CRIT", f"⚠️ ARP SPOOFING WYKRYTY! IP {ip}", f"Oryginalny MAC: {self.arp_table[ip]} → Nowy: {mac}")
                self.arp_table[ip] = mac

            if IP not in pkt:
                return

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            now = time.time()

            # DNS Monitoring
            if DNS in pkt and DNSQR in pkt:
                query_name = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                self.dns_queries[src_ip].append((now, query_name))

                # Phishing/malicious domain check
                for domain in MALICIOUS_DOMAINS:
                    if domain in query_name:
                        alert = {"type": "MALICIOUS_DNS", "severity": "CRITICAL",
                                "ip": src_ip, "domain": query_name, "time": now}
                        self.alerts_queue.append(alert)
                        db.add_event("MALICIOUS_DNS", "CRITICAL",
                            f"Zapytanie DNS do złośliwej domeny: {query_name} z {src_ip}", alert)
                        cprint("CRIT", f"Złośliwa domena: {query_name}", f"Źródło: {src_ip}")

                # DNS Tunneling Detection (zbyt wiele queries)
                recent = [t for t, _ in self.dns_queries[src_ip] if now - t < 60]
                if len(recent) > CONFIG["max_dns_per_min"]:
                    alert = {"type": "DNS_TUNNEL", "severity": "HIGH",
                            "ip": src_ip, "count": len(recent), "time": now}
                    if not any(a.get("type") == "DNS_TUNNEL" and a.get("ip") == src_ip
                               and now - a.get("time", 0) < 300 for a in self.alerts_queue):
                        self.alerts_queue.append(alert)
                        db.add_event("DNS_TUNNEL", "HIGH",
                            f"Anomalia DNS: {len(recent)} zapytań/min z {src_ip}", alert)
                        cprint("WARN", f"DNS Tunneling suspect: {src_ip}", f"{len(recent)} queries/min")

            # Port Scan Detection
            if TCP in pkt:
                dst_port = pkt[TCP].dport
                self.port_access[src_ip].add(dst_port)
                if len(self.port_access[src_ip]) > CONFIG["port_scan_threshold"]:
                    alert = {"type": "PORT_SCAN", "severity": "HIGH",
                            "ip": src_ip, "ports": len(self.port_access[src_ip]), "time": now}
                    if not any(a.get("type") == "PORT_SCAN" and a.get("ip") == src_ip
                               and now - a.get("time", 0) < 300 for a in self.alerts_queue):
                        self.alerts_queue.append(alert)
                        db.add_event("PORT_SCAN", "HIGH",
                            f"Skanowanie portów z {src_ip}: {len(self.port_access[src_ip])} portów", alert)
                        cprint("WARN", f"Port scan: {src_ip}", f"Skanowane porty: {len(self.port_access[src_ip])}")

            # Tor Exit Node Detection
            if dst_ip in TOR_EXIT_NODES or src_ip in TOR_EXIT_NODES:
                alert = {"type": "TOR_CONNECTION", "severity": "HIGH",
                        "src": src_ip, "dst": dst_ip, "time": now}
                if not any(a.get("type") == "TOR_CONNECTION" and
                           (a.get("src") == src_ip or a.get("dst") == dst_ip)
                           and now - a.get("time", 0) < 600 for a in self.alerts_queue):
                    self.alerts_queue.append(alert)
                    db.add_event("TOR_CONNECTION", "HIGH",
                        f"Połączenie z węzłem Tor: {src_ip} → {dst_ip}", alert)
                    cprint("WARN", f"Tor connection: {src_ip} → {dst_ip}")

            # ── IoT / Tuya Device Monitoring ─────────────────
            self._monitor_iot(src_ip, dst_ip, pkt, now)

        except Exception as e:
            pass  # Cicho obsłuż błędy parsowania pakietów

    def _monitor_iot(self, src_ip: str, dst_ip: str, pkt, now: float):
        """Specjalny monitoring urządzeń IoT (domofon Tuya i inne)"""
        # Znajdź czy src lub dst to urządzenie IoT
        iot_ip = None
        iot_cfg = None
        for mac, cfg in IOT_DEVICES.items():
            if src_ip == cfg["ip"] or dst_ip == cfg["ip"]:
                iot_ip = cfg["ip"]
                iot_cfg = cfg
                break

        if not iot_ip or not iot_cfg:
            return

        local_network = ipaddress.ip_network(CONFIG["network_range"], strict=False)
        is_src_iot = (src_ip == iot_ip)

        # 1. Wykryj próbę dostępu do sieci lokalnej
        if iot_cfg.get("alert_on_local_scan") and is_src_iot:
            try:
                dst_addr = ipaddress.ip_address(dst_ip)
                if dst_addr in local_network and dst_ip != CONFIG.get("gateway", "192.168.100.1"):
                    alert = {
                        "type": "IOT_LOCAL_SCAN",
                        "severity": "CRITICAL",
                        "iot": iot_cfg["name"],
                        "src": src_ip, "dst": dst_ip,
                        "time": now
                    }
                    if not any(a.get("type") == "IOT_LOCAL_SCAN" and
                               a.get("dst") == dst_ip and
                               now - a.get("time", 0) < 300 for a in self.alerts_queue):
                        self.alerts_queue.append(alert)
                        db.add_event("IOT_LOCAL_SCAN", "CRITICAL",
                            f"🚨 {iot_cfg['name']} próbuje połączyć się z {dst_ip} w sieci lokalnej!",
                            alert)
                        cprint("CRIT", f"IoT skanuje sieć lokalną!",
                               f"{iot_cfg['name']} ({src_ip}) → {dst_ip}")
            except:
                pass

        # 2. Monitoruj ruch wychodzący — wykryj nadmierny upload
        if is_src_iot and IP in pkt:
            pkt_len = len(pkt)
            hour_key = int(now // 3600)
            IOT_TRAFFIC[iot_ip][hour_key] += pkt_len
            mb_this_hour = IOT_TRAFFIC[iot_ip][hour_key] / (1024 * 1024)
            max_mb = iot_cfg.get("max_upload_mb_per_hour", 50)
            if mb_this_hour > max_mb:
                alert = {
                    "type": "IOT_HIGH_UPLOAD",
                    "severity": "HIGH",
                    "iot": iot_cfg["name"],
                    "ip": iot_ip,
                    "mb": round(mb_this_hour, 1),
                    "time": now
                }
                if not any(a.get("type") == "IOT_HIGH_UPLOAD" and
                           a.get("ip") == iot_ip and
                           now - a.get("time", 0) < 3600 for a in self.alerts_queue):
                    self.alerts_queue.append(alert)
                    db.add_event("IOT_HIGH_UPLOAD", "HIGH",
                        f"⚠️ {iot_cfg['name']} wysłał {mb_this_hour:.1f} MB w ciągu godziny — możliwy wyciek danych",
                        alert)
                    cprint("WARN", f"IoT nadmierny upload: {iot_cfg['name']}",
                           f"{mb_this_hour:.1f} MB / {max_mb} MB limit")

        # 3. Loguj wszystkie połączenia zewnętrzne jeśli włączone
        if iot_cfg.get("log_all_connections") and is_src_iot:
            try:
                dst_addr = ipaddress.ip_address(dst_ip)
                if dst_addr not in local_network:
                    # Sprawdź czy to dozwolony serwer Tuya
                    allowed = iot_cfg.get("allowed_external", [])
                    is_allowed = any(dst_ip.startswith(prefix) for prefix in allowed)
                    if not is_allowed:
                        alert = {
                            "type": "IOT_UNKNOWN_SERVER",
                            "severity": "HIGH",
                            "iot": iot_cfg["name"],
                            "src": src_ip, "dst": dst_ip,
                            "time": now
                        }
                        if not any(a.get("type") == "IOT_UNKNOWN_SERVER" and
                                   a.get("dst") == dst_ip and
                                   now - a.get("time", 0) < 3600 for a in self.alerts_queue):
                            self.alerts_queue.append(alert)
                            db.add_event("IOT_UNKNOWN_SERVER", "HIGH",
                                f"🌐 {iot_cfg['name']} łączy się z nieznanym serwerem: {dst_ip}",
                                alert)
                            cprint("WARN", f"IoT nieznany serwer: {iot_cfg['name']}",
                                   f"Połączenie z {dst_ip}")
            except:
                pass

    def get_recent_alerts(self, n: int = 20) -> list:
        return list(self.alerts_queue)[-n:]

# ══════════════════════════════════════════════════════════════
# MODUŁ 2b: ARP TABLE SYNC (czyta /proc/net/arp lokalnie)
# ══════════════════════════════════════════════════════════════
class RouterSync:
    """Czyta lokalną tablicę ARP z /proc/net/arp.
    Uzupełnia dane agenta o urządzenia które nie odpowiadają na broadcast ARP,
    ale były aktywne od ostatniego restartu systemu."""

    def __init__(self, scanner):
        self.scanner   = scanner
        self.last_sync = 0
        self.interval  = CONFIG.get("router", {}).get("sync_interval", 60)
        cprint("OK", "ARP Sync aktywny — czyta /proc/net/arp")

    def sync(self) -> int:
        now = time.time()
        if now - self.last_sync < self.interval:
            return 0
        self.last_sync = now

        arp_devices = self._read_arp_table()
        new_count = 0

        for mac, ip in arp_devices.items():
            if mac not in self.scanner.active_devices:
                name = CONFIG["device_names"].get(mac) or f"Urządzenie ({ip})"
                tag  = "trusted" if mac in CONFIG["trusted_macs"] else "new"
                self.scanner.active_devices[mac] = {
                    "ip": ip, "mac": mac,
                    "vendor": self.scanner._get_vendor(mac),
                    "hostname": name,
                    "status": "online",
                    "is_host": False,
                    "tag": tag,
                    "source": "arp_table",
                }
                db.upsert_device(mac, self.scanner.active_devices[mac])
                new_count += 1
                cprint("INFO", f"ARP Sync: wykryto {name} ({ip}) [{mac}]")
            else:
                self.scanner.active_devices[mac]["ip"]     = ip
                self.scanner.active_devices[mac]["status"] = "online"

        return new_count

    def _read_arp_table(self) -> dict:
        devices = {}
        try:
            with open("/proc/net/arp") as f:
                next(f)  # pomiń nagłówek
                for line in f:
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    ip    = parts[0]
                    flags = parts[2]
                    mac   = parts[3].lower()
                    iface = parts[5].strip()
                    if (flags == "0x2" and
                            mac != "00:00:00:00:00:00" and
                            iface == CONFIG.get("interface", "eno1")):
                        devices[mac] = ip
        except Exception as e:
            cprint("WARN", f"ARP Sync: błąd odczytu: {e}")
        return devices

class AIAnalyst:
    def __init__(self, model: str = "llama3.2"):
        self.model = model
        self.available = OLLAMA_AVAILABLE and self._check_ollama()
        if self.available:
            cprint("OK", f"Lokalny LLM dostępny: {model}")
        else:
            cprint("WARN", "Ollama niedostępne — używam analizy heurystycznej")

    def _check_ollama(self) -> bool:
        try:
            ollama.list()
            return True
        except:
            return False

    def analyze(self, context: str, question: str) -> str:
        if not self.available:
            return self._heuristic_analysis(question)

        system_prompt = """Jesteś NetGuard AI — lokalnym agentem bezpieczeństwa sieci domowej.
Analizujesz dane sieciowe i pomagasz właścicielowi chronić jego sieć.
Odpowiadasz po polsku, zwięźle i konkretnie.
Używasz technicznych terminów ale tłumaczysz je dla zwykłego użytkownika.
Nigdy nie wysyłasz danych na zewnątrz — działasz wyłącznie lokalnie.
Kontekst sieci: """ + context

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": question}
                ]
            )
            return response['message']['content']
        except Exception as e:
            return f"Błąd LLM: {e}\n\n{self._heuristic_analysis(question)}"

    def _heuristic_analysis(self, question: str) -> str:
        """Analiza bez LLM — reguły heurystyczne"""
        q = question.lower()
        alerts = db.data.get("events", [])
        critical = [e for e in alerts if e.get("severity") == "CRITICAL"]
        high = [e for e in alerts if e.get("severity") == "HIGH"]

        if "podejrzan" in q or "niebezpiecz" in q or "zagroż" in q:
            return (f"📊 Analiza heurystyczna:\n"
                    f"• Zagrożenia krytyczne: {len(critical)}\n"
                    f"• Zagrożenia wysokie: {len(high)}\n"
                    f"• Ostatni alert: {critical[0]['description'] if critical else 'brak'}\n"
                    f"Zalecenie: {'Sprawdź ostatnie alerty i zidentyfikuj nieznane urządzenia.' if critical else 'Sieć wygląda bezpiecznie.'}")

        return ("Tryb heurystyczny aktywny. Zainstaluj Ollama i pobierz model:\n"
                "  brew install ollama  (macOS)\n"
                "  curl -fsSL https://ollama.com/install.sh | sh  (Linux)\n"
                "  ollama pull llama3.2\n"
                "Następnie uruchom agenta z flagą --llm")

# ══════════════════════════════════════════════════════════════
# MODUŁ 4: ALERT MANAGER + DZIENNY RAPORT EMAIL
# ══════════════════════════════════════════════════════════════
class AlertManager:
    def __init__(self, email: str = ""):
        self.email = email
        self.notifications = []
        # Statystyki do dziennego raportu
        self._day_devices_seen = set()
        self._day_new_devices  = []
        self._day_threats      = []
        self._report_sent_date = None

    def send(self, severity: str, title: str, detail: str):
        """Wyślij powiadomienie (log + opcjonalnie email)"""
        msg = f"[{severity}] {title}: {detail}"
        self.notifications.append({
            "time": datetime.datetime.now().isoformat(),
            "severity": severity, "title": title, "detail": detail
        })
        if severity == "CRITICAL":
            cprint("CRIT", title, detail)
        elif severity == "HIGH":
            cprint("WARN", title, detail)
        else:
            cprint("INFO", title, detail)
        log.warning(msg) if severity in ("CRITICAL", "HIGH") else log.info(msg)
        if self.email:
            self._send_email_smtp(severity, title, detail)

    def track_device(self, mac: str, hostname: str, ip: str):
        """Śledź urządzenia do dziennego raportu"""
        self._day_devices_seen.add(mac)

    def track_new_device(self, mac: str, hostname: str, ip: str, vendor: str):
        """Śledź nowe urządzenia"""
        self._day_new_devices.append({
            "mac": mac, "hostname": hostname,
            "ip": ip, "vendor": vendor,
            "time": datetime.datetime.now().strftime("%H:%M")
        })

    def track_threat(self, threat_type: str, description: str, severity: str):
        """Śledź zagrożenia do raportu"""
        self._day_threats.append({
            "type": threat_type, "description": description,
            "severity": severity,
            "time": datetime.datetime.now().strftime("%H:%M")
        })

    def check_daily_report(self, scanner):
        """Sprawdź czy czas wysłać dzienny raport (20:00 czasu warszawskiego)"""
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo("Europe/Warsaw")
        except ImportError:
            try:
                import pytz
                tz = pytz.timezone("Europe/Warsaw")
            except ImportError:
                import datetime as _dt
                # Fallback — UTC+1/+2 bez biblioteki
                tz = datetime.timezone(datetime.timedelta(hours=1))

        now_local = datetime.datetime.now(tz)
        today = now_local.date()
        report_hour = 20

        if (now_local.hour == report_hour and
                now_local.minute < 2 and
                self._report_sent_date != today):
            self._report_sent_date = today
            self._send_daily_report(scanner, now_local)

    def _send_daily_report(self, scanner, now_local):
        """Zbuduj i wyślij dzienny raport"""
        if not self.email:
            cprint("WARN", "Brak emaila — raport nie wysłany")
            return

        date_str = now_local.strftime("%d.%m.%Y")
        events_today = self._get_events_today()

        # Urządzenia online teraz
        online_devices = list(scanner.active_devices.values())
        online_count = len(online_devices)

        # Nowe urządzenia z bazy (dziś)
        new_devs = self._day_new_devices
        new_devs_db = [
            e for e in db.data.get("events", [])
            if e.get("type") == "NEW_DEVICE" and
            e.get("timestamp", "")[:10] == now_local.strftime("%Y-%m-%d")
        ]

        # Zagrożenia z dziś
        threats_today = [
            e for e in events_today
            if e.get("severity") in ("CRITICAL", "HIGH") and
            e.get("type") != "NEW_DEVICE"
        ]

        # Zlicz typy zagrożeń
        threat_counts = defaultdict(int)
        for t in threats_today:
            threat_counts[t.get("type", "INNE")] += 1

        # Ikony dla typów
        icons = {
            "PORT_SCAN": "🔍", "ARP_SPOOFING": "⚠️", "DNS_TUNNEL": "📡",
            "MALICIOUS_DNS": "☠️", "TOR_CONNECTION": "🧅",
            "IOT_LOCAL_SCAN": "🚨", "IOT_HIGH_UPLOAD": "📤",
            "IOT_UNKNOWN_SERVER": "🌐", "NEW_DEVICE": "📱",
        }

        # Ocena ryzyka
        critical_count = len([e for e in threats_today if e.get("severity") == "CRITICAL"])
        high_count     = len([e for e in threats_today if e.get("severity") == "HIGH"])
        if critical_count > 0:
            risk = "🔴 WYSOKIE"
        elif high_count > 2:
            risk = "🟡 ŚREDNIE"
        else:
            risk = "🟢 NISKIE"

        # Buduj wiersze tabeli urządzeń
        device_rows = ""
        for d in online_devices:
            name = CONFIG["device_names"].get(d.get("mac", ""),
                   d.get("hostname") or d.get("vendor", "Nieznane"))
            ip   = d.get("ip", "—")
            tag  = d.get("tag", "new")
            color  = "#2e7d32" if tag == "trusted" else "#f57c00"
            status = "✓ Zaufane" if tag == "trusted" else "⚠ Nowe"
            device_rows += (
                '<tr style="border-bottom:1px solid #eee;">'
                '<td style="padding:8px;">' + name + '</td>'
                '<td style="padding:8px;font-family:monospace;">' + ip + '</td>'
                '<td style="padding:8px;"><span style="color:' + color + '">' + status + '</span></td>'
                '</tr>'
            )

        # Buduj sekcję nowych urządzeń
        if new_devs_db:
            new_devs_html = '<h3 style="color:#f57c00;border-bottom:2px solid #f57c00;padding-bottom:5px;margin-top:20px;">🆕 Nowe urządzenia dzisiaj</h3><ul style="font-size:13px;">'
            for e in new_devs_db:
                ts = e.get("timestamp", "")[:16].replace("T", " ")
                new_devs_html += '<li style="margin:5px 0;"><b>' + e.get("description", "") + '</b> — ' + ts + '</li>'
            new_devs_html += '</ul>'
        else:
            new_devs_html = '<p style="color:#2e7d32;">✓ Brak nowych urządzeń dzisiaj</p>'

        # Buduj sekcję zagrożeń
        if threats_today:
            threats_html = '<ul style="font-size:13px;">'
            for e in threats_today[:20]:
                bg   = "#ffebee" if e.get("severity") == "CRITICAL" else "#fff8e1"
                icon = icons.get(e.get("type", ""), "•")
                ttype = e.get("type", "").replace("_", " ")
                desc  = e.get("description", "")[:100]
                ts    = e.get("timestamp", "")[:16].replace("T", " ")
                threats_html += (
                    '<li style="margin:8px 0;padding:8px;background:' + bg + ';border-radius:4px;">'
                    + icon + ' <b>' + ttype + '</b> — ' + desc
                    + ' <span style="color:#999;font-size:11px;">(' + ts + ')</span></li>'
                )
            threats_html += '</ul>'
        else:
            threats_html = '<p style="color:#2e7d32;">✓ Brak zagrożeń dzisiaj — sieć bezpieczna</p>'

        # Złóż pełny HTML
        html = (
            '<html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#333;">'
            '<div style="background:#0a0e14;padding:20px;border-radius:8px 8px 0 0;">'
            '<h1 style="color:#00d4ff;margin:0;font-size:20px;">🛡 NetGuard AI — Raport dzienny</h1>'
            '<p style="color:#6a8aaa;margin:5px 0 0;">' + date_str + ' | Sieć: ' + CONFIG["network_range"] + '</p>'
            '</div>'
            '<div style="background:#f8f9fa;padding:20px;border:1px solid #dee2e6;">'
            '<table style="width:100%;border-collapse:collapse;margin-bottom:20px;"><tr>'
            '<td style="background:#e3f2fd;padding:15px;border-radius:6px;text-align:center;width:25%;">'
            '<div style="font-size:28px;font-weight:bold;color:#1976d2;">' + str(online_count) + '</div>'
            '<div style="font-size:12px;color:#666;">Urządzeń online</div></td>'
            '<td style="width:4%;"></td>'
            '<td style="background:#fff3e0;padding:15px;border-radius:6px;text-align:center;width:25%;">'
            '<div style="font-size:28px;font-weight:bold;color:#f57c00;">' + str(len(new_devs_db)) + '</div>'
            '<div style="font-size:12px;color:#666;">Nowych urządzeń</div></td>'
            '<td style="width:4%;"></td>'
            '<td style="background:#fce4ec;padding:15px;border-radius:6px;text-align:center;width:25%;">'
            '<div style="font-size:28px;font-weight:bold;color:#c62828;">' + str(len(threats_today)) + '</div>'
            '<div style="font-size:12px;color:#666;">Zagrożeń</div></td>'
            '<td style="width:4%;"></td>'
            '<td style="background:#f3e5f5;padding:15px;border-radius:6px;text-align:center;width:25%;">'
            '<div style="font-size:16px;font-weight:bold;">' + risk + '</div>'
            '<div style="font-size:12px;color:#666;">Poziom ryzyka</div></td>'
            '</tr></table>'
            '<h3 style="color:#1976d2;border-bottom:2px solid #1976d2;padding-bottom:5px;">'
            '📱 Urządzenia w sieci (' + str(online_count) + ')</h3>'
            '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
            '<tr style="background:#e3f2fd;">'
            '<th style="padding:8px;text-align:left;">Nazwa</th>'
            '<th style="padding:8px;text-align:left;">IP</th>'
            '<th style="padding:8px;text-align:left;">Status</th></tr>'
            + device_rows +
            '</table>'
            + new_devs_html +
            '<h3 style="color:#c62828;border-bottom:2px solid #c62828;padding-bottom:5px;margin-top:20px;">'
            '⚠️ Zagrożenia i zdarzenia (' + str(len(threats_today)) + ')</h3>'
            + threats_html +
            '</div>'
            '<div style="background:#0a0e14;padding:12px 20px;border-radius:0 0 8px 8px;font-size:11px;color:#6a8aaa;">'
            'NetGuard AI v1.0 | Raport wygenerowany lokalnie | Żadne dane nie opuściły Twojej sieci'
            '</div></body></html>'
        )
        # Tekst plain-text jako fallback
        plain = f"""NetGuard AI — Raport dzienny {date_str}
{'='*50}
Urządzenia online: {online_count}
Nowe urządzenia:   {len(new_devs_db)}
Zagrożenia:        {len(threats_today)}
Poziom ryzyka:     {risk}

URZĄDZENIA ONLINE:
{chr(10).join(f"  • {CONFIG['device_names'].get(d.get('mac',''), d.get('hostname') or d.get('vendor','?'))} ({d.get('ip','?')})" for d in online_devices)}

NOWE URZĄDZENIA:
{chr(10).join(f"  • {e.get('description','')}" for e in new_devs_db) or "  Brak"}

ZAGROŻENIA:
{chr(10).join(f"  [{e.get('severity','')}] {e.get('description','')}" for e in threats_today[:10]) or "  Brak — sieć bezpieczna"}
"""
        self._send_html_email(
            subject=f"🛡 NetGuard — Raport {date_str} | Ryzyko: {risk} | {online_count} urządzeń",
            html=html,
            plain=plain
        )
        cprint("OK", f"Dzienny raport wysłany na {self.email}")

    def _get_events_today(self) -> list:
        today = datetime.date.today().isoformat()
        return [e for e in db.data.get("events", [])
                if e.get("timestamp", "")[:10] == today]

    def _send_html_email(self, subject: str, html: str, plain: str):
        """Wyślij email HTML przez Gmail SMTP"""
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText as _MIMEText

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"]    = CONFIG["alert_email"]
            msg["To"]      = CONFIG["alert_email"]
            msg.attach(_MIMEText(plain, "plain", "utf-8"))
            msg.attach(_MIMEText(html,  "html",  "utf-8"))

            # Użyj Gmail SMTP z hasłem aplikacji
            smtp_cfg = CONFIG.get("smtp", {})
            host = smtp_cfg.get("host", "smtp.gmail.com")
            port = smtp_cfg.get("port", 587)
            user = smtp_cfg.get("user", CONFIG["alert_email"])
            pwd  = smtp_cfg.get("password", "")

            if not pwd:
                cprint("WARN", "Brak hasła SMTP — ustaw CONFIG['smtp']['password']")
                log.info(f"[EMAIL RAPORT — nie wysłany, brak hasła]\n{plain}")
                return

            with smtplib.SMTP(host, port) as s:
                s.starttls()
                s.login(user, pwd)
                s.send_message(msg)
        except Exception as e:
            cprint("WARN", f"Błąd wysyłania emaila: {e}")
            log.info(f"[EMAIL RAPORT]\n{plain}")

    def _send_email_smtp(self, severity: str, title: str, detail: str):
        """Wyślij alert email (dla krytycznych zdarzeń)"""
        try:
            import smtplib
            from email.mime.text import MIMEText as _MIMEText
            smtp_cfg = CONFIG.get("smtp", {})
            pwd = smtp_cfg.get("password", "")
            if not pwd:
                return
            msg = _MIMEText(f"NetGuard AI Alert\n\nPoziom: {severity}\nTytuł: {title}\n\nSzczegóły:\n{detail}\n\nCzas: {datetime.datetime.now()}", "plain", "utf-8")
            msg["Subject"] = f"[NetGuard {severity}] {title}"
            msg["From"]    = CONFIG["alert_email"]
            msg["To"]      = CONFIG["alert_email"]
            with smtplib.SMTP(smtp_cfg.get("host","smtp.gmail.com"), smtp_cfg.get("port", 587)) as s:
                s.starttls()
                s.login(smtp_cfg.get("user", CONFIG["alert_email"]), pwd)
                s.send_message(msg)
        except Exception as e:
            log.debug(f"Email alert błąd: {e}")

# ══════════════════════════════════════════════════════════════
# MODUŁ 5: WEB DASHBOARD API (opcjonalny Flask)
# ══════════════════════════════════════════════════════════════
def start_dashboard(scanner: 'NetworkScanner', analyzer: 'PacketAnalyzer',
                    ai: 'AIAnalyst', port: int = 8765):
    if not FLASK_AVAILABLE:
        cprint("WARN", "Flask niedostępny — dashboard wyłączony. pip install flask")
        return

    import os as _os
    script_dir = _os.path.dirname(_os.path.abspath(__file__))
    app = Flask(__name__, static_folder=script_dir)

    # ── Dekorator sprawdzający token bezpieczeństwa ───────────
    from functools import wraps

    def require_token(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = (request.headers.get("X-NetGuard-Token") or
                     request.args.get("token") or
                     (request.json or {}).get("token", "") if request.is_json else "")
            if token != DASHBOARD_TOKEN:
                return jsonify({"error": "Brak autoryzacji — nieprawidłowy token"}), 403
            return f(*args, **kwargs)
        return decorated

    @app.after_request
    def add_cors(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    @app.route('/api/devices')
    def api_devices():
        devs = list(scanner.active_devices.values())
        # Upewnij się że każde urządzenie ma pole is_host
        for d in devs:
            d.setdefault('is_host', False)
            d.setdefault('tag', 'trusted' if d.get('is_host') else 'new')
        return jsonify(devs)

    @app.route('/api/alerts')
    def api_alerts():
        return jsonify(db.data.get("events", [])[:50])

    @app.route('/api/stats')
    def api_stats():
        events = db.data.get("events", [])
        devices = db.data.get("devices", {})
        online = len([d for d in scanner.active_devices.values() if d.get("status") == "online"])
        new = len([mac for mac, d in devices.items() if mac not in CONFIG["trusted_macs"]])
        critical = len([e for e in events if e.get("severity") == "CRITICAL"])
        return jsonify({"online": online, "new_devices": new,
                       "active_alerts": critical, "total_devices": len(devices),
                       "total_events": len(events)})

    @app.route('/api/chat', methods=['POST'])
    def api_chat():
        data = request.json or {}
        question = data.get("message", "")
        if not question:
            return jsonify({"error": "Brak wiadomości"}), 400
        # Zbuduj kontekst sieci
        context = json.dumps({
            "devices": list(scanner.active_devices.values())[:10],
            "recent_alerts": analyzer.get_recent_alerts(5),
            "network": CONFIG["network_range"]
        }, ensure_ascii=False)
        response = ai.analyze(context, question)
        return jsonify({"response": response})

    @app.route('/api/block/<mac>', methods=['POST'])
    @require_token
    def api_block(mac):
        if mac not in CONFIG["blocked_macs"]:
            CONFIG["blocked_macs"].append(mac)
            # Faktyczna blokada przez iptables
            device = db.get_device(mac)
            if device and device.get("ip"):
                ip = device["ip"]
                os.system(f"iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")
                os.system(f"iptables -I FORWARD -d {ip} -j DROP 2>/dev/null")
            db.add_event("DEVICE_BLOCKED", "INFO", f"Urządzenie zablokowane: {mac}", {"mac": mac})
        return jsonify({"status": "blocked", "mac": mac})

    @app.route('/api/trust/<mac>', methods=['POST'])
    @require_token
    def api_trust(mac):
        if mac not in CONFIG["trusted_macs"]:
            CONFIG["trusted_macs"].append(mac)
            save_config()
            db.add_event("DEVICE_TRUSTED", "INFO", f"Urządzenie oznaczone jako zaufane: {mac}", {"mac": mac})
        return jsonify({"status": "trusted", "mac": mac})

    @app.route('/api/rename', methods=['POST'])
    @require_token
    def api_rename():
        data = request.json or {}
        mac  = data.get("mac", "").lower().strip()
        name = data.get("name", "").strip()
        if not mac or not name:
            return jsonify({"error": "Brak mac lub name"}), 400
        CONFIG["device_names"][mac] = name
        save_config()
        if mac in scanner.active_devices:
            scanner.active_devices[mac]["hostname"] = name
        dev = db.data.get("devices", {}).get(mac, {})
        dev["hostname"] = name
        db.data.setdefault("devices", {})[mac] = dev
        db.save()
        db.add_event("DEVICE_RENAMED", "INFO",
            f"Urządzenie {mac} otrzymało nazwę: {name}", {"mac": mac, "name": name})
        cprint("OK", f"Urządzenie {mac} → {name}")
        return jsonify({"status": "ok", "mac": mac, "name": name})

    @app.route('/api/test-report', methods=['POST', 'GET'])
    @require_token
    def api_test_report():
        try:
            import datetime as _dt
            try:
                import zoneinfo
                tz = zoneinfo.ZoneInfo("Europe/Warsaw")
            except ImportError:
                tz = _dt.timezone(_dt.timedelta(hours=1))
            now_local = _dt.datetime.now(tz)
            # Wymuś wysłanie raportu ignorując datę ostatniego wysłania
            alerter = ai._alerter if hasattr(ai, '_alerter') else None
            # Pobierz alerter z globalnego agenta
            import gc
            agents = [obj for obj in gc.get_objects()
                      if isinstance(obj, AlertManager)]
            if agents:
                a = agents[0]
                a._report_sent_date = None  # reset żeby pozwolić na wysłanie
                a._send_daily_report(scanner, now_local)
                return jsonify({"status": "ok", "message": f"Raport testowy wysłany na {CONFIG['alert_email']}"})
            return jsonify({"status": "error", "message": "Nie znaleziono AlertManager"}), 500
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/api/token')
    def api_token():
        """Zwraca token dla dashboardu — dostępny tylko z localhost."""
        if request.remote_addr not in ('127.0.0.1', '::1', 'localhost'):
            return jsonify({"error": "Dostęp tylko z localhost"}), 403
        return jsonify({"token": DASHBOARD_TOKEN})

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(script_dir, 'favicon.ico',
                                   mimetype='image/x-icon')

    @app.route('/')
    def index():
        dashboard = _os.path.join(script_dir, 'network-agent-dashboard.html')
        if _os.path.exists(dashboard):
            return send_from_directory(script_dir, 'network-agent-dashboard.html')
        return "<h1>NetGuard AI API działa</h1><p>Umieść <b>network-agent-dashboard.html</b> obok netguard_agent.py</p><p><a href='/api/devices'>→ /api/devices</a> | <a href='/api/alerts'>→ /api/alerts</a> | <a href='/api/stats'>→ /api/stats</a></p>"

    import socket as _socket
    from werkzeug.serving import make_server
    cprint("OK", f"Dashboard dostępny: http://localhost:{port}")
    cprint("OK", f"Token bezpieczeństwa: {DASHBOARD_TOKEN[:8]}...{DASHBOARD_TOKEN[-4:]} (pełny w .netguard_token)")
    srv = make_server('0.0.0.0', port, app)
    srv.socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.serve_forever()

# ══════════════════════════════════════════════════════════════
# MODUŁ 6: GŁÓWNA PĘTLA AGENTA
# ══════════════════════════════════════════════════════════════
class NetGuardAgent:
    def __init__(self):
        self.scanner   = NetworkScanner(CONFIG["network_range"], CONFIG["interface"])
        self.analyzer  = PacketAnalyzer()
        self.ai        = AIAnalyst(CONFIG.get("llm_model", "llama3.2"))
        self.alerter   = AlertManager(CONFIG.get("alert_email", ""))
        self.router    = RouterSync(self.scanner)
        self.running   = False
        self._setup_signals()

    def _setup_signals(self):
        signal.signal(signal.SIGINT, self._graceful_shutdown)
        signal.signal(signal.SIGTERM, self._graceful_shutdown)

    def _graceful_shutdown(self, sig, frame):
        cprint("INFO", "Zatrzymywanie agenta NetGuard...")
        self.running = False
        self.analyzer.stop()
        sys.exit(0)

    def _detect_interface(self) -> str:
        if CONFIG["interface"] != "auto":
            return CONFIG["interface"]
        return self.scanner.get_interface()

    def run(self, with_dashboard: bool = False):
        self.running = True
        iface = self._detect_interface()
        cprint("OK", f"NetGuard AI uruchomiony", f"Sieć: {CONFIG['network_range']} | Interfejs: {iface}")

        # Uruchom przechwytywanie pakietów w tle
        if CONFIG["packet_capture"]:
            self.analyzer.start(iface)

        # Uruchom dashboard w tle
        if with_dashboard:
            dash_thread = threading.Thread(
                target=start_dashboard,
                args=(self.scanner, self.analyzer, self.ai, CONFIG["dashboard_port"]),
                daemon=True
            )
            dash_thread.start()
            # Otwórz przeglądarkę automatycznie po 2 sekundach
            url = f"http://localhost:{CONFIG['dashboard_port']}"
            def _open_browser():
                time.sleep(2)
                try:
                    import webbrowser
                    webbrowser.open(url)
                    cprint("OK", f"Dashboard otwarty w przeglądarce: {url}")
                except:
                    cprint("INFO", f"Otwórz ręcznie: {url}")
            threading.Thread(target=_open_browser, daemon=True).start()

        # Główna pętla skanowania
        last_known_macs = set()

        while self.running:
            try:
                cprint("INFO", f"Skanowanie sieci... [{datetime.datetime.now().strftime('%H:%M:%S')}]")
                devices = self.scanner.scan()

                for mac, info in devices.items():
                    is_new = db.upsert_device(mac, info)

                    # Śledź urządzenia do dziennego raportu
                    self.alerter.track_device(mac, info.get("hostname",""), info.get("ip",""))

                    if is_new and mac not in last_known_macs:
                        self.alerter.send("HIGH", "Nowe urządzenie w sieci",
                            f"MAC: {mac} | IP: {info['ip']} | Producent: {info['vendor']}")
                        db.add_event("NEW_DEVICE", "HIGH",
                            f"Nowe urządzenie: {info.get('hostname','?')} ({info['ip']})",
                            info)
                        self.alerter.track_new_device(
                            mac, info.get("hostname","?"),
                            info.get("ip",""), info.get("vendor",""))

                    if mac in CONFIG["blocked_macs"]:
                        ip = info.get("ip")
                        if ip:
                            os.system(f"iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")

                current_macs = set(devices.keys())
                left = last_known_macs - current_macs
                for mac in left:
                    cprint("INFO", f"Urządzenie opuściło sieć: {mac}")

                last_known_macs = current_macs

                # Śledź zagrożenia z analizatora pakietów do dziennego raportu
                for alert in list(self.analyzer.alerts_queue):
                    if alert.get("severity") in ("CRITICAL", "HIGH"):
                        self.alerter.track_threat(
                            alert.get("type",""),
                            alert.get("description", str(alert)),
                            alert.get("severity",""))

                # Synchronizuj urządzenia z routerem co 5 minut
                self.router.sync()

                # Sprawdź czy czas na dzienny raport (20:00 czasu warszawskiego)
                self.alerter.check_daily_report(self.scanner)

                # AI analiza co 15 minut
                if int(time.time()) % 900 == 0 and self.ai.available:
                    context = json.dumps({"devices": list(devices.values())[:5],
                                        "alerts": db.data.get("events", [])[:5]},
                                        ensure_ascii=False)
                    summary = self.ai.analyze(context,
                        "Przeanalizuj bieżący stan sieci i podaj krótkie podsumowanie zagrożeń.")
                    cprint("INFO", "AI Analiza sieci:", summary[:200] + "...")

                print(f"\n{C['gray']}─── Status: {len(devices)} urządzeń online | "
                      f"Alerty: {len(db.data.get('events',[]))} | "
                      f"Następne skanowanie: {CONFIG['scan_interval']}s ───{C['reset']}\n")

                time.sleep(CONFIG["scan_interval"])

            except KeyboardInterrupt:
                break
            except Exception as e:
                cprint("WARN", f"Błąd w pętli głównej: {e}")
                time.sleep(10)

# ══════════════════════════════════════════════════════════════
# SETUP WIZARD
# ══════════════════════════════════════════════════════════════
def run_setup():
    print(f"""
{C['blue']}{C['bold']}
╔══════════════════════════════════════════════════════════════╗
║            NETGUARD AI — Kreator konfiguracji                ║
╚══════════════════════════════════════════════════════════════╝
{C['reset']}""")

    # Wykryj sieć
    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        networks = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
        if networks:
            print(f"Wykryte sieci lokalne: {', '.join(networks)}")
            CONFIG["network_range"] = networks[0]
    except:
        pass

    network = input(f"Zakres sieci [{CONFIG['network_range']}]: ").strip()
    if network: CONFIG["network_range"] = network

    email = input("Email do alertów (zostaw puste aby pominąć): ").strip()
    if email: CONFIG["alert_email"] = email

    # Zapisz konfigurację
    config_path = "/etc/netguard/config.json"
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(CONFIG, f, indent=2)

    cprint("OK", f"Konfiguracja zapisana w {config_path}")
    cprint("INFO", "Uruchom agenta: sudo python3 netguard_agent.py --dashboard")

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
def print_banner():
    print(f"""{C['blue']}{C['bold']}
 ███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
 ██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
 ██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
 ██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{C['reset']}{C['gray']}                    AI Agent Sieci Domowej — v1.0.0 — tryb lokalny{C['reset']}
""")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='NetGuard AI — Lokalny Agent Sieci Domowej')
    parser.add_argument('--setup',     action='store_true', help='Kreator konfiguracji')
    parser.add_argument('--dashboard', action='store_true', help='Uruchom web dashboard (port 8765)')
    parser.add_argument('--llm',       action='store_true', help='Włącz lokalny LLM (Ollama)')
    parser.add_argument('--no-llm',    action='store_true', help='Wyłącz LLM — tylko heurystyki')
    parser.add_argument('--model',     default='llama3.2',  help='Model Ollama (domyślnie: llama3.2)')
    parser.add_argument('--network',   default='',          help='Zakres sieci (np. 192.168.1.0/24)')
    parser.add_argument('--email',     default='',          help='Email do alertów')
    parser.add_argument('--interval',  type=int, default=60, help='Interwał skanowania (sekundy)')
    args = parser.parse_args()

    print_banner()

    if args.setup:
        run_setup()
        sys.exit(0)

    if args.network: CONFIG["network_range"] = args.network
    if args.email:   CONFIG["alert_email"]   = args.email
    if args.model:   CONFIG["llm_model"]     = args.model
    if args.interval: CONFIG["scan_interval"] = args.interval
    if args.no_llm:  OLLAMA_AVAILABLE = False  # type: ignore

    cprint("INFO", "Uruchamianie NetGuard AI...", f"Sieć: {CONFIG['network_range']}")
    agent = NetGuardAgent()
    agent.run(with_dashboard=args.dashboard)
