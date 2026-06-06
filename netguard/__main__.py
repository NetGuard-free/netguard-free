import os
import sys
import json
import time
import socket
import threading
import signal
import datetime
import argparse
import webbrowser
import subprocess
import re
import logging
import gc

from netguard import C, VERSION, IS_WINDOWS, OLLAMA_AVAILABLE, _AGENT_DIR
from netguard.config import load_config, validate_config, is_scheduled_blocked, CONFIG_FILE as _CONFIG_FILE
from netguard.utils import cprint, _setup_logging, _check_updates_loop
from netguard.database import DeviceDB
from netguard.gateway import detect_gateway_mode, setup_nat, cleanup_nat
from netguard.scanner import NetworkScanner
from netguard.analyzer import PacketAnalyzer
from netguard.ai_analyst import AIAnalyst
from netguard.router_sync import RouterSync
from netguard.parental import ChildDNSProxy
from netguard.gateway import SuricataManager
from netguard.alerts import AlertManager
from netguard.dashboard import start_dashboard
from netguard.license import get_plan, get_limits, is_paid


# ── GLOBAL STATE (wired from config) ──────────────────────────
_db = None


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


def _resolve_gateway_state():
    is_gw, wan, lan = detect_gateway_mode()
    return is_gw, wan, lan


class NetGuardAgent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.scanner = NetworkScanner(
            cfg["network_range"], cfg["interface"],
            cfg=cfg, cprint_func=cprint,
            get_limits_func=lambda: get_limits(get_plan(cfg))
        )
        self.analyzer = PacketAnalyzer(cfg=cfg, cprint_func=cprint, db=_db, scanner=self.scanner)
        self.ai = AIAnalyst(cfg.get("llm_model", "llama3.2"), cprint_func=cprint, db=_db)
        self.alerter = AlertManager(
            cfg.get("alert_email", ""), cfg=cfg,
            cprint_func=cprint, db=_db, log_func=logging.getLogger(__name__).info
        )
        self.router = RouterSync(self.scanner, cfg=cfg, cprint_func=cprint, db=_db)
        self.suricata = SuricataManager(cfg=cfg, cprint_func=cprint, db=_db)
        self.dns_proxy = ChildDNSProxy(self.scanner, cfg=cfg, cprint_func=cprint)
        self.running = False
        self._setup_signals()

        # Wire scanner back to analyzer
        self.analyzer.scanner = self.scanner

    def _setup_signals(self):
        signal.signal(signal.SIGINT, self._graceful_shutdown)
        try:
            signal.signal(signal.SIGTERM, self._graceful_shutdown)
        except (OSError, ValueError):
            pass

    def _graceful_shutdown(self, sig, frame):
        cprint("INFO", "Zatrzymywanie agenta NetGuard...")
        self.running = False
        self.analyzer.stop()
        self.suricata.stop()
        self.dns_proxy.stop()
        is_gw, wan, lan = _resolve_gateway_state()
        if is_gw and not IS_WINDOWS:
            cleanup_nat(wan, lan)
        sys.exit(0)

    def _detect_interface(self) -> str:
        if self.cfg["interface"] != "auto":
            return self.cfg["interface"]
        return self.scanner.get_interface()

    def run(self, with_dashboard: bool = False):
        global _scanner
        _scanner = self.scanner

        self.running = True
        iface = self._detect_interface()
        cprint("OK", "NetGuard AI uruchomiony",
               f"Siec: {self.cfg['network_range']} | Interfejs: {iface}")

        is_gw, wan, lan = _resolve_gateway_state()
        if is_gw and not IS_WINDOWS:
            setup_nat(wan, lan)
        plan = get_plan(self.cfg)
        if plan == "enterprise":
            cprint("OK", "Licencja: NetGuard ENTERPRISE ✓",
                   "Wszystkie funkcje odblokowane | Bez limitu urzadzen")
        elif plan == "home":
            limits = get_limits(plan)
            cprint("OK", "Licencja: NetGuard HOME ✓",
                   f"Limit: {limits['max_devices']} urzadzen | Historia: {limits['history_days']} dni")
        else:
            limits = get_limits("free")
            cprint("INFO", "Licencja: NetGuard FREE (Demo)",
                   f"Limit: {limits['max_devices']} urzadzen | Brak AI | Uaktualnij: netguardhome.pl")

        _host_ip = self.scanner._get_own_ip(iface)
        _host_mac = self.scanner._get_own_mac(iface)
        if _host_ip and _host_mac:
            self.scanner.active_devices[_host_mac] = {
                "ip": _host_ip, "mac": _host_mac, "is_host": True, "tag": "trusted",
                "vendor": self.scanner._get_vendor(_host_mac),
                "hostname": self.cfg.get("device_names", {}).get(_host_mac) or socket.gethostname(),
                "status": "online",
            }

        capture_iface = lan if is_gw else iface
        if self.cfg.get("packet_capture", True):
            self.analyzer.start(capture_iface)

        if is_gw and not IS_WINDOWS:
            self.dns_proxy.start()

        if is_gw and not IS_WINDOWS and is_paid(plan):
            self.suricata.start(iface, self.scanner)

        threading.Thread(target=_check_updates_loop, daemon=True, name="UpdateCheck").start()

        if with_dashboard:
            dash_thread = threading.Thread(
                target=start_dashboard,
                args=(self.scanner, self.analyzer, self.ai,
                      self.cfg.get("dashboard_port", 8767), self.suricata,
                      self.cfg, _db, cprint, self.dns_proxy),
                daemon=True
            )
            dash_thread.start()
            url = f"http://localhost:{self.cfg.get('dashboard_port', 8767)}"
            def _open_browser():
                time.sleep(3)
                cprint("OK", f"Dashboard dostepny pod adresem: {url}")
                if IS_WINDOWS:
                    cprint("INFO", f"Otworz w przegladarce: {url}")
                try:
                    opened = webbrowser.open(url)
                    if not opened:
                        cprint("INFO", f"Nie udalo sie otworzyc przegladarki — wejdz recznie: {url}")
                except Exception:
                    cprint("INFO", f"Otworz recznie w przegladarce: {url}")
            threading.Thread(target=_open_browser, daemon=True).start()

        last_known_macs = set()

        while self.running:
            try:
                now_ts = time.time()
                cprint("INFO", f"Skanowanie sieci... [{datetime.datetime.now().strftime('%H:%M:%S')}]")
                self.scanner._health["last_scan_time"] = now_ts
                self.scanner._health["scan_count"] += 1
                devices = self.scanner.scan()
                self.scanner._health["total_devices_found"] = len(devices)

                for mac, info in devices.items():
                    is_new = _db.upsert_device(mac, info, save=False)
                    self.alerter.track_device(mac, info.get("hostname", ""), info.get("ip", ""))
                    if is_new and mac not in last_known_macs:
                        self.alerter.send("HIGH", "Nowe urzadzenie w sieci",
                            f"MAC: {mac} | IP: {info['ip']} | Producent: {info['vendor']}")
                        _db.add_event("NEW_DEVICE", "HIGH",
                            f"Nowe urzadzenie: {info.get('hostname','?')} ({info['ip']})", info)
                        self.alerter.track_new_device(
                            mac, info.get("hostname", "?"),
                            info.get("ip", ""), info.get("vendor", ""))

                    is_manual = mac in self.cfg.get("blocked_macs", [])
                    is_sched = is_scheduled_blocked(mac, self.cfg)
                    ip = info.get("ip")
                    if ip and not IS_WINDOWS and is_gw:
                        if is_manual or is_sched:
                            os.system(f"iptables -C FORWARD -s {ip} -j DROP 2>/dev/null || iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")
                            os.system(f"iptables -C FORWARD -d {ip} -j DROP 2>/dev/null || iptables -I FORWARD -d {ip} -j DROP 2>/dev/null")
                        else:
                            os.system(f"iptables -D FORWARD -s {ip} -j DROP 2>/dev/null")
                            os.system(f"iptables -D FORWARD -d {ip} -j DROP 2>/dev/null")
                        if mac in self.cfg.get("child_macs", []):
                            os.system(f"iptables -C FORWARD -s {ip} -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -I FORWARD -s {ip} -p tcp --dport 853 -j REJECT --reject-with tcp-reset 2>/dev/null")
                            for doh_ip in ("1.1.1.1","1.0.0.1","8.8.8.8","8.8.4.4","9.9.9.9","149.112.112.112","208.67.222.222","208.67.220.220"):
                                os.system(f"iptables -C FORWARD -s {ip} -d {doh_ip} -p tcp --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -I FORWARD -s {ip} -d {doh_ip} -p tcp --dport 443 -j REJECT --reject-with tcp-reset 2>/dev/null")
                            os.system(f"iptables -t nat -C PREROUTING -s {ip} -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null || iptables -t nat -I PREROUTING -s {ip} -p udp --dport 53 -j REDIRECT --to-port 5300 2>/dev/null")

                _db.save()

                current_macs = set(devices.keys())
                left = last_known_macs - current_macs
                for mac in left:
                    cprint("INFO", f"Urzadzenie opuscilo siec: {mac}")
                last_known_macs = current_macs

                _child_now = time.time()
                _child_today = datetime.datetime.now().strftime("%Y-%m-%d")
                _child_hm = datetime.datetime.now().strftime("%H:%M")
                for mac, info in devices.items():
                    if mac in self.cfg.get("child_macs", []) and info.get("status") == "online":
                        _entry = self.analyzer.child_online[mac]
                        if _child_today not in _entry:
                            _entry[_child_today] = {
                                "first": _child_hm, "last": _child_hm,
                                "total_minutes": 0.0, "last_ts": _child_now
                            }
                        else:
                            _day = _entry[_child_today]
                            _gap = _child_now - _day.get("last_ts", _child_now)
                            if _gap < self.cfg.get("scan_interval", 60) * 4:
                                _day["total_minutes"] += _gap / 60
                            _day["last"] = _child_hm
                            _day["last_ts"] = _child_now

                for alert in list(self.analyzer.alerts_queue):
                    if alert.get("severity") in ("CRITICAL", "HIGH"):
                        self.alerter.track_threat(
                            alert.get("type", ""),
                            alert.get("description", str(alert)),
                            alert.get("severity", ""))

                self.router.sync()

                self.alerter.check_daily_report(self.scanner)

                if int(time.time()) % 1800 == 0:
                    _db.checkpoint()
                    gc.collect()

                if int(time.time()) % 900 == 0 and self.ai.available:
                    context = json.dumps({
                        "devices": list(devices.values())[:5],
                        "alerts": (_db.get_events(5) if _db else [])
                    }, ensure_ascii=False)
                    summary = self.ai.analyze(context,
                        "Przeanalizuj biezacy stan sieci i podaj krotkie podsumowanie zagrozen.")
                    cprint("INFO", "AI Analiza sieci:", summary[:200] + "...")

                print(f"\n{C['gray']}--- Status: {len(devices)} urzadzen online | "
                      f"Alerty: {_db.event_count() if _db else 0} | "
                      f"Nastepne skanowanie: {self.cfg.get('scan_interval', 60)}s ---{C['reset']}\n")

                time.sleep(self.cfg.get("scan_interval", 60))

            except KeyboardInterrupt:
                break
            except Exception as e:
                cprint("WARN", f"Blad w petli glownej: {e}")
                self.scanner._health["errors_last_hour"] += 1
                self.analyzer._health["errors_last_hour"] += 1
                time.sleep(10)


def run_setup():
    print(f"""
{C['blue']}{C['bold']}
{chr(0x2554)}{chr(0x2550)*56}{chr(0x2557)}
{chr(0x2551)}            NETGUARD AI — Kreator konfiguracji              {chr(0x2551)}
{chr(0x255A)}{chr(0x2550)*56}{chr(0x255D)}
{C['reset']}""")

    # Load or detect defaults
    cfg = {}
    try:
        with open(_CONFIG_FILE) as f:
            cfg = json.load(f)
    except Exception:
        logging.getLogger(__name__).debug("Could not load existing config %s", _CONFIG_FILE)

    try:
        result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
        networks = re.findall(r'(\d+\.\d+\.\d+\.\d+/\d+)', result.stdout)
        if networks:
            print(f"Wykryte sieci lokalne: {', '.join(networks)}")
            if "network_range" not in cfg:
                cfg["network_range"] = networks[0]
    except Exception:
        logging.getLogger(__name__).debug("Could not detect local networks via ip route")

    network = input(f"Zakres sieci [{cfg.get('network_range', '192.168.1.0/24')}]: ").strip()
    if network:
        cfg["network_range"] = network

    email = input("Email do alertow (zostaw puste aby pominac): ").strip()
    if email:
        cfg["alert_email"] = email

    config_path = _CONFIG_FILE
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(cfg, f, indent=2)

    cprint("OK", f"Konfiguracja zapisana w {config_path}")
    cprint("INFO", "Uruchom agenta: sudo python3 -m netguard --dashboard")


def main():
    parser = argparse.ArgumentParser(description='NetGuard AI — Lokalny Agent Sieci Domowej')
    parser.add_argument('--setup',     action='store_true', help='Kreator konfiguracji')
    parser.add_argument('--dashboard', action='store_true', help='Uruchom web dashboard (port 8767)')
    parser.add_argument('--llm',       action='store_true', help='Wlacz lokalny LLM (Ollama)')
    parser.add_argument('--no-llm',    action='store_true', help='Wylacz LLM — tylko heurystyki')
    parser.add_argument('--model',     default='llama3.2',  help='Model Ollama (domyslnie: llama3.2)')
    parser.add_argument('--network',   default='',          help='Zakres sieci (np. 192.168.1.0/24)')
    parser.add_argument('--email',     default='',          help='Email do alertow')
    parser.add_argument('--interval',  type=int, default=60, help='Interwal skanowania (sekundy)')
    args = parser.parse_args()

    print_banner()

    if args.setup:
        run_setup()
        sys.exit(0)

    # Load config
    cfg = load_config()
    errors = validate_config(cfg)
    if errors:
        print("Blad: konfiguracja zawiera bledy — popraw config.json i uruchom ponownie")
        sys.exit(1)
    if args.network:
        cfg["network_range"] = args.network
    if args.email:
        cfg["alert_email"] = args.email
    if args.model:
        cfg["llm_model"] = args.model
    if args.interval:
        cfg["scan_interval"] = args.interval

    # Setup logging
    _setup_logging(cfg.get("log_file", "/var/log/netguard.log"))

    # Init global state
    global _db, _CONFIG
    _CONFIG = cfg
    limits_func = lambda: get_limits(get_plan(cfg))
    _db = DeviceDB(cfg.get("db_file", os.path.join(_AGENT_DIR, "netguard_devices.json")),
                   get_limits_func=limits_func)

    cprint("INFO", "Uruchamianie NetGuard AI...", f"Siec: {cfg['network_range']}")
    agent = NetGuardAgent(cfg)
    agent.run(with_dashboard=True)


if __name__ == "__main__":
    main()
