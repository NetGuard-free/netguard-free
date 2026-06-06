import os
import json
import subprocess
import ipaddress
import re
import datetime
import getpass
import hashlib

from netguard import IS_WINDOWS, PSUTIL_AVAILABLE, C, _AGENT_DIR


CONFIG_FILE = os.path.join(_AGENT_DIR, "config.json")
DEVICES_FILE = os.path.join(_AGENT_DIR, "netguard_devices.json")
INFRA_ENV_FILE = os.path.join(_AGENT_DIR, ".infrastructure.env")


def _load_infrastructure_env():
    """Load .infrastructure.env into os.environ if present."""
    path = INFRA_ENV_FILE
    if not os.path.exists(path):
        alt = os.path.expanduser("~/.infrastructure.env")
        if os.path.exists(alt):
            path = alt
        else:
            return
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("\"'")
                os.environ.setdefault(key, val)
    except Exception:
        pass

_DEFAULT_LOG = (os.path.join(_AGENT_DIR, "netguard.log")
                if IS_WINDOWS else "/var/log/netguard.log")

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
    "dashboard_https": False,
    "log_file": _DEFAULT_LOG,
    "db_file": os.path.join(_AGENT_DIR, "netguard_devices.db"),
    "admin_password_hash": "",
    "iot_devices": {},
    "router": {"sync_interval": 60},
    "smtp": {"host": "smtp.gmail.com", "port": 587, "user": "", "password": ""},
}


def load_devices() -> dict:
    default = {
        "trusted_macs": [], "blocked_macs": [], "device_names": {},
        "schedules": {}, "connection_types": {}, "child_macs": [],
        "admin_pin": "", "iot_devices": {}, "custom_block_domains": {}
    }
    for path in [DEVICES_FILE, "/var/lib/netguard/netguard_devices.json"]:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    data = json.load(f)
                return {**default, **data}
            except Exception:
                pass
    return default


def save_devices(cfg: dict):
    try:
        data = {
            "trusted_macs":        cfg.get("trusted_macs", []),
            "blocked_macs":        cfg.get("blocked_macs", []),
            "device_names":        cfg.get("device_names", {}),
            "schedules":           cfg.get("schedules", {}),
            "connection_types":    cfg.get("connection_types", {}),
            "child_macs":          cfg.get("child_macs", []),
            "admin_pin":           cfg.get("admin_pin", ""),
            "iot_devices":         cfg.get("iot_devices", {}),
            "custom_block_domains": cfg.get("custom_block_domains", {}),
        }
        with open(DEVICES_FILE, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Blad zapisu netguard_devices.json: {e}")


def is_scheduled_blocked(mac: str, cfg: dict) -> bool:
    sched = cfg.get("schedules", {}).get(mac)
    if not sched:
        return False
    start_str = sched.get("start")
    end_str = sched.get("end")
    if not start_str or not end_str:
        return False
    try:
        now = datetime.datetime.now().time()
        start = datetime.datetime.strptime(start_str, "%H:%M").time()
        end = datetime.datetime.strptime(end_str, "%H:%M").time()
        if start <= end:
            return start <= now <= end
        else:
            return now >= start or now <= end
    except Exception:
        return False


def _detect_network() -> tuple:
    if IS_WINDOWS:
        try:
            if PSUTIL_AVAILABLE:
                import psutil as _psutil
                gws = _psutil.net_if_addrs()
                stats = _psutil.net_if_stats()
                for iface, addrs in gws.items():
                    if not stats.get(iface, None) or not stats[iface].isup:
                        continue
                    if iface.lower() in ('lo', 'loopback', 'localhost'):
                        continue
                    for addr in addrs:
                        if addr.family == 2:
                            ip = addr.address
                            netmask = addr.netmask
                            if ip.startswith('127.'):
                                continue
                            try:
                                net = str(ipaddress.ip_network(
                                    f"{ip}/{netmask}", strict=False))
                                return iface, net
                            except Exception:
                                pass
        except Exception:
            pass
        return "Ethernet", "192.168.1.0/24"
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r"dev (\S+)", result.stdout)
        iface = m.group(1) if m else "eth0"
        result2 = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show", iface],
            capture_output=True, text=True, timeout=5
        )
        m2 = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", result2.stdout)
        if m2:
            net = str(ipaddress.ip_network(m2.group(1), strict=False))
            return iface, net
    except Exception:
        pass
    return "eth0", "192.168.1.0/24"


def validate_config(cfg: dict) -> list:
    errors = []
    if not isinstance(cfg.get("network_range"), str):
        errors.append("network_range: musi byc stringiem (np. '192.168.1.0/24')")
    elif cfg["network_range"] != "auto":
        try:
            ipaddress.ip_network(cfg["network_range"], strict=False)
        except Exception:
            errors.append(f"network_range: '{cfg['network_range']}' nie jest poprawna siecia CIDR")

    if not isinstance(cfg.get("interface"), str):
        errors.append("interface: musi byc stringiem")

    interval = cfg.get("scan_interval", 60)
    if not isinstance(interval, (int, float)) or interval < 5 or interval > 3600:
        errors.append(f"scan_interval: {interval} — musi byc liczba od 5 do 3600")

    port = cfg.get("dashboard_port", 8767)
    if not isinstance(port, int) or port < 1024 or port > 65535:
        errors.append(f"dashboard_port: {port} — musi byc portem (1024-65535)")

    email = cfg.get("alert_email", "")
    if email and not isinstance(email, str):
        errors.append("alert_email: musi byc stringiem")
    elif email and ("@" not in email or "." not in email.split("@")[-1]):
        errors.append(f"alert_email: '{email}' nie wyglada na poprawny email")

    if not isinstance(cfg.get("packet_capture"), bool):
        errors.append("packet_capture: musi byc true/false")

    model = cfg.get("llm_model", "")
    if model and not isinstance(model, str):
        errors.append("llm_model: musi byc stringiem")

    smtp = cfg.get("smtp", {})
    if not isinstance(smtp, dict):
        errors.append("smtp: musi byc obiektem")
    else:
        if smtp.get("user") and not isinstance(smtp["user"], str):
            errors.append("smtp.user: musi byc stringiem")
        smtp_port = smtp.get("port", 587)
        if not isinstance(smtp_port, int) or smtp_port not in (25, 465, 587, 2525):
            errors.append(f"smtp.port: {smtp_port} — dozwolone: 25, 465, 587, 2525")

    if not isinstance(cfg.get("max_dns_per_min", 300), int):
        errors.append("max_dns_per_min: musi byc liczba calkowita")
    if not isinstance(cfg.get("port_scan_threshold", 10), int):
        errors.append("port_scan_threshold: musi byc liczba calkowita")

    return errors


def _hash_password(password: str) -> str:
    from netguard import BCRYPT_AVAILABLE
    if BCRYPT_AVAILABLE:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return hashlib.sha256(password.encode()).hexdigest()


def _verify_password(password: str, stored_hash: str) -> bool:
    from netguard import BCRYPT_AVAILABLE
    if not stored_hash:
        return False
    if stored_hash.startswith("$2") and BCRYPT_AVAILABLE:
        try:
            import bcrypt
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
        except Exception:
            return False
    if len(stored_hash) == 64:
        try:
            return hashlib.sha256(password.encode()).hexdigest() == stored_hash
        except Exception:
            return False
    return False


def _run_wizard() -> dict:
    from netguard import cprint
    print("\n" + "="*60)
    print("  NetGuard AI — Pierwsze uruchomienie")
    print("="*60 + "\n")
    iface, net = _detect_network()
    print(f"  Wykryto interfejs: {iface}")
    print(f"  Wykryto siec:      {net}\n")
    cfg = dict(CONFIG_DEFAULTS)
    ans = input(f"  Interfejs sieciowy [{iface}]: ").strip()
    cfg["interface"] = ans if ans else iface
    ans = input(f"  Zakres sieci [{net}]: ").strip()
    cfg["network_range"] = ans if ans else net
    ans = input("  Email do powiadomien (Enter aby pominac): ").strip()
    cfg["alert_email"] = ans
    if ans:
        cfg["smtp"]["user"] = ans
        print("  Haslo SMTP ustaw pozniej w config.json (smtp.password)")
    ans = input("  Port dashboardu [8767]: ").strip()
    cfg["dashboard_port"] = int(ans) if ans.isdigit() else 8767
    print("\n  Ustaw haslo administratora dashboardu.\n")
    while True:
        pwd = getpass.getpass("  Haslo administratora: ")
        pwd2 = getpass.getpass("  Powtorz haslo: ")
        if pwd == pwd2 and len(pwd) >= 4:
            cfg["admin_password_hash"] = _hash_password(pwd)
            print("  Haslo ustawione\n")
            break
        elif len(pwd) < 4:
            print("  Haslo musi miec co najmniej 4 znaki")
        else:
            print("  Hasla nie sa identyczne")
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
    print(f"  Konfiguracja zapisana w {CONFIG_FILE}")
    return cfg


def load_config() -> dict:
    _load_infrastructure_env()
    cfg = dict(CONFIG_DEFAULTS)
    if not os.path.exists(CONFIG_FILE):
        cfg = _run_wizard()
    else:
        try:
            with open(CONFIG_FILE) as f:
                user_cfg = json.load(f)
            cfg.update(user_cfg)
            for key in ("smtp", "router"):
                if key in CONFIG_DEFAULTS:
                    merged = dict(CONFIG_DEFAULTS[key])
                    merged.update(user_cfg.get(key, {}))
                    cfg[key] = merged
        except Exception as e:
            print(f"Blad wczytywania config.json: {e} — uzywam domyslnych")
    if cfg.get("network_range") == "auto" or cfg.get("interface") == "auto":
        iface, net = _detect_network()
        if cfg.get("interface") == "auto":
            cfg["interface"] = iface
        if cfg.get("network_range") == "auto":
            cfg["network_range"] = net
    if not cfg["smtp"].get("password") and os.environ.get("SMTP_GMAIL_PASSWORD"):
        cfg["smtp"]["password"] = os.environ["SMTP_GMAIL_PASSWORD"]
    if not cfg["smtp"].get("user") and os.environ.get("SMTP_GMAIL_USER"):
        cfg["smtp"]["user"] = os.environ["SMTP_GMAIL_USER"]
    if not cfg.get("alert_email") and os.environ.get("SMTP_GMAIL_USER"):
        cfg["alert_email"] = os.environ["SMTP_GMAIL_USER"]

    devices_data = load_devices()
    cfg["trusted_macs"]        = devices_data.get("trusted_macs", [])
    cfg["blocked_macs"]        = devices_data.get("blocked_macs", [])
    cfg["device_names"]        = devices_data.get("device_names", {})
    cfg["connection_types"]    = devices_data.get("connection_types", {})
    cfg["child_macs"]          = devices_data.get("child_macs", [])
    cfg["admin_pin"]           = devices_data.get("admin_pin", "")
    cfg["iot_devices"]         = devices_data.get("iot_devices", {})
    cfg["custom_block_domains"] = devices_data.get("custom_block_domains", {})
    errors = validate_config(cfg)
    if errors:
        print("\n" + "!" * 60)
        print("  BLEDY KONFIGURACJI — agent nie uruchomi sie:")
        for e in errors:
            print(f"  • {e}")
        print("!" * 60 + "\n")
        return cfg
    return cfg


def save_config(cfg: dict):
    try:
        exclude = ("log_file", "db_file", "trusted_macs", "blocked_macs", "device_names")
        saveable = {k: v for k, v in cfg.items() if k not in exclude}
        with open(CONFIG_FILE, "w") as f:
            json.dump(saveable, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Blad zapisu config.json: {e}")
