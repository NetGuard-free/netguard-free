import logging
import sys
import os
import hashlib
import json
import time

from netguard import C, VERSION, _update_available, _latest_version


_LOGGER: logging.Logger = None


def _setup_logging(log_file: str):
    global _LOGGER
    from logging.handlers import RotatingFileHandler
    _LOGGER = logging.getLogger("netguard")
    _LOGGER.setLevel(logging.INFO)
    _LOGGER.handlers.clear()
    _LOGGER.propagate = False
    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        _LOGGER.addHandler(RotatingFileHandler(
            log_file, maxBytes=1*1024*1024, backupCount=3, encoding="utf-8"))
    except Exception:
        pass


def cprint(level: str, msg: str, detail: str = ""):
    if _LOGGER is None:
        _setup_logging(os.environ.get("NETGUARD_LOG_FILE", "/tmp/netguard.log"))
    colors = {"INFO": C["blue"], "WARN": C["yellow"], "CRIT": C["red"], "OK": C["green"]}
    icons  = {"INFO": "I", "WARN": "W", "CRIT": "!", "OK": "*"}
    c = colors.get(level, "")
    i = icons.get(level, "?")
    print(f"{c}{C['bold']}{i} [{level}]{C['reset']} {msg}")
    if detail:
        print(f"   {C['gray']}{detail}{C['reset']}")
    log_map = {"CRIT": logging.CRITICAL, "WARN": logging.WARNING,
               "INFO": logging.INFO, "OK": logging.INFO}
    log_line = f"[{level}] {msg}" + (f" | {detail}" if detail else "")
    _LOGGER.log(log_map.get(level, logging.INFO), "%s", log_line)


def _hash_password(password: str) -> str:
    from netguard import BCRYPT_AVAILABLE
    if BCRYPT_AVAILABLE:
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    return hashlib.sha256(password.encode()).hexdigest()


def _version_gt(a, b):
    try:
        return tuple(int(x) for x in a.split('.')) > tuple(int(x) for x in b.split('.'))
    except Exception:
        return False


def _check_updates_loop():
    global _update_available, _latest_version
    import urllib.request
    time.sleep(120)
    while True:
        try:
            with urllib.request.urlopen("https://netguardhome.pl/version.json", timeout=10) as r:
                data = json.loads(r.read().decode())
            latest = data.get('version', VERSION)
            _latest_version = latest
            _update_available = _version_gt(latest, VERSION)
        except Exception:
            pass
        time.sleep(86400)
