import time
import subprocess
import re

from netguard import IS_WINDOWS, C


class RouterSync:
    def __init__(self, scanner, cfg: dict = None, cprint_func=None, db=None):
        self.scanner = scanner
        self.cfg = cfg or {}
        self.cprint = cprint_func or (lambda *a: None)
        self.db = db
        self.last_sync = 0
        self.interval = cfg.get("router", {}).get("sync_interval", 60) if cfg else 60
        src = "arp -a" if IS_WINDOWS else "/proc/net/arp"
        self.cprint("OK", f"ARP Sync aktywny — czyta {src}")

    def sync(self) -> int:
        now = time.time()
        if now - self.last_sync < self.interval:
            return 0
        self.last_sync = now
        arp_devices = self._read_arp_table()
        new_count = 0
        for mac, ip in arp_devices.items():
            if mac not in self.scanner.active_devices:
                name = self.cfg.get("device_names", {}).get(mac) or f"Urzadzenie ({ip})"
                tag = "trusted" if mac in self.cfg.get("trusted_macs", []) else "new"
                self.scanner.active_devices[mac] = {
                    "ip": ip, "mac": mac,
                    "vendor": self.scanner._get_vendor(mac),
                    "hostname": name,
                    "status": "online",
                    "is_host": False,
                    "tag": tag,
                    "source": "arp_table",
                }
                if self.db:
                    self.db.upsert_device(mac, self.scanner.active_devices[mac], save=False)
                new_count += 1
                self.cprint("INFO", f"ARP Sync: wykryto {name} ({ip}) [{mac}]")
            else:
                self.scanner.active_devices[mac]["ip"] = ip
                self.scanner.active_devices[mac]["status"] = "online"
        self.scanner._apply_limit(self.scanner.active_devices)
        if new_count and self.db:
            self.db.save()
        return new_count

    def _read_arp_table(self) -> dict:
        if IS_WINDOWS:
            return self._read_arp_table_windows()
        devices = {}
        iface = self.cfg.get("interface", "eno1") if self.cfg else "eno1"
        _LIVE_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT"}
        try:
            result = subprocess.run(
                ["ip", "neigh", "show", "dev", iface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                ip = parts[0]
                state = parts[-1]
                if state not in _LIVE_STATES:
                    continue
                try:
                    mac = parts[parts.index("lladdr") + 1].lower()
                except (ValueError, IndexError):
                    continue
                if mac != "00:00:00:00:00:00" and ":" in ip:
                    continue
                if mac != "00:00:00:00:00:00":
                    devices[mac] = ip
        except Exception as e:
            self.cprint("WARN", f"ARP Sync: blad ip neigh: {e}")
        return devices

    def _read_arp_table_windows(self) -> dict:
        devices = {}
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
                    devices[mac] = ip
        except Exception as e:
            self.cprint("WARN", f"ARP Sync (Windows): blad: {e}")
        return devices
