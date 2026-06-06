import os
import sys
import subprocess
import re
import ipaddress
import socket
import shutil
import json
import threading
import time

from netguard import IS_WINDOWS, C, PSUTIL_AVAILABLE


def detect_gateway_mode() -> tuple:
    if IS_WINDOWS:
        return False, None, None
    try:
        with open('/proc/sys/net/ipv4/ip_forward') as f:
            if f.read().strip() != '1':
                return False, None, None
        out = subprocess.check_output(
            ['ip', 'route', 'show', 'default'], text=True, stderr=subprocess.DEVNULL)
        m = re.search(r'dev\s+(\S+)', out)
        if not m:
            return False, None, None
        wan = m.group(1)
        stats = PSUTIL_AVAILABLE and __import__('psutil', fromlist=['net_if_stats']).net_if_stats() or {}
        addrs = PSUTIL_AVAILABLE and __import__('psutil', fromlist=['net_if_addrs']).net_if_addrs() or {}
        lan = None
        for iface, s in stats.items():
            if iface in ('lo', wan) or not s.isup:
                continue
            if any(iface.startswith(p) for p in ('docker', 'veth', 'br-', 'virbr', 'tun', 'tap')):
                continue
            has_private_ipv4 = any(
                a.family == socket.AF_INET and
                ipaddress.ip_address(a.address).is_private
                for a in addrs.get(iface, [])
            )
            if not has_private_ipv4:
                continue
            lan = iface
            break
        if not lan:
            return False, None, None
        return True, wan, lan
    except Exception:
        return False, None, None


def setup_nat(wan: str, lan: str, cprint=None):
    rules = [
        f'iptables -t nat -C POSTROUTING -o {wan} -j MASQUERADE 2>/dev/null || '
        f'iptables -t nat -A POSTROUTING -o {wan} -j MASQUERADE',
        f'iptables -C FORWARD -i {lan} -o {wan} -j ACCEPT 2>/dev/null || '
        f'iptables -A FORWARD -i {lan} -o {wan} -j ACCEPT',
        f'iptables -C FORWARD -i {wan} -o {lan} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || '
        f'iptables -A FORWARD -i {wan} -o {lan} -m state --state RELATED,ESTABLISHED -j ACCEPT',
    ]
    for cmd in rules:
        os.system(cmd + ' 2>/dev/null')
    if cprint:
        cprint("OK", f"Tryb Gateway aktywny", f"WAN: {wan} | LAN: {lan} | NAT: wlaczony")


def cleanup_nat(wan: str, lan: str, cprint=None):
    os.system(f'iptables -t nat -D POSTROUTING -o {wan} -j MASQUERADE 2>/dev/null')
    os.system(f'iptables -D FORWARD -i {lan} -o {wan} -j ACCEPT 2>/dev/null')
    os.system(f'iptables -D FORWARD -i {wan} -o {lan} -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null')
    if cprint:
        cprint("INFO", "Reguly NAT Gateway usuniete")


_SURICATA_CONFIG_PATH = "/etc/suricata/netguard.yaml"
_SURICATA_RULES_PATH = "/etc/suricata/rules/netguard.rules"
_SURICATA_WHITELIST_PATH = "/etc/suricata/rules/whitelist.rules"
_SURICATA_LOG_DIR = "/var/log/suricata"
_SURICATA_EVE = "/var/log/suricata/eve.json"

_SURICATA_CONFIG_TEMPLATE = """\
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[{home_net}]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SSH_PORTS: "22"
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502

default-log-dir: {log_dir}

stats:
  enabled: no

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      community-id: false
      types:
        - alert:
            payload: no
            packet: no
            metadata: no
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: no

af-packet:
  - interface: {iface}
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

detect:
  profile: low
  custom-values:
    toclient-groups: 2
    toserver-groups: 10

threading:
  set-cpu-affinity: no
  worker-threads: 1

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
    dns:
      enabled: yes
    ssh:
      enabled: no
    smtp:
      enabled: no
    imap:
      enabled: no
    dcerpc:
      enabled: no
    ftp:
      enabled: no
    rdp:
      enabled: no
    nfs:
      enabled: no
    smb:
      enabled: no
    tftp:
      enabled: no
    krb5:
      enabled: no
    ikev2:
      enabled: no
    ntp:
      enabled: no
    dhcp:
      enabled: no
    sip:
      enabled: no

default-rule-path: /etc/suricata/rules
rule-files:
  - whitelist.rules
  - netguard.rules
"""

_SURICATA_SEV_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM"}

_SURICATA_LITE_RULES = [
    ("botcc.portgrouped",   "Znane serwery C2 (IP)"),
    ("emerging-exploit",    "Exploity przegladarek i plikow"),
    ("emerging-scan",       "Skanowanie portow i sieci"),
    ("emerging-dns",        "Anomalie DNS"),
    ("emerging-web_client", "Ataki webowe na klientow"),
]


class SuricataManager:
    def __init__(self, db=None, scanner=None, cprint_func=None, cfg=None):
        self.binary = shutil.which("suricata")
        self.running = False
        self.scanner = scanner
        self.db = db
        self.cprint = cprint_func or (lambda *a: None)
        self.cfg = cfg or {}
        self._proc = None
        self._thread = None
        self.alerts_count = 0
        self.last_alert_ts = None

    def is_available(self) -> bool:
        return self.binary is not None

    def _suricata_version_str(self) -> str:
        try:
            out = subprocess.check_output([self.binary, "--build-info"], text=True,
                                          stderr=subprocess.DEVNULL, timeout=5)
            m = re.search(r'Version\s+(\d+\.\d+)', out)
            if m:
                major = int(m.group(1).split(".")[0])
                return f"suricata-{major}.0"
        except Exception:
            pass
        return "suricata-6.0"

    def _download_rules(self):
        ver = self._suricata_version_str()
        self.cprint("INFO", f"Suricata: pobieranie regul ET Open ({ver} lite)...")
        combined = []
        et_base = "https://rules.emergingthreats.net/open/{ver}/rules/{cat}.rules"
        for cat, label in _SURICATA_LITE_RULES:
            url = et_base.format(ver=ver, cat=cat)
            try:
                result = subprocess.run(
                    ["curl", "-sf", "--max-time", "30", url],
                    capture_output=True, text=True)
                if result.returncode == 0 and result.stdout.strip():
                    lines = [l for l in result.stdout.splitlines() if not l.startswith("#") and l.strip()]
                    combined.extend(lines)
                    self.cprint("OK", f"  {label}: {len(lines)} regul")
                else:
                    self.cprint("WARN", f"  {label}: brak odpowiedzi (pominieto)")
            except Exception as e:
                self.cprint("WARN", f"  {label}: blad pobierania: {e}")
        with open(_SURICATA_RULES_PATH, "w") as f:
            f.write("\n".join(combined))
        self.cprint("OK", f"Suricata: zaladowano {len(combined)} regul lacznie")
        return len(combined)

    def _write_whitelist(self):
        domains = self.db.data.get("suricata_whitelist", []) if self.db else []
        lines = ["# NetGuard whitelist — generowane automatycznie"]
        for i, domain in enumerate(domains, start=1):
            sid = 9000000 + i
            lines.append(
                f'pass dns any any -> any any '
                f'(dns.query; content:"{domain}"; nocase; '
                f'msg:"NetGuard whitelist: {domain}"; sid:{sid}; rev:1;)'
            )
        with open(_SURICATA_WHITELIST_PATH, "w") as f:
            f.write("\n".join(lines) + "\n")

    def _prepare(self, iface: str):
        network = self.cfg.get("network_range", "192.168.100.0/24")
        home_net = network.split("/")[0] + "/" + network.split("/")[1] if "/" in network else network
        os.makedirs(_SURICATA_LOG_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(_SURICATA_RULES_PATH), exist_ok=True)
        if not os.path.exists(_SURICATA_RULES_PATH) or os.path.getsize(_SURICATA_RULES_PATH) == 0:
            self._download_rules()
        self._write_whitelist()
        with open(_SURICATA_CONFIG_PATH, "w") as f:
            f.write(_SURICATA_CONFIG_TEMPLATE.format(
                home_net=home_net, log_dir=_SURICATA_LOG_DIR, iface=iface))

    def start(self, iface: str, scanner):
        if not self.is_available():
            self.cprint("WARN", "Suricata: brak — IDS wylaczony", "Zainstaluj: apt install suricata")
            return
        self.scanner = scanner
        self._prepare(iface)
        try:
            self._proc = subprocess.Popen(
                [self.binary, "-c", _SURICATA_CONFIG_PATH,
                 "-i", iface, "-l", _SURICATA_LOG_DIR],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.cprint("OK", f"Suricata IDS uruchomiona na {iface}", f"PID: {self._proc.pid}")
        except Exception as e:
            self.cprint("WARN", f"Suricata: blad uruchomienia: {e}")
            return
        self.running = True
        self._thread = threading.Thread(target=self._reader_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass

    def _reader_loop(self):
        for _ in range(60):
            if os.path.exists(_SURICATA_EVE):
                break
            time.sleep(1)
        if not os.path.exists(_SURICATA_EVE):
            self.cprint("WARN", "Suricata: brak eve.json po 60s — sprawdz logi")
            return
        self.cprint("OK", f"Suricata: czytanie alertow z {_SURICATA_EVE}")
        try:
            with open(_SURICATA_EVE, "r") as f:
                f.seek(0, 2)
                while self.running:
                    line = f.readline()
                    if not line:
                        if self._proc and self._proc.poll() is not None:
                            self.cprint("WARN", "Suricata: proces zakonczony nieoczekiwanie")
                            break
                        time.sleep(0.3)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._handle_event(json.loads(line))
                    except (json.JSONDecodeError, Exception):
                        pass
        except Exception as e:
            self.cprint("WARN", f"Suricata reader: {e}")

    def _ip_to_mac(self, ip: str) -> str:
        if not self.scanner:
            return ""
        for mac, dev in self.scanner.active_devices.items():
            if dev.get("ip") == ip:
                return mac
        return ""

    def _handle_event(self, event: dict):
        etype = event.get("event_type")
        if etype == "alert":
            alert = event.get("alert", {})
            src_ip = event.get("src_ip", "?")
            dst_ip = event.get("dest_ip", "?")
            dst_port = event.get("dest_port", "")
            proto = event.get("proto", "")
            sig = alert.get("signature", "Nieznana sygnatura")
            category = alert.get("category", "")
            sig_id = alert.get("signature_id", 0)
            sev = alert.get("severity", 2)
            ng_sev = _SURICATA_SEV_MAP.get(sev, "HIGH")
            mac = self._ip_to_mac(src_ip)
            dev = self.scanner.active_devices.get(mac, {}) if mac else {}
            hostname = dev.get("hostname", src_ip)
            dst_str = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
            if self.db:
                self.db.add_event(
                    "SURICATA_ALERT", ng_sev,
                    f"[IDS] {hostname} -> {dst_str} | {sig}",
                    {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
                     "proto": proto, "signature": sig, "signature_id": sig_id,
                     "category": category, "severity_raw": sev, "mac": mac, "hostname": hostname}
                )
            self.alerts_count += 1
            self.last_alert_ts = event.get("timestamp", "")
            self.cprint("WARN", f"Suricata [{ng_sev}]: {sig}", f"{src_ip} -> {dst_str}")
        elif etype == "anomaly":
            anomaly = event.get("anomaly", {})
            atype = anomaly.get("type", "")
            aname = anomaly.get("event", "")
            src_ip = event.get("src_ip", "?")
            if atype not in ("stream", "decode") and self.db:
                self.db.add_event(
                    "SURICATA_ANOMALY", "MEDIUM",
                    f"[IDS] Anomalia {atype}: {aname} od {src_ip}",
                    {"src_ip": src_ip, "type": atype, "event": aname}
                )

    def status(self) -> dict:
        proc_ok = self._proc is not None and self._proc.poll() is None
        return {
            "available": self.is_available(),
            "running": proc_ok,
            "pid": self._proc.pid if proc_ok else None,
            "alerts_count": self.alerts_count,
            "last_alert": self.last_alert_ts,
        }
