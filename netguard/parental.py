import socket
import threading
import logging

from netguard.models import CHILD_BLOCK_DOMAINS, _expand_blocked

logger = logging.getLogger(__name__)


class ChildDNSProxy:
    PORT = 5300

    def __init__(self, scanner=None, cfg: dict = None, cprint_func=None):
        self.scanner = scanner
        self.cfg = cfg or {}
        self.cprint = cprint_func or (lambda *a: None)
        self._sock = None
        self._running = False

    def start(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.PORT))
            self._sock.settimeout(1.0)
            self._running = True
            threading.Thread(target=self._loop, daemon=True, name="ChildDNSProxy").start()
            self.cprint("OK", f"ChildDNSProxy nasluchuje na :{self.PORT}")
        except Exception as e:
            self.cprint("WARN", f"ChildDNSProxy: nie mozna uruchomic: {e}")

    def _loop(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
                threading.Thread(target=self._handle, args=(data, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                logger.debug("ChildDNSProxy _loop exception, exiting")
                break

    def _handle(self, data, addr):
        src_ip = addr[0]
        src_mac = ""
        if self.scanner:
            for m, d in list(self.scanner.active_devices.items()):
                if d.get("ip") == src_ip:
                    src_mac = m.lower()
                    break
        qname = self._parse_qname(data)
        if qname and src_mac and src_mac in self.cfg.get("child_macs", []):
            parts = qname.split(".")
            base = ".".join(parts[-2:]) if len(parts) >= 2 else qname
            blocked = _expand_blocked(self.cfg.get("custom_block_domains", {}).get(src_mac, []))
            if base in blocked or qname in blocked or base in CHILD_BLOCK_DOMAINS:
                self._sock.sendto(self._nxdomain(data), addr)
                self.cprint("INFO", f"DNS proxy: zablokowano {qname} dla {src_ip}")
                return
        try:
            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.settimeout(3.0)
            fwd.sendto(data, ("192.168.100.42", 53))
            resp, _ = fwd.recvfrom(4096)
            fwd.close()
            self._sock.sendto(resp, addr)
        except Exception:
            logger.debug("DNS forward failed for %s", src_ip)

    def _parse_qname(self, data):
        try:
            offset, labels = 12, []
            while offset < len(data) and data[offset] != 0:
                n = data[offset]
                offset += 1
                labels.append(data[offset:offset+n].decode("ascii", errors="ignore"))
                offset += n
            return ".".join(labels).lower() if labels else None
        except Exception:
            logger.debug("Failed to parse DNS qname")
            return None

    def _nxdomain(self, query):
        h = bytearray(query[:12])
        h[2] = 0x84
        h[3] = 0x03
        h[6] = h[7] = h[8] = h[9] = h[10] = h[11] = 0
        return bytes(h) + query[12:]

    def stop(self):
        self._running = False
        try:
            self._sock.close()
        except Exception:
            logger.debug("ChildDNSProxy socket close error (ignored)")
