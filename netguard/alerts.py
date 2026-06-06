import datetime
import logging
from collections import deque, defaultdict

from netguard.email_service import send_html_email, build_daily_report_html, build_alert_html


class AlertManager:
    def __init__(self, email: str = "", cfg: dict = None,
                 cprint_func=None, db=None, log_func=None):
        self.email = email
        self.cfg = cfg or {}
        self.cprint = cprint_func or (lambda *a: None)
        self.db = db
        self.log = log_func or (lambda *a: None)
        self.notifications = deque(maxlen=500)
        self._day_devices_seen = set()
        self._day_new_devices = []
        self._day_threats = []
        self._report_sent_date = None

    def send(self, severity: str, title: str, detail: str):
        msg = f"[{severity}] {title}: {detail}"
        self.notifications.append({
            "time": datetime.datetime.now().isoformat(),
            "severity": severity, "title": title, "detail": detail
        })
        if severity == "CRITICAL":
            self.cprint("CRIT", title, detail)
        elif severity == "HIGH":
            self.cprint("WARN", title, detail)
        else:
            self.cprint("INFO", title, detail)
        self.log(msg)
        if self.email:
            self._send_email_smtp(severity, title, detail)

    def track_device(self, mac: str, hostname: str, ip: str):
        self._day_devices_seen.add(mac)

    def track_new_device(self, mac: str, hostname: str, ip: str, vendor: str):
        self._day_new_devices.append({
            "mac": mac, "hostname": hostname,
            "ip": ip, "vendor": vendor,
            "time": datetime.datetime.now().strftime("%H:%M")
        })

    def track_threat(self, threat_type: str, description: str, severity: str):
        self._day_threats.append({
            "type": threat_type, "description": description,
            "severity": severity,
            "time": datetime.datetime.now().strftime("%H:%M")
        })

    def check_daily_report(self, scanner):
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo("Europe/Warsaw")
        except (ImportError, KeyError):
            try:
                import pytz
                tz = pytz.timezone("Europe/Warsaw")
            except Exception:
                tz = datetime.timezone(datetime.timedelta(hours=1))
        now_local = datetime.datetime.now(tz)
        today = now_local.date()
        report_hour = 20
        if (now_local.hour == report_hour and
                now_local.minute < 2 and
                self._report_sent_date != today):
            self._report_sent_date = today
            self._send_daily_report(scanner, now_local)
            self._day_new_devices = []
            self._day_threats = []

    def _send_daily_report(self, scanner, now_local):
        if not self.email:
            self.cprint("WARN", "Brak emaila — raport nie wyslany")
            return
        date_str = now_local.strftime("%d.%m.%Y")
        events_today = self._get_events_today()
        online_devices = list(scanner.active_devices.values())
        online_count = len(online_devices)
        new_devs_db = [
            e for e in (self.db.data.get("events", []) if self.db else [])
            if e.get("type") == "NEW_DEVICE" and
            e.get("timestamp", "")[:10] == now_local.strftime("%Y-%m-%d")
        ]
        threats_today = [
            e for e in events_today
            if e.get("severity") in ("CRITICAL", "HIGH") and
            e.get("type") != "NEW_DEVICE"
        ]
        critical_count = len([e for e in threats_today if e.get("severity") == "CRITICAL"])
        high_count = len([e for e in threats_today if e.get("severity") == "HIGH"])
        if critical_count > 0:
            risk = "WYSOKIE"
        elif high_count > 2:
            risk = "SREDNIE"
        else:
            risk = "NISKIE"
        html, plain = build_daily_report_html(
            [], online_devices, new_devs_db, threats_today,
            self.cfg, risk, date_str, online_count
        )
        send_html_email(
            subject=f"NetGuard — Raport {date_str} | Ryzyko: {risk} | {online_count} urzadzen",
            html=html, plain=plain, cfg=self.cfg,
            cprint_func=self.cprint, log_func=self.log
        )
        self.cprint("OK", f"Dzienny raport wyslany na {self.email}")

    def _get_events_today(self) -> list:
        today = datetime.date.today().isoformat()
        return [e for e in (self.db.data.get("events", []) if self.db else [])
                if e.get("timestamp", "")[:10] == today]

    def _send_email_smtp(self, severity: str, title: str, detail: str):
        smtp_cfg = self.cfg.get("smtp", {})
        if not smtp_cfg.get("password", ""):
            return
        html, plain = build_alert_html(severity, title, detail, self.cfg)
        label = {"CRITICAL": "KRYTYCZNY", "HIGH": "WYSOKI", "INFO": "INFO"}.get(severity, severity)
        send_html_email(
            subject=f"[NetGuard {label}] {title}",
            html=html, plain=plain, cfg=self.cfg,
            cprint_func=self.cprint, log_func=self.log
        )
