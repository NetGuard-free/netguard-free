import os
import json
import hashlib
import datetime
import time
import sqlite3
import threading
from typing import Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT,
    hostname TEXT DEFAULT '',
    vendor TEXT DEFAULT '',
    status TEXT DEFAULT 'online',
    tag TEXT DEFAULT 'new',
    is_host INTEGER DEFAULT 0,
    first_seen TEXT DEFAULT '',
    last_seen TEXT DEFAULT '',
    seen_count INTEGER DEFAULT 1,
    extra TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT DEFAULT '',
    data TEXT DEFAULT '{}'
);
"""


class DeviceDB:
    def __init__(self, path: str, get_limits_func=None):
        self.path = path
        self.get_limits = get_limits_func
        self._local = threading.local()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._maybe_migrate_legacy_json()
        self._init_db()

    def _is_valid_sqlite(self) -> bool:
        if not os.path.exists(self.path):
            return False
        try:
            with open(self.path, "rb") as f:
                header = f.read(16)
            return header == b"SQLite format 3\0"
        except Exception:
            return False

    def _maybe_migrate_legacy_json(self):
        if self._is_valid_sqlite():
            return
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            db_path = self.path.rsplit(".", 1)[0] + ".db"
            self.path = db_path
        except (json.JSONDecodeError, UnicodeDecodeError):
            os.rename(self.path, self.path + ".bak")
        except Exception:
            pass

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn.execute("PRAGMA wal_autocheckpoint=500")
        return self._local.conn

    def checkpoint(self):
        try:
            self._conn.execute("PRAGMA wal_checkpoint(RESTART)")
        except Exception:
            pass

    def _init_db(self):
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._migrate_from_json()

    def _migrate_from_json(self):
        json_path = self.path.replace(".db", ".json")
        if json_path == self.path:
            json_path = self.path + ".json"
        count = self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        if count > 0 or not os.path.exists(json_path):
            return
        try:
            with open(json_path) as f:
                data = json.load(f)
            old_devices = data.get("devices", {})
            if not isinstance(old_devices, dict) or not old_devices:
                return
            for mac, info in old_devices.items():
                self.upsert_device(mac, info, save=False)
            for evt in data.get("events", []):
                self._insert_event(evt)
            self._conn.commit()
            os.rename(json_path, json_path + ".bak")
        except Exception:
            pass

    def _insert_event(self, evt: dict):
        self._conn.execute(
            "INSERT OR IGNORE INTO events (id, timestamp, type, severity, description, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (evt.get("id", ""), evt.get("timestamp", ""), evt.get("type", ""),
             evt.get("severity", ""), evt.get("description", ""),
             json.dumps(evt.get("data", {}), default=str))
        )

    def get_device(self, mac: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        if not row:
            return None
        dev = dict(row)
        try:
            extra = json.loads(dev.pop("extra", "{}"))
        except (json.JSONDecodeError, TypeError):
            extra = {}
        dev.update(extra)
        dev["is_host"] = bool(dev["is_host"])
        return dev

    def upsert_device(self, mac: str, info: dict, save: bool = True) -> bool:
        existing = self._conn.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac,)
        ).fetchone()
        is_new = existing is None
        now = datetime.datetime.now().isoformat()
        extra_keys = {"ip", "hostname", "vendor", "status", "tag", "is_host",
                      "first_seen", "last_seen", "seen_count"}
        core = {k: info.get(k, "") for k in extra_keys}
        extra = {k: v for k, v in info.items() if k not in extra_keys and k != "mac"}
        if existing:
            existing = dict(existing)
            core["first_seen"] = info.get("first_seen", existing.get("first_seen", now))
            core["seen_count"] = existing.get("seen_count", 0) + 1
        else:
            core["first_seen"] = now
            core["seen_count"] = 1
        core["last_seen"] = now
        self._conn.execute(
            "INSERT OR REPLACE INTO devices "
            "(mac, ip, hostname, vendor, status, tag, is_host, "
            " first_seen, last_seen, seen_count, extra) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (mac, core["ip"], core["hostname"], core["vendor"],
             core["status"], core["tag"], int(bool(core.get("is_host"))),
             core["first_seen"], core["last_seen"], core["seen_count"],
             json.dumps(extra, default=str))
        )
        if save:
            self._conn.commit()
        return is_new

    def add_event(self, event_type: str, severity: str, description: str,
                  data: dict = None) -> dict:
        evt = {
            "id": hashlib.md5(f"{time.time()}{event_type}".encode()).hexdigest()[:8],
            "timestamp": datetime.datetime.now().isoformat(),
            "type": event_type,
            "severity": severity,
            "description": description,
            "data": data or {}
        }
        self._insert_event(evt)
        try:
            days = self.get_limits().get("history_days", 30) if self.get_limits else 30
        except Exception:
            days = 30
        cutoff = (datetime.datetime.now() - datetime.timedelta(days=days)).isoformat()
        self._conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        self._conn.commit()
        return evt

    def get_events(self, limit: int = 100) -> list:
        rows = self._conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        result = []
        for row in rows:
            evt = dict(row)
            try:
                evt["data"] = json.loads(evt.get("data", "{}"))
            except (json.JSONDecodeError, TypeError):
                evt["data"] = {}
            result.append(evt)
        return result

    def event_count(self, severity_filter: tuple = None) -> int:
        if severity_filter:
            placeholders = ",".join("?" for _ in severity_filter)
            row = self._conn.execute(
                f"SELECT COUNT(*) FROM events WHERE severity IN ({placeholders})",
                severity_filter
            ).fetchone()
        else:
            row = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row else 0

    def event_count_since(self, since: datetime.datetime, severity_filter: tuple = None) -> int:
        if severity_filter:
            placeholders = ",".join("?" for _ in severity_filter)
            row = self._conn.execute(
                f"SELECT COUNT(*) FROM events WHERE timestamp >= ? AND severity IN ({placeholders})",
                (since.isoformat(), *severity_filter)
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
                (since.isoformat(),)
            ).fetchone()
        return row[0] if row else 0

    def device_count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM devices").fetchone()
        return row[0] if row else 0

    def get_devices(self) -> dict:
        rows = self._conn.execute("SELECT * FROM devices").fetchall()
        devices = {}
        for row in rows:
            dev = dict(row)
            try:
                extra = json.loads(dev.pop("extra", "{}"))
            except (json.JSONDecodeError, TypeError):
                extra = {}
            dev.update(extra)
            dev["is_host"] = bool(dev["is_host"])
            mac = dev.pop("mac")
            dev["mac"] = mac
            devices[mac] = dev
        return devices

    def save(self):
        self._conn.commit()

    # Backward compat for tests that access .data directly
    @property
    def data(self) -> dict:
        return {
            "devices": self.get_devices(),
            "events": self.get_events(),
            "rules": [],
        }
