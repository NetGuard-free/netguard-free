import os
import json
import hashlib
import time
import datetime
import glob as _glob
import secrets
import urllib.request as _ur
import urllib.error as _ue
import socket as _socket
import threading
import gc
import logging

logger = logging.getLogger(__name__)

from functools import wraps

from netguard import FLASK_AVAILABLE, IS_WINDOWS, PSUTIL_AVAILABLE, C

import psutil  # noqa: F402

from netguard.config import save_devices, is_scheduled_blocked, _hash_password, _verify_password, save_config
from netguard.models import COMMON_PORTS
from netguard.license import get_plan, is_paid, get_limits
from netguard.gateway import detect_gateway_mode, setup_nat, cleanup_nat
from netguard import VERSION, _update_available, _latest_version


def start_dashboard(scanner, analyzer, ai, port: int = 8767,
                    suricata=None, cfg: dict = None, db=None,
                    cprint_func=None, dns_proxy=None):
    if not FLASK_AVAILABLE:
        cprint_func("WARN", "Flask niedostepny — dashboard wylaczony. pip install flask")
        return

    from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context

    script_dir = os.path.dirname(os.path.abspath(__file__))
    app = Flask(__name__, static_folder=script_dir)

    _admin_sessions = {}
    _ids_explanations = {}
    _SESSION_TTL = 1800
    _sys_prev = {}
    _login_attempts = {}
    _LOGIN_RATE_LIMIT = 5
    _LOGIN_RATE_WINDOW = 300
    _csrf_tokens = {}
    _CSRF_TTL = 3600

    DASHBOARD_TOKEN = ""
    token_file = os.path.join(os.path.dirname(
        os.path.join(script_dir, '..', 'config.json') if script_dir else ''), ".netguard_token")
    if os.path.exists(token_file):
        try:
            with open(token_file) as f:
                DASHBOARD_TOKEN = f.read().strip()
        except Exception:
            logger.debug("Could not read dashboard token file")
            DASHBOARD_TOKEN = ""
    if not DASHBOARD_TOKEN or len(DASHBOARD_TOKEN) != 32:
        DASHBOARD_TOKEN = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
        try:
            with open(token_file, "w") as f:
                f.write(DASHBOARD_TOKEN)
            os.chmod(token_file, 0o600)
        except Exception:
            logger.debug("Could not save dashboard token file")

    def _is_admin_session(req) -> bool:
        sess = req.headers.get("X-Admin-Session") or (req.json or {}).get("admin_session", "") if req.is_json else ""
        if not sess:
            sess = req.args.get("admin_session", "")
        now = time.time()
        if sess in _admin_sessions and _admin_sessions[sess] > now:
            _admin_sessions[sess] = now + _SESSION_TTL
            return True
        return False

    def require_token(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            is_admin = _is_admin_session(request)
            if not is_admin:
                token = (request.headers.get("X-NetGuard-Token") or
                         request.args.get("token") or
                         (request.json or {}).get("token", "") if request.is_json else "")
                if token != DASHBOARD_TOKEN:
                    if request.method in ("POST", "PUT", "DELETE"):
                        return jsonify({"error": "Wymagane logowanie administratora", "need_admin": True}), 401
                    return jsonify({"error": "Brak autoryzacji — nieprawidlowy token"}), 403
                if request.method in ("POST", "PUT", "DELETE"):
                    return jsonify({"error": "Wymagane logowanie administratora", "need_admin": True}), 401
            if request.method in ("POST", "PUT", "DELETE"):
                csrf = (request.headers.get("X-CSRF-Token") or
                        (request.json or {}).get("csrf_token", "") if request.is_json else "")
                now = time.time()
                if csrf in _csrf_tokens and _csrf_tokens[csrf] > now:
                    _csrf_tokens[csrf] = now + _CSRF_TTL
                else:
                    logger.warning("CSRF validation failed")
                    return jsonify({"error": "Nieprawidlowy token CSRF — odswiez strone i sprobuj ponownie"}), 403
            return f(*args, **kwargs)
        return decorated

    @app.route('/api/admin/login', methods=['POST'])
    def api_admin_login():
        client_ip = request.remote_addr or "unknown"
        now = time.time()
        attempts = _login_attempts.get(client_ip, [])
        attempts = [t for t in attempts if now - t < _LOGIN_RATE_WINDOW]
        if len(attempts) >= _LOGIN_RATE_LIMIT:
            retry_after = int(_LOGIN_RATE_WINDOW - (now - attempts[0]))
            logger.warning("Rate limit exceeded for %s — %d attempts in %ds",
                          client_ip, len(attempts), _LOGIN_RATE_WINDOW)
            return jsonify({"error": "Zbyt wiele prob logowania. Sproboj ponownie za %d sekund." % retry_after,
                           "retry_after": retry_after}), 429
        attempts.append(now)
        _login_attempts[client_ip] = attempts
        data = request.json or {}
        password = data.get("password", "")
        stored_hash = cfg.get("admin_password_hash", "")
        if not stored_hash:
            return jsonify({"error": "Brak hasla admina"}), 500
        if _verify_password(password, stored_hash):
            session_token = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
            _admin_sessions[session_token] = time.time() + _SESSION_TTL
            csrf_token = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
            _csrf_tokens[csrf_token] = time.time() + _CSRF_TTL
            cprint_func("OK", "Administrator zalogowany do dashboardu")
            return jsonify({"status": "ok", "session": session_token,
                           "csrf_token": csrf_token, "ttl": _SESSION_TTL})
        return jsonify({"error": "Nieprawidlowe haslo"}), 401

    @app.route('/api/admin/check', methods=['GET'])
    def api_admin_check():
        sess = request.args.get("session", "")
        now = time.time()
        if sess in _admin_sessions and _admin_sessions[sess] > now:
            return jsonify({"admin": True, "ttl": int(_admin_sessions[sess] - now)})
        return jsonify({"admin": False})

    @app.after_request
    def add_cors(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    @app.route('/api/devices')
    def api_devices():
        devs = list(scanner.active_devices.values())
        active_macs = {d.get('mac') for d in devs}
        extra_macs = set(cfg.get("blocked_macs", [])) | set(cfg.get("child_macs", []))
        for mac in extra_macs:
            if mac not in active_macs:
                stored = db.data.get("devices", {}).get(mac) if db else None
                if stored:
                    entry = dict(stored)
                    entry['mac'] = mac
                    entry['status'] = 'offline'
                    devs.append(entry)
                    active_macs.add(mac)
        for d in devs:
            mac = d.get('mac', '')
            d.setdefault('is_host', False)
            d['connection'] = cfg.get("connection_types", {}).get(mac, 'wifi')
            if mac in cfg.get("blocked_macs", []) or is_scheduled_blocked(mac, cfg):
                d['tag'] = 'blocked'
            elif mac in cfg.get("trusted_macs", []) or mac in cfg.get("child_macs", []) or d.get('is_host'):
                d['tag'] = 'trusted'
            elif mac in cfg.get("device_names", {}):
                d['tag'] = 'known'
            else:
                d['tag'] = 'new'
            d['child'] = mac in cfg.get("child_macs", [])
            d['schedule'] = cfg.get("schedules", {}).get(mac) or None
        return jsonify(devs)

    @app.route('/api/alerts')
    def api_alerts():
        limit = int(request.args.get("limit", 200))
        events = db.get_events(limit) if db else []
        if _ids_explanations:
            enriched = []
            for e in events:
                if e.get("type") == "SURICATA_ALERT":
                    sig = (e.get("data") or {}).get("signature", "")
                    expl = _ids_explanations.get(sig)
                    if expl:
                        e = dict(e)
                        e["data"] = dict(e.get("data") or {})
                        e["data"]["explanation_pl"] = expl
                enriched.append(e)
            return jsonify(enriched)
        return jsonify(events)

    @app.route('/api/ids/explain', methods=['POST'])
    def api_ids_explain():
        body = request.get_json(silent=True) or {}
        sig = body.get("signature", "").strip()
        expl = body.get("explanation", "").strip()
        if sig and expl:
            _ids_explanations[sig] = expl
            return jsonify({"ok": True})
        return jsonify({"error": "missing signature or explanation"}), 400

    @app.route('/api/ask', methods=['POST'])
    def api_ask():
        if not is_paid(get_plan(cfg)):
            return jsonify({"error": "AI dostepne od planu Home.",
                            "upgrade_url": "https://netguardhome.pl/#cennik"}), 403
        body = request.get_json(silent=True) or {}
        question = body.get("question", "").strip()
        if not question:
            return jsonify({"error": "missing question"}), 400
        payload = json.dumps({"question": question}).encode()

        def _stream():
            req = _ur.Request("http://192.168.100.42:8768/ask",
                              data=payload,
                              headers={"Content-Type": "application/json"},
                              method="POST")
            try:
                with _ur.urlopen(req, timeout=120) as r:
                    for line in r:
                        yield line
            except _ue.URLError as e:
                yield f"data: {json.dumps({'error': f'LLM offline: {e.reason}'})}\n\n".encode()
                yield b"data: [DONE]\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n".encode()
                yield b"data: [DONE]\n\n"
        return Response(stream_with_context(_stream()),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache"})

    @app.route('/api/stats')
    def api_stats():
        online = len([d for d in scanner.active_devices.values() if d.get("status") == "online"])
        total_devices = db.device_count() if db else 0
        total_events = db.event_count() if db else 0
        new = 0
        if db:
            for mac, d in db.data.get("devices", {}).items():
                if mac not in cfg.get("trusted_macs", []) and not d.get("is_host", False):
                    new += 1
        active = db.event_count(severity_filter=("CRITICAL", "HIGH")) if db else 0
        cutoff_24h = datetime.datetime.now() - datetime.timedelta(hours=24)
        cutoff_24h = datetime.datetime.now() - datetime.timedelta(hours=24)

        active_24h = db.event_count_since(cutoff_24h, severity_filter=("CRITICAL", "HIGH")) if db else 0
        return jsonify({"online": online, "new_devices": new,
                       "active_alerts": active, "active_alerts_24h": active_24h,
                       "total_devices": total_devices, "total_events": total_events})

    @app.route('/api/chat', methods=['POST'])
    def api_chat():
        if not is_paid(get_plan(cfg)):
            return jsonify({
                "error": "AI Chat dostepny od planu Home.",
                "upgrade_url": "https://netguardhome.pl/#cennik"
            }), 403
        data = request.json or {}
        question = data.get("message", "")
        if not question:
            return jsonify({"error": "Brak wiadomosci"}), 400
        try:
            context = json.dumps({
                "devices": list(scanner.active_devices.values())[:10],
                "recent_alerts": analyzer.get_recent_alerts(5),
                "network": cfg["network_range"]
            }, ensure_ascii=False, default=str)
        except Exception:
            logger.debug("Failed to build AI context, using minimal")
            context = json.dumps({"network": cfg["network_range"]})
        response = ai.analyze(context, question)
        return jsonify({"response": response})

    @app.route('/api/block/<mac>', methods=['POST'])
    @require_token
    def api_block(mac):
        if mac not in cfg.get("blocked_macs", []):
            if "blocked_macs" not in cfg:
                cfg["blocked_macs"] = []
            cfg["blocked_macs"].append(mac)
            save_devices(cfg)
            if not IS_WINDOWS:
                IS_GATEWAY, GATEWAY_WAN, GATEWAY_LAN = detect_gateway_mode()
                if IS_GATEWAY:
                    device = db.get_device(mac) if db else None
                    if device and device.get("ip"):
                        ip = device["ip"]
                        os.system(f"iptables -C FORWARD -s {ip} -j DROP 2>/dev/null || iptables -I FORWARD -s {ip} -j DROP 2>/dev/null")
                        os.system(f"iptables -C FORWARD -d {ip} -j DROP 2>/dev/null || iptables -I FORWARD -d {ip} -j DROP 2>/dev/null")
            if db:
                db.add_event("DEVICE_BLOCKED", "INFO", f"Urzadzenie zablokowane: {mac}", {"mac": mac})
        return jsonify({"status": "blocked", "mac": mac})

    @app.route('/api/unblock/<mac>', methods=['POST'])
    @require_token
    def api_unblock(mac):
        if mac in cfg.get("blocked_macs", []):
            cfg["blocked_macs"].remove(mac)
            save_devices(cfg)
            if not IS_WINDOWS:
                IS_GATEWAY, GATEWAY_WAN, GATEWAY_LAN = detect_gateway_mode()
                if IS_GATEWAY:
                    device = db.get_device(mac) if db else None
                    if device and device.get("ip"):
                        ip = device["ip"]
                        os.system(f"iptables -D FORWARD -s {ip} -j DROP 2>/dev/null")
                        os.system(f"iptables -D FORWARD -d {ip} -j DROP 2>/dev/null")
            if db:
                db.add_event("DEVICE_UNBLOCKED", "INFO", f"Urzadzenie odblokowane: {mac}", {"mac": mac})
        return jsonify({"status": "unblocked", "mac": mac})

    @app.route('/api/schedule', methods=['POST'])
    @require_token
    def api_schedule():
        data = request.json or {}
        mac = data.get("mac", "").lower().strip()
        start = data.get("start", "").strip()
        end = data.get("end", "").strip()
        if not mac:
            return jsonify({"error": "Brak mac"}), 400
        if "schedules" not in cfg:
            cfg["schedules"] = {}
        if not start or not end:
            if mac in cfg["schedules"]:
                del cfg["schedules"][mac]
            save_devices(cfg)
            if db:
                db.add_event("SCHEDULE_REMOVED", "INFO", f"Usunieto harmonogram: {mac}", {"mac": mac})
            return jsonify({"status": "schedule_removed", "mac": mac})
        cfg["schedules"][mac] = {"start": start, "end": end}
        save_devices(cfg)
        if db:
            db.add_event("SCHEDULE_ADDED", "INFO", f"Dodano harmonogram dla {mac} ({start}-{end})", {"mac": mac})
        return jsonify({"status": "schedule_added", "mac": mac, "schedule": cfg["schedules"][mac]})

    @app.route('/api/child/<mac>', methods=['POST'])
    @require_token
    def api_child(mac):
        mac = mac.lower().strip()
        if "child_macs" not in cfg:
            cfg["child_macs"] = []
        if mac in cfg["child_macs"]:
            cfg["child_macs"].remove(mac)
            save_devices(cfg)
            if db:
                db.add_event("CHILD_PROTECTION_OFF", "INFO", f"Wylaczono ochrone dziecieca: {mac}", {"mac": mac})
            return jsonify({"status": "child_removed", "mac": mac})
        else:
            cfg["child_macs"].append(mac)
            save_devices(cfg)
            if db:
                db.add_event("CHILD_PROTECTION_ON", "INFO", f"Wlaczono ochrone dziecieca: {mac}", {"mac": mac})
            return jsonify({"status": "child_added", "mac": mac})

    @app.route('/api/children')
    def api_children():
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        result = []
        for mac in cfg.get("child_macs", []):
            dev = scanner.active_devices.get(mac, {})
            name = cfg.get("device_names", {}).get(mac) or dev.get("hostname", mac)
            online_today = analyzer.child_online.get(mac, {}).get(today, {}) if hasattr(analyzer, 'child_online') else {}
            top_domains = sorted(analyzer.child_dns_hist.get(mac, {}).items(),
                                 key=lambda x: x[1], reverse=True)[:15] if hasattr(analyzer, 'child_dns_hist') else []
            result.append({
                "mac": mac,
                "name": name,
                "ip": dev.get("ip", ""),
                "online": dev.get("status") == "online",
                "today": {
                    "first": online_today.get("first", "-"),
                    "last": online_today.get("last", "-"),
                    "total_minutes": int(online_today.get("total_minutes", 0))
                },
                "dns_today": [{"domain": d, "count": c} for d, c in top_domains],
                "blocked_domains": cfg.get("custom_block_domains", {}).get(mac, [])
            })
        return jsonify({"children": result})

    @app.route('/api/child_block/<mac>', methods=['POST'])
    @require_token
    def api_child_block_add(mac):
        mac = mac.lower().strip()
        data = request.json or {}
        raw = data.get("domain", "").strip().lower()
        domain = raw.lstrip("www.").rstrip(".")
        parts = domain.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        if not domain or "." not in domain:
            return jsonify({"error": "Nieprawidlowa domena"}), 400
        if "custom_block_domains" not in cfg:
            cfg["custom_block_domains"] = {}
        if mac not in cfg["custom_block_domains"]:
            cfg["custom_block_domains"][mac] = []
        if domain not in cfg["custom_block_domains"][mac]:
            cfg["custom_block_domains"][mac].append(domain)
            save_devices(cfg)
            if db:
                db.add_event("CHILD_BLOCK_ADDED", "INFO",
                    f"Dodano blokade domeny {domain} dla {cfg.get('device_names',{}).get(mac, mac)}",
                    {"mac": mac, "domain": domain})
        return jsonify({"status": "ok", "mac": mac, "domain": domain,
                        "blocked": cfg["custom_block_domains"][mac]})

    @app.route('/api/child_block/<mac>', methods=['DELETE'])
    @require_token
    def api_child_block_remove(mac):
        mac = mac.lower().strip()
        data = request.json or {}
        domain = data.get("domain", "").strip().lower()
        blocks = cfg.get("custom_block_domains", {}).get(mac, [])
        if domain in blocks:
            cfg["custom_block_domains"][mac] = [d for d in blocks if d != domain]
            save_devices(cfg)
            if db:
                db.add_event("CHILD_BLOCK_REMOVED", "INFO",
                    f"Usunieto blokade domeny {domain} dla {cfg.get('device_names',{}).get(mac, mac)}",
                    {"mac": mac, "domain": domain})
        return jsonify({"status": "ok", "mac": mac,
                        "blocked": cfg.get("custom_block_domains", {}).get(mac, [])})

    @app.route('/api/child_unblock/<mac>', methods=['POST'])
    @require_token
    def api_child_unblock(mac):
        mac = mac.lower().strip()
        data = request.json or {}
        domain = data.get("domain", "").strip().lower()
        blocks = cfg.get("custom_block_domains", {}).get(mac, [])
        if domain in blocks:
            cfg["custom_block_domains"][mac] = [d for d in blocks if d != domain]
            save_devices(cfg)
            if db:
                db.add_event("CHILD_BLOCK_REMOVED", "INFO",
                    f"Usunieto blokade domeny {domain} dla {cfg.get('device_names',{}).get(mac, mac)}",
                    {"mac": mac, "domain": domain})
        return jsonify({"status": "ok", "mac": mac,
                        "blocked": cfg.get("custom_block_domains", {}).get(mac, [])})

    @app.route('/api/admin/status')
    def api_admin_status():
        token = request.headers.get('X-Admin-Token', '')
        exp = _admin_sessions.get(token, 0)
        unlocked = bool(token) and exp > time.time()
        if not unlocked and token in _admin_sessions:
            del _admin_sessions[token]
        pin_set = bool(cfg.get("admin_pin", ""))
        return jsonify({"unlocked": unlocked, "pin_set": pin_set})

    @app.route('/api/admin/unlock', methods=['POST'])
    def api_admin_unlock():
        data = request.json or {}
        stored = cfg.get("admin_pin", "")
        if not stored:
            return jsonify({"error": "PIN nie jest ustawiony"}), 400
        if data.get("pin", "") != stored:
            return jsonify({"error": "Nieprawidlowy PIN"}), 401
        token = secrets.token_hex(16)
        _admin_sessions[token] = time.time() + 1800
        return jsonify({"token": token})

    @app.route('/api/admin/lock', methods=['POST'])
    def api_admin_lock():
        token = request.headers.get('X-Admin-Token', '')
        _admin_sessions.pop(token, None)
        return jsonify({"ok": True})

    @app.route('/api/admin/setpin', methods=['POST'])
    def api_admin_setpin():
        data = request.json or {}
        stored = cfg.get("admin_pin", "")
        token = request.headers.get('X-Admin-Token', '')
        is_unlocked = bool(token) and _admin_sessions.get(token, 0) > time.time()
        if stored and not is_unlocked:
            return jsonify({"error": "Wymagane odblokowanie admina"}), 403
        new_pin = str(data.get("pin", "")).strip()
        if not new_pin:
            return jsonify({"error": "PIN nie moze byc pusty"}), 400
        if len(new_pin) < 4:
            return jsonify({"error": "PIN musi miec co najmniej 4 znaki"}), 400
        cfg["admin_pin"] = new_pin
        save_devices(cfg)
        _admin_sessions.clear()
        new_token = secrets.token_hex(16)
        _admin_sessions[new_token] = time.time() + 1800
        return jsonify({"ok": True, "token": new_token})

    @app.route('/api/iot', methods=['GET'])
    def api_iot_list():
        result = []
        for mac, iot_cfg in cfg.get("iot_devices", {}).items():
            result.append({
                "mac": mac,
                "name": iot_cfg.get("name", mac),
                "ip": iot_cfg.get("ip", ""),
                "alert_on_local_scan": iot_cfg.get("alert_on_local_scan", True),
                "max_upload_mb_per_hour": iot_cfg.get("max_upload_mb_per_hour", 50),
            })
        return jsonify(result)

    @app.route('/api/iot', methods=['POST'])
    @require_token
    def api_iot_add():
        data = request.json or {}
        mac = data.get("mac", "").lower().strip()
        if not mac:
            return jsonify({"error": "Brak adresu MAC"}), 400
        ip = data.get("ip", "")
        if not ip and db:
            ip = db.data.get("devices", {}).get(mac, {}).get("ip", "")
        iot_entry = {
            "name": (data.get("name") or mac).strip(),
            "ip": ip,
            "alert_on_local_scan": bool(data.get("alert_on_local_scan", True)),
            "max_upload_mb_per_hour": int(data.get("max_upload_mb_per_hour") or 50),
        }
        if "iot_devices" not in cfg:
            cfg["iot_devices"] = {}
        cfg["iot_devices"][mac] = iot_entry
        if hasattr(analyzer, 'iot_devices'):
            analyzer.iot_devices[mac] = iot_entry
        save_devices(cfg)
        if db:
            db.add_event("IOT_ADDED", "INFO", f"Dodano urzadzenie IoT: {iot_entry['name']} ({ip})", {"mac": mac})
        return jsonify({"ok": True, "mac": mac})

    @app.route('/api/iot/<mac>/delete', methods=['POST'])
    @app.route('/api/iot/<mac>', methods=['DELETE'])
    @require_token
    def api_iot_delete(mac):
        mac = mac.lower().strip()
        cfg.get("iot_devices", {}).pop(mac, None)
        if hasattr(analyzer, 'iot_devices'):
            analyzer.iot_devices.pop(mac, None)
        save_devices(cfg)
        if db:
            db.add_event("IOT_REMOVED", "INFO", f"Usunieto urzadzenie IoT: {mac}", {"mac": mac})
        return jsonify({"ok": True})

    @app.route('/api/trust/<mac>', methods=['POST'])
    @require_token
    def api_trust(mac):
        if mac not in cfg.get("trusted_macs", []):
            if "trusted_macs" not in cfg:
                cfg["trusted_macs"] = []
            cfg["trusted_macs"].append(mac)
            save_devices(cfg)
            if db:
                db.add_event("DEVICE_TRUSTED", "INFO", f"Urzadzenie oznaczone jako zaufane: {mac}", {"mac": mac})
        return jsonify({"status": "trusted", "mac": mac})

    @app.route('/api/rename', methods=['POST'])
    @require_token
    def api_rename():
        data = request.json or {}
        mac = data.get("mac", "").lower().strip()
        name = data.get("name", "").strip()
        if not mac or not name:
            return jsonify({"error": "Brak mac lub name"}), 400
        cfg.setdefault("device_names", {})[mac] = name
        save_devices(cfg)
        if mac in scanner.active_devices:
            scanner.active_devices[mac]["hostname"] = name
        if db:
            dev = db.data.get("devices", {}).get(mac, {})
            dev["hostname"] = name
            db.data.setdefault("devices", {})[mac] = dev
            db.save()
            db.add_event("DEVICE_RENAMED", "INFO",
                f"Urzadzenie {mac} otrzymalo nazwe: {name}", {"mac": mac, "name": name})
        return jsonify({"status": "ok", "mac": mac, "name": name})

    @app.route('/api/connection', methods=['POST'])
    @require_token
    def api_connection():
        data = request.json or {}
        mac = data.get("mac", "").lower().strip()
        ctype = data.get("connection", "").strip()
        if not mac or not ctype or ctype not in ['wifi', 'wired']:
            return jsonify({"error": "Brak mac lub nieprawidlowy connection_type"}), 400
        if "connection_types" not in cfg:
            cfg["connection_types"] = {}
        cfg["connection_types"][mac] = ctype
        save_devices(cfg)
        if db:
            db.add_event("CONFIG_CHANGED", "INFO",
                f"Zmiana typu polaczenia ({ctype}) dla urzadzenia: {mac}", {"mac": mac})
        return jsonify({"status": "ok", "mac": mac, "connection": ctype})

    @app.route('/api/test-report', methods=['POST', 'GET'])
    @require_token
    def api_test_report():
        try:
            import zoneinfo
            tz = zoneinfo.ZoneInfo("Europe/Warsaw")
        except ImportError:
            tz = datetime.timezone(datetime.timedelta(hours=1))
        now_local = datetime.datetime.now(tz)
        agents = [obj for obj in gc.get_objects() if hasattr(obj, '_send_daily_report')]
        if agents:
            a = agents[0]
            a._report_sent_date = None
            a._send_daily_report(scanner, now_local)
            return jsonify({"status": "ok", "message": f"Raport testowy wyslany na {cfg.get('alert_email', '?')}"})
        return jsonify({"status": "error", "message": "Nie znaleziono AlertManager"}), 500

    @app.route('/api/token')
    def api_token():
        addr = request.remote_addr or ''
        local_prefixes = ('127.', '::1', '10.', '172.', '192.168.')
        is_local = addr in ('127.0.0.1', '::1') or any(addr.startswith(p) for p in local_prefixes)
        if not is_local and not _is_admin_session(request):
            return jsonify({"error": "Dostep tylko z sieci lokalnej"}), 403
        return jsonify({"token": DASHBOARD_TOKEN})

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(script_dir, '..', 'netguard-home'), 'netguard.ico',
                                   mimetype='image/x-icon')

    @app.route('/manifest.json')
    def manifest():
        return send_from_directory(os.path.join(script_dir, '..'), 'manifest.json',
                                   mimetype='application/manifest+json')

    @app.route('/sw.js')
    def service_worker():
        resp = send_from_directory(os.path.join(script_dir, '..'), 'sw.js',
                                   mimetype='application/javascript')
        resp.headers['Service-Worker-Allowed'] = '/'
        return resp

    @app.route('/icon-192.png')
    def icon192():
        return send_from_directory(os.path.join(script_dir, '..', 'obrazy'), 'icon-192.png',
                                   mimetype='image/png')

    @app.route('/icon-512.png')
    def icon512():
        return send_from_directory(os.path.join(script_dir, '..', 'obrazy'), 'icon-512.png',
                                   mimetype='image/png')

    @app.route('/api/license')
    def api_license():
        plan = get_plan(cfg)
        limits = get_limits(plan)
        IS_GATEWAY, GATEWAY_WAN, GATEWAY_LAN = detect_gateway_mode()
        return jsonify({
            "plan": plan,
            "is_home": plan == "home",
            "is_enterprise": plan == "enterprise",
            "is_paid": is_paid(plan),
            "max_devices": limits["max_devices"],
            "history_days": limits["history_days"],
            "upgrade_url": "https://netguardhome.pl/#cennik",
            "is_gateway": IS_GATEWAY,
            "wan_iface": GATEWAY_WAN,
            "lan_iface": GATEWAY_LAN,
        })

    @app.route('/api/version')
    def api_version():
        return jsonify({
            "version": VERSION,
            "update_available": _update_available,
            "latest_version": _latest_version,
            "update_url": "https://netguardhome.pl/update.sh",
        })

    @app.route('/api/gateway')
    def api_gateway():
        IS_GATEWAY, GATEWAY_WAN, GATEWAY_LAN = detect_gateway_mode()
        return jsonify({
            "is_gateway": IS_GATEWAY,
            "wan_iface": GATEWAY_WAN,
            "lan_iface": GATEWAY_LAN,
        })

    @app.route('/api/ids/status')
    def api_ids_status():
        return jsonify(suricata.status() if suricata else {
            "available": False, "running": False, "pid": None,
            "alerts_count": 0, "last_alert": None})

    @app.route('/api/system')
    def api_system():
        cpu_pct = psutil.cpu_percent(interval=None) if PSUTIL_AVAILABLE else 0
        mem = psutil.virtual_memory() if PSUTIL_AVAILABLE else None
        temp_c = None
        try:
            for zone in sorted(_glob.glob('/sys/class/thermal/thermal_zone*/temp')):
                raw = int(open(zone).read().strip())
                val = raw / 1000 if raw > 1000 else float(raw)
                if 10 < val < 120:
                    temp_c = round(val, 1)
                    break
        except Exception:
            logger.debug("Could not read temperature from thermal zones")
        uptime_sec = 0
        try:
            uptime_sec = int(float(open('/proc/uptime').read().split()[0]))
        except Exception:
            logger.debug("Could not read uptime from /proc/uptime")
        wan_down_bps = wan_up_bps = 0
        now_t = time.time()
        try:
            net = psutil.net_io_counters(pernic=True) if PSUTIL_AVAILABLE else {}
            IS_GATEWAY, GATEWAY_WAN, GATEWAY_LAN = detect_gateway_mode()
            wan_key = GATEWAY_WAN or ''
            cur = net.get(wan_key)
            prev = _sys_prev.get('net')
            prev_t = _sys_prev.get('t', now_t)
            dt = now_t - prev_t
            if cur and prev and 0.5 < dt < 60:
                wan_down_bps = max(0, int((cur.bytes_recv - prev.bytes_recv) / dt))
                wan_up_bps = max(0, int((cur.bytes_sent - prev.bytes_sent) / dt))
            if cur:
                _sys_prev['net'] = cur
                _sys_prev['t'] = now_t
        except Exception:
            logger.debug("Could not read WAN interface network counters")
        online = len([d for d in scanner.active_devices.values() if d.get('status') == 'online'])
        cutoff_24h = datetime.datetime.now() - datetime.timedelta(hours=24)
        alerts_24h = db.event_count_since(cutoff_24h, severity_filter=("CRITICAL", "HIGH")) if db else 0
        IS_GATEWAY, GATEWAY_WAN, GATEWAY_LAN = detect_gateway_mode()
        ids_running = bool(suricata and suricata.status().get('running'))
        s_health = getattr(scanner, '_health', {})
        a_health = getattr(analyzer, '_health', {})
        agent_start = s_health.get("start_time", 0)
        agent_uptime = int(time.time() - agent_start) if agent_start > 0 else 0
        last_scan = s_health.get("last_scan_time", 0)
        scan_stale = int(time.time() - last_scan) if last_scan > 0 else -1
        last_pkt = a_health.get("last_packet_time", 0)
        pkt_stale = int(time.time() - last_pkt) if last_pkt > 0 else -1
        errors_h = s_health.get("errors_last_hour", 0) + a_health.get("errors_last_hour", 0)
        return jsonify({
            'cpu_pct': round(cpu_pct, 1),
            'ram_used_mb': mem.used // (1024 * 1024) if mem else 0,
            'ram_total_mb': mem.total // (1024 * 1024) if mem else 0,
            'ram_pct': round(mem.percent, 1) if mem else 0,
            'temp_c': temp_c,
            'uptime_sec': uptime_sec,
            'wan_iface': GATEWAY_WAN or '',
            'wan_down_bps': wan_down_bps,
            'wan_up_bps': wan_up_bps,
            'online_devices': online,
            'active_alerts_24h': alerts_24h,
            'ids_active': ids_running,
            # health self-check
            'agent_uptime_sec': agent_uptime,
            'scan_count': s_health.get("scan_count", 0),
            'last_scan_ago_sec': scan_stale,
            'scanner_alive': scan_stale < 300,
            'packets_captured': a_health.get("packets_captured", 0),
            'last_packet_ago_sec': pkt_stale,
            'sniffer_alive': pkt_stale < 300,
            'errors_last_hour': errors_h,
            'total_devices_found': s_health.get("total_devices_found", 0),
        })

    @app.route('/api/traffic')
    def api_traffic():
        samples = list(analyzer.traffic_samples)
        dev_bytes = dict(analyzer.device_bytes)
        top_devices = []
        for mac, byt in sorted(dev_bytes.items(), key=lambda x: -x[1])[:6]:
            dev = scanner.active_devices.get(mac) or (db.get_device(mac) if db else {}) or {}
            name = cfg.get("device_names", {}).get(mac) or dev.get("hostname") or dev.get("name") or mac
            top_devices.append({
                "mac": mac,
                "name": name,
                "ip": dev.get("ip", ""),
                "bytes": byt,
            })
        top_ports = []
        for port, count in sorted(analyzer.port_counts.items(), key=lambda x: -x[1])[:8]:
            port_devs = analyzer.port_devices.get(port, {})
            top_pd = []
            for mac, cnt in sorted(port_devs.items(), key=lambda x: -x[1])[:2]:
                dev = scanner.active_devices.get(mac) or (db.get_device(mac) if db else {}) or {}
                dname = cfg.get("device_names", {}).get(mac) or dev.get("hostname") or dev.get("name") or mac
                top_pd.append({"mac": mac, "name": dname, "count": cnt})
            top_ports.append({
                "port": port,
                "proto": COMMON_PORTS.get(port, "TCP/UDP"),
                "count": count,
                "devices": top_pd,
            })
        return jsonify({
            "samples": samples,
            "top_devices": top_devices,
            "top_ports": top_ports,
        })

    @app.route('/')
    def index():
        dashboard = os.path.join(script_dir, '..', 'strony_podstrony', 'network-agent-dashboard.html')
        if os.path.exists(dashboard):
            return send_from_directory(os.path.join(script_dir, '..', 'strony_podstrony'), 'network-agent-dashboard.html')
        return '<!DOCTYPE html><html lang="pl"><head><meta charset="utf-8"><title>NetGuard — dashboard</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#0b1120;color:#c8d6e5;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:20px;text-align:center}h1{color:#00d4ff;margin-bottom:8px;font-size:24px}p{color:#6b8299;margin-bottom:20px;font-size:14px}.links{display:flex;flex-wrap:wrap;gap:10px;justify-content:center}.links a{background:rgba(0,212,255,0.1);border:1px solid rgba(0,212,255,0.2);border-radius:8px;padding:12px 18px;color:#00d4ff;text-decoration:none;font-size:13px;transition:background 0.2s}.links a:hover{background:rgba(0,212,255,0.2)}.note{margin-top:24px;font-size:12px;color:#4a6080}</style></head><body><h1>&#x1f6e1; NetGuard</h1><p>Dashboard nie zosta&#x142; znaleziony. API jest dost&#x119;pne:</p><div class="links"><a href=\'/api/devices\'>&#x1f4e1; Urz&#x105;dzenia</a><a href=\'/api/alerts\'>&#x26a0;&#xfe0f; Alerty</a><a href=\'/api/stats\'>&#x1f4ca; Statystyki</a><a href=\'/api/system\'>&#x1f527; System</a></div></body></html>"'

    use_https = cfg.get("dashboard_https", False)
    cert_file = os.path.join(script_dir, '..', 'dashboard.crt')
    key_file = os.path.join(script_dir, '..', 'dashboard.key')
    if use_https and not (os.path.exists(cert_file) and os.path.exists(key_file)):
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization as _crypto_serialization
            import ipaddress as ipaddr_mod
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
                x509.NameAttribute(NameOID.COMMON_NAME, "NetGuard Dashboard"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddr_mod.ip_address("127.0.0.1")),
                ]), critical=False)
                .sign(key, hashes.SHA256(), backend=default_backend())
            )
            with open(key_file, "wb") as f:
                f.write(key.private_bytes(
                    encoding=_crypto_serialization.Encoding.PEM,
                    format=_crypto_serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=_crypto_serialization.NoEncryption()))
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(_crypto_serialization.Encoding.PEM))
            os.chmod(key_file, 0o600)
            cprint_func("OK", f"Wygenerowano certyfikat SSL: {cert_file}")
        except ImportError:
            cprint_func("WARN", "Biblioteka cryptography niedostepna — https wylaczony. Zainstaluj: pip install cryptography")
            use_https = False
        except Exception as e:
            cprint_func("WARN", f"Nie udalo sie wygenerowac certyfikatu SSL: {e}")
            use_https = False
    from werkzeug.serving import make_server
    proto = "https" if use_https else "http"
    cprint_func("OK", f"Dashboard dostepny: {proto}://localhost:{port}")
    srv = make_server('0.0.0.0', port, app, threaded=True)
    srv.socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    if use_https:
        import ssl as _ssl_mod
        ctx = _ssl_mod.SSLContext(_ssl_mod.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
