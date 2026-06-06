import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_html_email(subject: str, html: str, plain: str,
                    cfg: dict, cprint_func=None, log_func=None):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = cfg.get("alert_email", "")
        msg["To"] = cfg.get("alert_email", "")
        msg.attach(MIMEText(plain, "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
        smtp_cfg = cfg.get("smtp", {})
        host = smtp_cfg.get("host", "smtp.gmail.com")
        port = smtp_cfg.get("port", 587)
        user = smtp_cfg.get("user", cfg.get("alert_email", ""))
        pwd = smtp_cfg.get("password", "")
        if not pwd:
            if cprint_func:
                cprint_func("WARN", "Brak hasla SMTP")
            if log_func:
                log_func(f"[EMAIL — nie wyslany, brak hasla]\n{plain}")
            return
        with smtplib.SMTP(host, port) as s:
            s.starttls()
            s.login(user, pwd)
            s.send_message(msg)
    except Exception as e:
        if cprint_func:
            cprint_func("WARN", f"Blad wysylania emaila: {e}")
        if log_func:
            log_func(f"[EMAIL]\n{plain}")


def build_daily_report_html(alerts: list, online_devices: list,
                            new_devs_db: list, threats_today: list,
                            cfg: dict, risk: str, date_str: str,
                            online_count: int) -> tuple:
    icons = {
        "PORT_SCAN": "S", "ARP_SPOOFING": "W", "DNS_TUNNEL": "D",
        "MALICIOUS_DNS": "M", "TOR_CONNECTION": "T",
        "IOT_LOCAL_SCAN": "I", "IOT_HIGH_UPLOAD": "U",
        "IOT_UNKNOWN_SERVER": "S", "NEW_DEVICE": "N",
    }
    device_rows = ""
    for i, d in enumerate(online_devices):
        name = cfg.get("device_names", {}).get(d.get("mac", ""),
               d.get("hostname") or d.get("vendor", "Nieznane"))
        ip = d.get("ip", "-")
        tag = d.get("tag", "new")
        bg_row = "#f8fafc" if i % 2 == 0 else "#ffffff"
        if tag == "trusted":
            badge = '<span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;">Zaufane</span>'
        else:
            badge = '<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;">Nowe</span>'
        device_rows += (
            f'<tr style="background:{bg_row};">'
            f'<td style="padding:9px 12px;font-size:13px;color:#1e293b;">{name}</td>'
            f'<td style="padding:9px 12px;font-size:12px;color:#475569;font-family:Courier,monospace;">{ip}</td>'
            f'<td style="padding:9px 12px;">{badge}</td></tr>'
        )
    if new_devs_db:
        new_devs_html = '<div style="margin-top:24px;"><div style="font-size:10px;letter-spacing:2px;color:#f59e0b;font-weight:700;font-family:Courier,monospace;margin-bottom:10px;">NOWE URZADZENIA DZISIAJ</div>'
        for e in new_devs_db:
            ts = e.get("timestamp", "")[:16].replace("T", " ")
            new_devs_html += (
                f'<table width="100%" cellpadding="0" cellspacing="0" style="background:#fffbeb;border-left:3px solid #f59e0b;border-radius:0 6px 6px 0;margin-bottom:8px;">'
                f'<tr><td style="padding:10px 14px;font-size:13px;color:#1e293b;">{e.get("description","")}'
                f'<span style="float:right;font-size:11px;color:#94a3b8;font-family:Courier,monospace;">{ts}</span></td></tr></table>'
            )
        new_devs_html += "</div>"
    else:
        new_devs_html = '<div style="margin-top:16px;padding:12px 14px;background:#f0fdf4;border-radius:6px;font-size:13px;color:#166534;">Brak nowych urzadzen dzisiaj</div>'
    if threats_today:
        threats_html = '<div style="margin-top:4px;">'
        for e in threats_today[:20]:
            sev = e.get("severity", "")
            bg_t = "#fff1f2" if sev == "CRITICAL" else "#fffbeb"
            border = "#dc2626" if sev == "CRITICAL" else "#f59e0b"
            icon = icons.get(e.get("type", ""), ".")
            ttype = e.get("type", "").replace("_", " ")
            desc = e.get("description", "")[:120]
            ts = e.get("timestamp", "")[:16].replace("T", " ")
            threats_html += (
                f'<table width="100%" cellpadding="0" cellspacing="0" style="background:{bg_t};border-left:3px solid {border};border-radius:0 6px 6px 0;margin-bottom:8px;">'
                f'<tr><td style="padding:10px 14px;">'
                f'<div style="font-size:12px;font-weight:700;color:#1e293b;margin-bottom:3px;">{icon} {ttype}</div>'
                f'<div style="font-size:12px;color:#475569;">{desc}</div>'
                f'<div style="font-size:11px;color:#94a3b8;margin-top:4px;font-family:Courier,monospace;">{ts}</div>'
                f"</td></tr></table>"
            )
        threats_html += "</div>"
    else:
        threats_html = '<div style="padding:12px 14px;background:#f0fdf4;border-radius:6px;font-size:13px;color:#166534;">Brak zagrozen dzisiaj — siec bezpieczna</div>'
    risk_bg = {"WYSOKIE": "#fee2e2", "SREDNIE": "#fef3c7", "NISKIE": "#dcfce7"}.get(risk.split()[-1], "#f8fafc") if " " in risk else "#f8fafc"
    risk_color = {"WYSOKIE": "#dc2626", "SREDNIE": "#d97706", "NISKIE": "#16a34a"}.get(risk.split()[-1] if " " in risk else risk, "#374151")
    network = cfg.get("network_range", "-")
    risk_display = risk
    html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;">
<tr><td align="center" style="padding:24px 10px;">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
  <tr><td style="background:#0a0e14;border-radius:10px 10px 0 0;padding:22px 24px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td>
        <div style="font-size:10px;letter-spacing:3px;color:#00d4ff;font-weight:700;font-family:Courier,monospace;">NETGUARD AI</div>
        <div style="font-size:18px;color:#f5f2ec;font-weight:700;margin-top:5px;">Raport Dzienny Sieci</div>
        <div style="font-size:12px;color:#4a6080;margin-top:4px;">{date_str} &nbsp;.&nbsp; {network}</div>
      </td>
      <td align="right" style="vertical-align:middle;">
        <div style="background:{risk_bg};color:{risk_color};padding:8px 16px;border-radius:8px;font-size:13px;font-weight:700;text-align:center;white-space:nowrap;">{risk_display}</div>
        <div style="font-size:10px;color:#4a6080;text-align:center;margin-top:4px;">Poziom ryzyka</div>
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="background:#ffffff;padding:20px 24px 0;">
    <table width="100%" cellpadding="0" cellspacing="0">
      <tr>
        <td width="31%" style="background:#eff6ff;border-radius:8px;padding:14px;text-align:center;">
          <div style="font-size:30px;font-weight:700;color:#1d4ed8;">{online_count}</div>
          <div style="font-size:11px;color:#64748b;margin-top:4px;">Urzadzen online</div>
        </td>
        <td width="4%"></td>
        <td width="31%" style="background:#fffbeb;border-radius:8px;padding:14px;text-align:center;">
          <div style="font-size:30px;font-weight:700;color:#d97706;">{len(new_devs_db)}</div>
          <div style="font-size:11px;color:#64748b;margin-top:4px;">Nowych urzadzen</div>
        </td>
        <td width="4%"></td>
        <td width="31%" style="background:#fff1f2;border-radius:8px;padding:14px;text-align:center;">
          <div style="font-size:30px;font-weight:700;color:#dc2626;">{len(threats_today)}</div>
          <div style="font-size:11px;color:#64748b;margin-top:4px;">Zagrozen</div>
        </td>
      </tr>
    </table>
  </td></tr>
  <tr><td style="background:#ffffff;padding:20px 24px 0;">
    <div style="font-size:10px;letter-spacing:2px;color:#3b82f6;font-weight:700;font-family:Courier,monospace;margin-bottom:10px;">URZADZENIA W SIECI ({online_count})</div>
    <table width="100%" cellpadding="0" cellspacing="0" style="border-radius:8px;overflow:hidden;border:1px solid #e2e8f0;">
      <tr style="background:#eff6ff;">
        <th style="padding:9px 12px;text-align:left;font-size:11px;color:#3b82f6;font-weight:700;letter-spacing:1px;">NAZWA</th>
        <th style="padding:9px 12px;text-align:left;font-size:11px;color:#3b82f6;font-weight:700;letter-spacing:1px;">IP</th>
        <th style="padding:9px 12px;text-align:left;font-size:11px;color:#3b82f6;font-weight:700;letter-spacing:1px;">STATUS</th>
      </tr>
      {device_rows}
    </table>
    {new_devs_html}
  </td></tr>
  <tr><td style="background:#ffffff;padding:20px 24px 24px;">
    <div style="font-size:10px;letter-spacing:2px;color:#dc2626;font-weight:700;font-family:Courier,monospace;margin-bottom:10px;">ZAGROZENIA I ZDARZENIA ({len(threats_today)})</div>
    {threats_html}
  </td></tr>
  <tr><td style="background:#0a0e14;border-radius:0 0 10px 10px;padding:14px 24px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-size:11px;color:#4a6080;">NetGuard AI — lokalny monitor sieci</td>
      <td align="right" style="font-size:11px;color:#00d4ff;">netguardhome.pl</td>
    </tr></table>
  </td></tr>
</table>
</td></tr></table>
</body></html>"""
    plain = f"""NetGuard AI — Raport dzienny {date_str}
Urzadzenia online: {online_count}
Nowe urzadzenia:   {len(new_devs_db)}
Zagrozenia:        {len(threats_today)}
Poziom ryzyka:     {risk_display}

URZADZENIA ONLINE:
{chr(10).join(f"  * {cfg.get('device_names', {}).get(d.get('mac',''), d.get('hostname') or d.get('vendor','?'))} ({d.get('ip','?')})" for d in online_devices)}

NOWE URZADZENIA:
{chr(10).join(f"  * {e.get('description','')}" for e in new_devs_db) or "  Brak"}

ZAGROZENIA:
{chr(10).join(f"  [{e.get('severity','')}] {e.get('description','')}" for e in threats_today[:10]) or "  Brak — siec bezpieczna"}
"""
    return html, plain


def build_alert_html(severity: str, title: str, detail: str, cfg: dict) -> tuple:
    now_str = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    network = cfg.get("network_range", "-")
    sev_color = {"CRITICAL": "#dc2626", "HIGH": "#f59e0b"}.get(severity, "#3b82f6")
    sev_label = {"CRITICAL": "KRYTYCZNY", "HIGH": "WYSOKI", "INFO": "INFO"}.get(severity, severity)
    html = f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f0f2f5;">
<tr><td align="center" style="padding:24px 10px;">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
  <tr><td style="background:#0a0e14;border-radius:10px 10px 0 0;padding:20px 24px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td>
        <div style="font-size:10px;letter-spacing:3px;color:#00d4ff;font-weight:700;font-family:Courier,monospace;">NETGUARD AI</div>
        <div style="font-size:17px;color:#f5f2ec;font-weight:700;margin-top:4px;">Alert Bezpieczenstwa Sieci</div>
      </td>
      <td align="right" style="vertical-align:top;">
        <span style="background:{sev_color};color:#fff;padding:5px 14px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:1px;">{sev_label}</span>
      </td>
    </tr></table>
  </td></tr>
  <tr><td style="background:#ffffff;padding:24px 24px 20px;">
    <div style="font-size:17px;font-weight:700;color:#111827;margin-bottom:10px;">{title}</div>
    <div style="font-size:14px;color:#4b5563;line-height:1.7;margin-bottom:22px;">{detail}</div>
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border-radius:8px;border:1px solid #e2e8f0;">
      <tr><td style="padding:14px 18px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-size:10px;color:#94a3b8;font-weight:700;letter-spacing:1px;font-family:Courier,monospace;padding-bottom:8px;">CZAS ZDARZENIA</td>
            <td style="font-size:13px;color:#1e293b;text-align:right;padding-bottom:8px;font-family:Courier,monospace;">{now_str}</td>
          </tr>
          <tr>
            <td style="font-size:10px;color:#94a3b8;font-weight:700;letter-spacing:1px;font-family:Courier,monospace;">MONITOROWANA SIEC</td>
            <td style="font-size:13px;color:#1e293b;text-align:right;font-family:Courier,monospace;">{network}</td>
          </tr>
        </table>
      </td></tr>
    </table>
  </td></tr>
  <tr><td style="background:#0a0e14;border-radius:0 0 10px 10px;padding:13px 24px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td style="font-size:11px;color:#4a6080;">NetGuard AI — lokalny monitor sieci domowej</td>
      <td align="right" style="font-size:11px;color:#4a6080;">netguardhome.pl</td>
    </tr></table>
  </td></tr>
</table>
</td></tr></table>
</body></html>"""
    plain = f"NetGuard AI Alert [{sev_label}]\n\n{title}\n\n{detail}\n\nCzas: {now_str} | Siec: {network}"
    return html, plain
