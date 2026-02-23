# pwrLVL9000
<img width="1024" height="1536" alt="pwrlvl9000" src="https://github.com/user-attachments/assets/1100e03b-ecd6-4593-9491-9cae3c646d95" />


**Author:** sinX
**Platform:** Kali Linux
**Interface:** Web UI (Flask + SSE) + Discord Webhooks

---

## What it does

pwrLVL9000 is an all-in-one offensive recon tool with a real-time web dashboard. It combines web scanning, database credential bruteforcing, and WiFi handshake capture/cracking into a single browser-based interface with live streaming output and optional Discord webhook exfil.

---

## Modules

### Web Scanner
- Crawls targets for cookies (session tokens, auth cookies, tracking)
- 65+ secret patterns: AWS, Azure, GCP, GitHub, Stripe, Slack, OpenAI, JWT, SSH keys, DB connection strings, crypto keys, and more
- Sensitive file probing — 100+ paths (.env, .git, config files, DB dumps, admin panels, Swagger/GraphQL endpoints, CI/CD secrets, cloud creds)
- Inline `<script>` and HTML comment scanning
- CORS misconfiguration detection
- Security header audit (HSTS, CSP, X-Frame-Options)
- Version disclosure detection (Server / X-Powered-By headers)
- False-positive reduction via 404 fingerprinting
- Shannon entropy analysis for high-entropy strings

### DB Scanner
- Bruteforces MSSQL, MySQL, PostgreSQL, MongoDB, Redis
- 60+ credential pairs per database type
- Deep extraction: password hashes, user tables, sample data, cmdshell (MSSQL), /etc/passwd (MySQL UDF), Redis key dumps
- Custom wordlist support

### WiFi Scanner
- Detects wireless adapters including USB dongles (3-method detection)
- AP scan via `iw dev scan` — **works without monitor mode**
- Monitor mode toggle (MON ON / MON OFF) via airmon-ng
- WPA/WPA2 handshake capture with deauth injection
- Crack with aircrack-ng or hashcat (hc22000 format)

---

## Requirements

```
Python 3.8+
Flask
requests
beautifulsoup4

# WiFi module (Kali pre-installed):
aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng, aircrack-ng)
hcxpcapngtool (optional, for hashcat mode)
hashcat (optional)
iw
```

Install Python deps:
```bash
bash setup.sh
```

---

## Usage

```bash
sudo python3 app.py
# Open http://127.0.0.1:5000
```

> Must run as root for WiFi features. Web scanning works without root.

### Web UI tabs
| Tab | Description |
|-----|-------------|
| COOKIES | Session tokens, auth cookies, trackers |
| SECRETS | API keys, credentials, tokens |
| HEADERS | Security header issues, CORS, version disclosure |
| FILES | Exposed sensitive files (.env, .git, configs, etc.) |
| WIFI | AP scan, monitor mode, handshake capture + crack |
| DB | Database credential bruteforce + data extraction |
| LOOT | Combined DB loot (hashes, tables, shells, keys) |

### Discord Webhooks
Paste a webhook URL into any module's WEBHOOK:// field to get real-time embeds for every finding.

---

## CLI mode

```bash
python3 scanner.py https://target.com
```

---

## Disclaimer

For authorized penetration testing, CTF competitions, and security research only. Do not use against systems you do not have explicit permission to test.
