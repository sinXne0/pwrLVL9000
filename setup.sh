#!/usr/bin/env bash
set -e
echo "[*] Installing pwrLVL9000 dependencies..."
pip install requests beautifulsoup4 flask --quiet
echo ""
echo "[+] Done."
echo "[*] Start the web UI:  python3 app.py"
echo "[*] CLI mode:          python3 scanner.py https://target.com"
