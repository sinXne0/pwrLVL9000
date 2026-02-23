#!/usr/bin/env python3
"""
# Author: sinX
pwrLVL9000 - Cookie auditor + secret scanner for web targets.
Supports CLI output and web UI (via emit callback for real-time SSE streaming).
"""

import re
import sys
import json
import math
import time
import threading
import argparse
from urllib.parse import urlparse, urljoin
from collections import defaultdict
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Callable

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"[!] Missing dependency: {e}")
    print("[*] Install with:  pip install requests beautifulsoup4")
    sys.exit(1)


# ─── Terminal colours (CLI mode only) ────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"


# ─── Secret patterns ─────────────────────────────────────────────────────────
# Each tuple: (display_name, regex_pattern)

_RAW_PATTERNS = [
    # ── AWS ──────────────────────────────────────────────────────────────────
    ("AWS Access Key ID",      r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    ("AWS Secret Access Key",  r"(?i)aws.{0,30}(?:secret|key).{0,30}['\"]([0-9a-zA-Z/+]{40})['\"]"),
    ("AWS Session Token",      r"(?i)aws.{0,10}session.{0,10}token.{0,10}['\"]([A-Za-z0-9/+=]{100,})['\"]"),
    ("AWS S3 Bucket URL",      r"[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"),
    ("AWS ARN",                r"arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]{12}:[a-zA-Z0-9\-_/:.]+"),
    ("AWS Lambda URL",         r"https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws"),
    # ── Azure ─────────────────────────────────────────────────────────────────
    ("Azure Storage Key",      r"DefaultEndpointsProtocol=https;AccountName=[^;]{1,60};AccountKey=[a-zA-Z0-9+/=]{80,}"),
    ("Azure SAS Token",        r"sv=[0-9-]{4,10}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=[^&]+&st=[^&]+&spr=https&sig=[a-zA-Z0-9%+/=]{40,}"),
    ("Azure Client Secret",    r"(?i)(?:client.secret|clientSecret|AZURE_CLIENT_SECRET)\s*[:=]\s*['\"]?([a-zA-Z0-9~._\-]{30,})['\"]?"),
    ("Azure Blob URL",         r"https://[a-z0-9]+\.blob\.core\.windows\.net/[a-z0-9\-]+/[^\s\"']+"),
    # ── Google / GCP ──────────────────────────────────────────────────────────
    ("Google API Key",         r"AIza[0-9A-Za-z\-_]{35}"),
    ("GCP Service Account",    r'"type"\s*:\s*"service_account"'),
    ("GCP Storage URL",        r"https://storage\.googleapis\.com/[a-z0-9\-_]{3,63}/[^\s\"']+"),
    ("Firebase URL",           r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ("Firebase App Config",    r"apiKey\s*:\s*['\"]AIza[0-9A-Za-z\-_]{35}['\"]"),
    # ── GitHub / GitLab ───────────────────────────────────────────────────────
    ("GitHub PAT",             r"gh[pousr]_[0-9a-zA-Z]{36,}"),
    ("GitHub Fine-grained PAT",r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}"),
    ("GitHub Actions Token",   r"ghs_[a-zA-Z0-9]{36}"),
    ("GitLab PAT",             r"glpat-[a-zA-Z0-9\-_]{20}"),
    ("GitLab CI Token",        r"(?i)CI_JOB_TOKEN\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?"),
    # ── Stripe / Payments ─────────────────────────────────────────────────────
    ("Stripe Secret Key",      r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable Key", r"pk_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("Stripe Restricted Key",  r"rk_(?:live|test)_[0-9a-zA-Z]{24,}"),
    ("Stripe Webhook Secret",  r"whsec_[a-zA-Z0-9]{32,}"),
    ("Braintree Access Token", r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    ("Square Access Token",    r"(?:EAAAENew|EAAAEP|sq0atp|sq0csp)-[a-zA-Z0-9\-_]{22,}"),
    # ── Communication ────────────────────────────────────────────────────────
    ("Slack Token",            r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    ("Slack Webhook",          r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
    ("Discord Webhook",        r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[a-zA-Z0-9\-_]{60,70}"),
    ("Telegram Bot Token",     r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}"),
    ("Twilio Account SID",     r"AC[0-9a-f]{32}"),
    ("Twilio Auth Token",      r"SK[0-9a-fA-F]{32}"),
    ("SendGrid API Key",       r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"),
    ("Mailgun API Key",        r"key-[0-9a-zA-Z]{32}"),
    ("Mailchimp API Key",      r"[0-9a-f]{32}-us[0-9]{1,2}"),
    ("Postmark Server Token",  r"(?i)postmark.{0,20}(?:server|api).?token\s*[:=]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?"),
    # ── Social / OAuth ────────────────────────────────────────────────────────
    ("Facebook Access Token",  r"EAACEdEose0cBA[0-9A-Za-z]+"),
    ("Facebook App Secret",    r"(?i)(?:facebook|fb).{0,20}(?:app.?secret|client.?secret)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"),
    ("Twitter API Key",        r"(?i)(?:twitter|TWITTER).{0,20}(?:api.?key|consumer.?key)\s*[:=]\s*['\"]?([a-zA-Z0-9]{25})['\"]?"),
    ("Twitter Bearer Token",   r"AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%\-_]{80,}"),
    # ── AI / ML ──────────────────────────────────────────────────────────────
    ("OpenAI Key",             r"sk-[a-zA-Z0-9]{48}"),
    ("OpenAI Org Key",         r"sk-proj-[a-zA-Z0-9\-_]{40,}"),
    ("Anthropic Key",          r"sk-ant-api\d{2}-[a-zA-Z0-9\-_]{90,}"),
    ("HuggingFace Token",      r"hf_[a-zA-Z0-9]{37}"),
    # ── DevOps / CI/CD ───────────────────────────────────────────────────────
    ("NPM Token",              r"npm_[a-zA-Z0-9]{36}"),
    ("PyPI Token",             r"pypi-[a-zA-Z0-9]{36,}"),
    ("Heroku API Key",         r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("Docker Hub Token",       r"(?i)(?:dockerhub|docker.hub|DOCKER).{0,20}(?:token|pass|password)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{32,})['\"]?"),
    ("Vercel Token",           r"(?i)vercel.{0,20}token\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{24,})['\"]?"),
    ("Netlify Token",          r"(?i)netlify.{0,20}token\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{40,})['\"]?"),
    # ── Infrastructure ───────────────────────────────────────────────────────
    ("Cloudflare API Key",     r"(?i)cloudflare.{0,20}(?:api.?key|global.?key)\s*[:=]\s*['\"]?([a-f0-9]{37})['\"]?"),
    ("Cloudflare Token",       r"(?i)cloudflare.{0,20}token\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{40})['\"]?"),
    ("DigitalOcean Token",     r"(?i)(?:digitalocean|DO_API).{0,20}token\s*[:=]\s*['\"]?([a-f0-9]{64})['\"]?"),
    ("Cloudinary URL",         r"cloudinary://[0-9]{15}:[a-zA-Z0-9\-_]+@[a-z0-9]+"),
    ("Mapbox Token",           r"pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9]{22,}"),
    # ── Monitoring / Analytics ───────────────────────────────────────────────
    ("Sentry DSN",             r"https://[a-f0-9]{32}(?::[a-f0-9]{32})?@(?:sentry\.io|o[0-9]+\.ingest\.sentry\.io)/[0-9]+"),
    ("New Relic License Key",  r"NRAK-[A-Z0-9]{27}"),
    ("Datadog API Key",        r"(?i)datadog.{0,20}(?:api.?key)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"),
    # ── Database connection strings ───────────────────────────────────────────
    ("MySQL Connection URI",   r"mysql://[a-zA-Z0-9_\-]+:[^@\s]{1,100}@[a-zA-Z0-9.\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+"),
    ("PostgreSQL URI",         r"postgres(?:ql)?://[a-zA-Z0-9_\-]+:[^@\s]{1,100}@[a-zA-Z0-9.\-]+(?::[0-9]+)?/[a-zA-Z0-9_\-]+"),
    ("MongoDB URI",            r"mongodb(?:\+srv)?://[a-zA-Z0-9_\-]+:[^@\s]{1,100}@[a-zA-Z0-9.\-]+"),
    ("Redis URL",              r"redis://(?:[^@\s:]{1,100}@)?[a-zA-Z0-9.\-]+:[0-9]+(?:/[0-9]+)?"),
    ("MSSQL Connection String",r"(?i)(?:Data Source|Server)\s*=\s*[a-zA-Z0-9.\-\\]+;[^;]{0,200}(?:Password|Pwd)\s*=\s*[^;\"']{4,}"),
    ("Elasticsearch URL w/creds",r"https?://[a-zA-Z0-9_\-]+:[^@\s]{4,100}@[a-zA-Z0-9.\-]+:[0-9]+"),
    # ── Keys / Certificates ───────────────────────────────────────────────────
    ("RSA Private Key",        r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    ("EC Private Key",         r"-----BEGIN EC PRIVATE KEY-----"),
    ("OpenSSH Private Key",    r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("PGP Private Key",        r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("Certificate",            r"-----BEGIN CERTIFICATE-----"),
    # ── Auth tokens ───────────────────────────────────────────────────────────
    ("JWT Token",              r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("Bearer Token",           r"(?i)Bearer\s+([a-zA-Z0-9\-_=.]{40,})"),
    ("Basic Auth Header",      r"(?i)Basic\s+([a-zA-Z0-9+/=]{20,})"),
    ("Password in URL",        r"[a-zA-Z]{3,10}://[^\s:@/]{3,40}:[^\s:@/]{3,40}@[a-zA-Z0-9.\-]+"),
    # ── Generic ───────────────────────────────────────────────────────────────
    ("Generic API Key",        r"(?i)(?:api[_\-]?key|api[_\-]?token|access[_\-]?token|app[_\-]?key|app[_\-]?secret)\s*[:=]\s*['\"]?([0-9a-zA-Z\-_]{32,})['\"]?"),
    ("Generic Secret/Password",r"(?i)(?:secret|password|passwd|pwd|pass)\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]"),
    ("Private Key in Env",     r"(?i)(?:PRIVATE_KEY|RSA_KEY|SSL_KEY)\s*=\s*['\"]?[a-zA-Z0-9+/=\-]{40,}['\"]?"),
    ("Webhook URL",            r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot[0-9]+)/[a-zA-Z0-9/_\-]{20,}"),
    ("Internal IP/Credential", r"(?i)(?:host|server|endpoint)\s*[:=]\s*['\"]?(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9.]{4,}['\"]?"),
]

COMPILED_PATTERNS = [(name, re.compile(pat)) for name, pat in _RAW_PATTERNS]

SENSITIVE_RESPONSE_HEADERS = {
    "authorization", "x-auth-token", "x-api-key",
    "x-access-token", "x-secret", "x-token", "x-session-token",
}

SECURITY_HEADERS_MISSING = {
    "strict-transport-security": "Missing HSTS — allows downgrade attacks",
    "x-frame-options": "Missing X-Frame-Options — clickjacking risk",
    "x-content-type-options": "Missing X-Content-Type-Options",
    "content-security-policy": "Missing CSP — XSS amplification risk",
}

# ─── Sensitive file paths to probe ───────────────────────────────────────────

SENSITIVE_PATHS = [
    # Environment / config
    "/.env", "/.env.local", "/.env.development", "/.env.production",
    "/.env.staging", "/.env.test", "/.env.backup", "/.env.bak",
    "/.env.old", "/.env.save", "/.env.orig", "/.env.example",
    "/env", "/env.txt", "/.env.php",
    # Config files
    "/config.php", "/config.php.bak", "/config.php.old", "/config.php~",
    "/config.js", "/config.json", "/config.yml", "/config.yaml", "/config.ini",
    "/configuration.php", "/settings.php", "/settings.py", "/settings.json",
    "/local_settings.py", "/app_settings.json", "/app/config.php",
    "/application/config.php", "/inc/config.php", "/includes/config.php",
    "/inc/db.php", "/includes/db.php", "/db.php", "/database.php",
    # WordPress
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-config.php~", "/wp-config.txt", "/wordpress/wp-config.php",
    "/xmlrpc.php",
    # Database dumps
    "/backup.sql", "/dump.sql", "/database.sql", "/db.sql",
    "/mysql.sql", "/db_backup.sql", "/data.sql", "/backup.sql.gz",
    "/exports/db.sql", "/backups/backup.sql", "/sql/dump.sql",
    # Git / VCS
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
    "/.git/packed-refs", "/.git/FETCH_HEAD", "/.gitignore",
    "/.gitconfig", "/.svn/entries", "/.hg/hgrc",
    # Server config
    "/.htaccess", "/.htpasswd", "/web.config",
    # CI/CD
    "/.travis.yml", "/.circleci/config.yml", "/Jenkinsfile",
    "/.github/workflows/deploy.yml", "/.gitlab-ci.yml",
    # Docker
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
    "/docker-compose.override.yml", "/.dockerenv",
    # Package managers
    "/package.json", "/package-lock.json", "/yarn.lock",
    "/composer.json", "/composer.lock", "/requirements.txt",
    "/Pipfile", "/Gemfile", "/.npmrc", "/.pypirc", "/setup.cfg",
    # Cloud credentials
    "/.aws/credentials", "/.aws/config",
    "/credentials", "/credentials.json", "/service-account.json",
    "/google-credentials.json", "/firebase-adminsdk.json",
    "/gcp-key.json", "/azure-credentials.json",
    # SSH / Keys
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/server.key", "/private.key", "/cert.key", "/ssl.key",
    # API docs (info gathering)
    "/api/swagger.json", "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/swagger-ui.html",
    "/api/docs", "/docs/api.json", "/graphql",
    "/_api/swagger.json", "/v1/swagger.json", "/v2/swagger.json",
    # Admin panels
    "/admin", "/admin.php", "/administrator", "/phpmyadmin",
    "/pma", "/dbadmin", "/adminer.php", "/wp-admin",
    # Debug / monitoring
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
    "/server-status", "/server-info",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
    "/actuator/loggers", "/actuator/httptrace",
    "/metrics", "/_debug", "/debug", "/trace", "/_profiler",
    # Log files
    "/error_log", "/error.log", "/access.log", "/debug.log",
    "/app.log", "/application.log", "/server.log", "/storage/logs/laravel.log",
    "/logs/error.log", "/logs/app.log", "/var/log/nginx/error.log",
    # IDE artifacts
    "/.idea/workspace.xml", "/.idea/dataSources.xml",
    "/.vscode/settings.json", "/.vscode/launch.json",
    "/.DS_Store",
    # Source backups
    "/index.php.bak", "/index.html.bak", "/app.py.bak",
    "/app.js.bak", "/index.bak", "/login.php.bak",
    # Security / well-known
    "/.well-known/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/robots.txt", "/sitemap.xml",
    # Framework-specific
    "/config/database.yml", "/config/database.php",
    "/config/mail.php", "/config/app.php", "/config/secrets.yml",
    "/storage/framework/cache/config.php",
    # Misc
    "/params.xml", "/parameters.yml", "/parameters.yaml",
]

# These content-type fragments indicate a scannable text response
_TEXT_TYPES = ("text/", "application/json", "application/xml",
               "application/javascript", "application/x-yaml", "application/yaml")

# Severity by path pattern
def _path_severity(path: str) -> str:
    path = path.lower()
    if any(x in path for x in (".env", "credentials", "id_rsa", "private.key",
                                "htpasswd", "wp-config", "service-account",
                                "firebase-adminsdk", ".sql", "backup.sql", "dump.sql")):
        return "CRITICAL"
    if any(x in path for x in (".git/config", "config.php", "settings.py",
                                "database.yml", "actuator/env", "actuator/beans",
                                ".travis.yml", ".npmrc", "secrets.yml")):
        return "HIGH"
    if any(x in path for x in ("swagger", "openapi", "graphql", "phpinfo",
                                "actuator", "debug", "composer.json", "package.json",
                                ".dockerenv", "docker-compose")):
        return "MEDIUM"
    return "LOW"


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class CookieFinding:
    name: str
    value: str
    url: str
    secure: bool
    http_only: bool
    same_site: Optional[str]
    domain: Optional[str]
    path: Optional[str]
    expires: Optional[str]
    issues: List[str] = field(default_factory=list)

    def severity(self) -> str:
        if len(self.issues) >= 3:
            return "HIGH"
        if len(self.issues) >= 1:
            return "MEDIUM"
        return "OK"

    def to_dict(self) -> dict:
        return {
            "name": self.name, "value": self.value, "url": self.url,
            "secure": self.secure, "http_only": self.http_only,
            "same_site": self.same_site, "domain": self.domain,
            "path": self.path, "expires": self.expires,
            "issues": self.issues, "severity": self.severity(),
        }


@dataclass
class SecretFinding:
    pattern: str
    url: str
    source: str
    line_num: int
    snippet: str
    entropy: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "pattern": self.pattern, "url": self.url, "source": self.source,
            "line_num": self.line_num, "snippet": self.snippet, "entropy": self.entropy,
        }


@dataclass
class AuthHeaderFinding:
    header: str
    value: str
    url: str

    def to_dict(self) -> dict:
        return {"header": self.header, "value": self.value, "url": self.url}


@dataclass
class ExposedFileFinding:
    path: str
    url: str
    status: int
    size: int
    content_type: str
    preview: str
    severity: str
    secrets_found: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path, "url": self.url, "status": self.status,
            "size": self.size, "content_type": self.content_type,
            "preview": self.preview, "severity": self.severity,
            "secrets_found": self.secrets_found,
        }


# ─── Helpers ──────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def high_entropy_strings(text: str, threshold: float = 4.5, min_len: int = 20):
    for m in re.finditer(r'[A-Za-z0-9+/=_\-]{20,}', text):
        s = m.group(0)
        if len(s) >= min_len:
            e = shannon_entropy(s)
            if e >= threshold:
                yield s, e


def _cookie_has_attr(cookie, attr: str) -> bool:
    try:
        return any(k.lower() == attr.lower() for k in cookie._rest.keys())
    except Exception:
        return cookie.has_nonstandard_attr(attr)


def _cookie_get_attr(cookie, attr: str) -> Optional[str]:
    try:
        for k, v in cookie._rest.items():
            if k.lower() == attr.lower():
                return v if v else attr
    except Exception:
        pass
    return None


def _quick_secret_scan(text: str) -> List[str]:
    """Return list of pattern names that matched — used for file preview."""
    found = []
    for pname, regex in COMPILED_PATTERNS:
        if regex.search(text):
            found.append(pname)
    return found


# ─── Scanner ──────────────────────────────────────────────────────────────────

class pwrLVL9000Scanner:
    def __init__(
        self,
        base_url: str,
        max_pages: int = 50,
        timeout: int = 15,
        verify_ssl: bool = True,
        entropy_threshold: float = 4.5,
        user_agent: str = "Mozilla/5.0 (pwrLVL9000-Scanner/2.0; security-audit)",
        emit: Optional[Callable] = None,
        stop_event=None,
        probe_files: bool = True,
        file_threads: int = 20,
    ):
        self.base_url    = base_url.rstrip("/")
        self.base_host   = urlparse(base_url).netloc
        self.max_pages   = max_pages
        self.timeout     = timeout
        self.verify_ssl  = verify_ssl
        self.entropy_threshold = entropy_threshold
        self._emit_cb    = emit
        self._stop       = stop_event
        self.probe_files = probe_files
        self.file_threads = file_threads

        self.session = requests.Session()
        self.session.headers["User-Agent"] = user_agent

        self.visited:                Set[str]                = set()
        self.queue:                  List[str]               = [self.base_url]
        self.cookie_findings:        List[CookieFinding]     = []
        self.secret_findings:        List[SecretFinding]     = []
        self.auth_header_findings:   List[AuthHeaderFinding] = []
        self.exposed_file_findings:  List[ExposedFileFinding]= []
        self.js_scanned:             Set[str]                = set()

        # Baseline 404 fingerprint (to reduce false positives in file probing)
        self._404_size:     Optional[int] = None
        self._404_fragment: str           = ""

    # ── Event emission ────────────────────────────────────────────────────────

    def _emit(self, payload: dict):
        if self._emit_cb:
            self._emit_cb(payload)

    def _log(self, msg: str, level: str = "info"):
        self._emit({"type": "log", "message": msg, "level": level})
        if not self._emit_cb:
            colors = {
                "info":   f"  {CYAN}→{RESET}",
                "ok":     f"  {GREEN}✓{RESET}",
                "warn":   f"  {YELLOW}!{RESET}",
                "error":  f"  {RED}✗{RESET}",
                "found":  f"  {RED}★{RESET}",
                "secret": f"  {RED}⚠{RESET}",
            }
            print(f"{colors.get(level,'  ')} {msg}")

    def _progress(self):
        self._emit({
            "type": "progress",
            "pages_done":   len(self.visited),
            "pages_queued": len(self.queue),
            "cookies":      len(self.cookie_findings),
            "secrets":      len(self.secret_findings),
            "auth_headers": len(self.auth_header_findings),
        })

    # ── Main crawl loop ───────────────────────────────────────────────────────

    def run(self):
        self._log(f"Target: {self.base_url}", "info")
        self._emit({"type": "scan_start", "url": self.base_url})

        # Baseline 404 fingerprint to avoid false positives
        self._calibrate_404()

        # Sensitive file probing (threaded, runs in parallel with crawl)
        file_thread = None
        if self.probe_files:
            file_thread = threading.Thread(target=self._probe_sensitive_paths, daemon=True)
            file_thread.start()

        # Main crawl
        while self.queue and len(self.visited) < self.max_pages:
            if self._stop and self._stop.is_set():
                self._log("Scan aborted.", "warn")
                break
            url = self.queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            self._scan_page(url)
            self._progress()

        if file_thread:
            file_thread.join(timeout=60)

        self._log(
            f"Done. {len(self.visited)} pages | "
            f"{len(self.cookie_findings)} cookies | "
            f"{len(self.secret_findings)} secrets | "
            f"{len(self.exposed_file_findings)} exposed files",
            "ok",
        )

        if not self._emit_cb:
            self._print_report()

    def _calibrate_404(self):
        """Fetch a known-nonexistent path to fingerprint the 404 response."""
        try:
            r = self.session.get(
                f"{self.base_url}/__wg_canary_{int(time.time())}_notexist__",
                timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True,
            )
            self._404_size = len(r.content)
            self._404_fragment = r.text[:80]
            self._log(f"404 baseline: {self._404_size} bytes", "info")
        except Exception:
            pass

    def _is_404_lookalike(self, resp: requests.Response) -> bool:
        """Return True if response looks like our baseline 404 (false positive)."""
        if self._404_size is None:
            return False
        size_diff = abs(len(resp.content) - self._404_size)
        if size_diff < 50 and self._404_fragment and self._404_fragment in resp.text:
            return True
        return False

    def _scan_page(self, url: str):
        self._log(f"Scanning: {url}", "info")
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=True
            )
        except requests.RequestException as exc:
            self._log(f"Fetch failed: {exc}", "error")
            return

        self._audit_cookies(resp, url)
        self._audit_response_headers(resp, url)

        ct = resp.headers.get("Content-Type", "")

        # Scan any text response for secrets (HTML, JS, JSON, YAML, etc.)
        if any(t in ct for t in _TEXT_TYPES):
            self._scan_content(resp.text, url, source="html")

        if "html" not in ct:
            return

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception:
            return

        # Scan inline <script> blocks
        for tag in soup.find_all("script"):
            if not tag.get("src") and tag.string:
                self._scan_content(tag.string, url, source="inline-script")

        # Scan HTML comments
        from bs4 import Comment
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            self._scan_content(str(comment), url, source="html-comment")

        # External JS files
        for script in soup.find_all("script", src=True):
            js_url = urljoin(url, script["src"])
            if js_url not in self.js_scanned and self._same_origin(js_url):
                self.js_scanned.add(js_url)
                self._scan_js(js_url)

        # Internal link crawling
        for tag in soup.find_all("a", href=True):
            link = urljoin(url, tag["href"]).split("#")[0].split("?")[0]
            if self._same_origin(link) and link not in self.visited and link not in self.queue:
                self.queue.append(link)

        # Scan form hidden inputs for embedded secrets
        for inp in soup.find_all("input", {"type": "hidden"}):
            val = inp.get("value", "")
            if len(val) > 8:
                self._scan_content(val, url, source=f"hidden-input:{inp.get('name','')}", is_single_line=True)

        # Parse robots.txt for hidden paths
        if url.rstrip("/").endswith("/robots.txt"):
            self._parse_robots(resp.text, url)

    def _scan_js(self, url: str):
        self._log(f"JS scan: {url}", "info")
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            self._scan_content(resp.text, url, source=f"js:{url}")
        except requests.RequestException:
            pass

    # ── Sensitive file probing ────────────────────────────────────────────────

    def _probe_sensitive_paths(self):
        self._log(f"Probing {len(SENSITIVE_PATHS)} sensitive paths...", "info")
        sem   = threading.Semaphore(self.file_threads)
        lock  = threading.Lock()

        def probe(path):
            if self._stop and self._stop.is_set():
                return
            full_url = self.base_url.rstrip("/") + path
            with sem:
                try:
                    resp = self.session.get(
                        full_url, timeout=self.timeout, verify=self.verify_ssl,
                        allow_redirects=False,
                    )
                    if resp.status_code != 200:
                        return
                    if len(resp.content) == 0:
                        return
                    if self._is_404_lookalike(resp):
                        return

                    ct      = resp.headers.get("Content-Type", "")
                    preview = resp.text[:600].strip()
                    sev     = _path_severity(path)

                    # Scan content for secrets
                    secrets_in_file: List[str] = []
                    if any(t in ct for t in _TEXT_TYPES) or len(resp.content) < 500_000:
                        secrets_in_file = _quick_secret_scan(resp.text)
                        # Also full secret-scan so findings appear in SECRETS tab
                        self._scan_content(resp.text, full_url, source=f"file:{path}")

                    ef = ExposedFileFinding(
                        path=path,
                        url=full_url,
                        status=resp.status_code,
                        size=len(resp.content),
                        content_type=ct,
                        preview=preview,
                        severity=sev,
                        secrets_found=secrets_in_file,
                    )

                    with lock:
                        self.exposed_file_findings.append(ef)

                    self._emit({"type": "exposed_file", "data": ef.to_dict()})
                    self._log(
                        f"EXPOSED [{sev}] {path} ({len(resp.content)} bytes)"
                        + (f" — secrets: {', '.join(secrets_in_file[:3])}" if secrets_in_file else ""),
                        "secret" if sev in ("CRITICAL", "HIGH") else "found",
                    )

                except requests.RequestException:
                    pass

        workers = [threading.Thread(target=probe, args=(p,), daemon=True)
                   for p in SENSITIVE_PATHS]
        for t in workers:
            t.start()
        for t in workers:
            t.join()

        self._log(
            f"File probe complete. {len(self.exposed_file_findings)} exposed file(s) found.", "ok"
        )

    def _parse_robots(self, text: str, robots_url: str):
        """Queue paths from Disallow: directives in robots.txt."""
        added = 0
        for line in text.splitlines():
            m = re.match(r'(?i)Disallow:\s*(/\S*)', line)
            if m:
                path = m.group(1).split("*")[0].rstrip("/") or "/"
                full = self.base_url.rstrip("/") + path
                if full not in self.visited and full not in self.queue:
                    self.queue.append(full)
                    added += 1
        if added:
            self._log(f"robots.txt: queued {added} disallowed path(s)", "info")

    # ── Cookie audit ─────────────────────────────────────────────────────────

    def _audit_cookies(self, resp: requests.Response, page_url: str):
        for cookie in resp.cookies:
            issues: List[str] = []
            secure    = bool(cookie.secure)
            http_only = _cookie_has_attr(cookie, "HttpOnly")
            ss_raw    = _cookie_get_attr(cookie, "SameSite")
            same_site = ss_raw.lower() if ss_raw else None

            if not secure:
                issues.append("Missing Secure flag — sent over plain HTTP")
            if not http_only:
                issues.append("Missing HttpOnly — accessible via JavaScript (XSS risk)")
            if same_site is None:
                issues.append("Missing SameSite — CSRF vulnerable")
            elif same_site == "none" and not secure:
                issues.append("SameSite=None without Secure is invalid/ignored")
            elif same_site == "none":
                issues.append("SameSite=None — cross-site cookie (verify necessity)")

            finding = CookieFinding(
                name=cookie.name, value=cookie.value, url=page_url,
                secure=secure, http_only=http_only, same_site=same_site,
                domain=cookie.domain, path=cookie.path,
                expires=str(cookie.expires) if cookie.expires else None,
                issues=issues,
            )
            self.cookie_findings.append(finding)
            self._emit({"type": "cookie", "data": finding.to_dict()})
            sev = finding.severity()
            self._log(f"Cookie [{sev}] {cookie.name} — {', '.join(issues) if issues else 'OK'}",
                      "found" if sev == "HIGH" else ("warn" if sev == "MEDIUM" else "ok"))

            if cookie.value:
                self._scan_content(cookie.value, page_url,
                                   source=f"cookie:{cookie.name}", is_single_line=True)

    # ── Response header audit ─────────────────────────────────────────────────

    def _audit_response_headers(self, resp: requests.Response, url: str):
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        # Auth token leaks in response headers
        for hdr, val in resp.headers.items():
            if hdr.lower() in SENSITIVE_RESPONSE_HEADERS:
                finding = AuthHeaderFinding(header=hdr, value=val, url=url)
                self.auth_header_findings.append(finding)
                self._emit({"type": "auth_header", "data": finding.to_dict()})
                self._log(f"Auth header in response: {hdr}: {val}", "found")

        # CORS misconfiguration
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao == "*":
            self._log(f"CORS: Access-Control-Allow-Origin: * — public CORS on {url}", "warn")
        elif acao and acao not in ("null",):
            acac = headers_lower.get("access-control-allow-credentials", "")
            if acac.lower() == "true":
                self._log(f"CORS: credentials=true + ACAO={acao} — possible CORS exploit", "found")

        # Security header gaps (only log on first page to avoid noise)
        if url == self.base_url:
            for h, msg in SECURITY_HEADERS_MISSING.items():
                if h not in headers_lower:
                    self._log(f"Security header: {msg}", "warn")

        # Version disclosure
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            if h in headers_lower and headers_lower[h]:
                self._log(f"Version disclosed — {h}: {headers_lower[h]}", "warn")

    # ── Secret scanning ───────────────────────────────────────────────────────

    def _scan_content(
        self,
        text: str,
        url: str,
        source: str,
        is_single_line: bool = False,
    ):
        lines   = [text] if is_single_line else text.splitlines()
        flagged: Set[int] = set()

        for lineno, line in enumerate(lines, 1):
            for pname, regex in COMPILED_PATTERNS:
                if regex.search(line):
                    sf = SecretFinding(pattern=pname, url=url, source=source,
                                       line_num=lineno, snippet=line.strip())
                    self.secret_findings.append(sf)
                    self._emit({"type": "secret", "data": sf.to_dict()})
                    self._log(f"Secret [{pname}] in {source}:{lineno}", "secret")
                    flagged.add(lineno)

            if lineno not in flagged:
                for _, e in high_entropy_strings(line, self.entropy_threshold):
                    sf = SecretFinding(pattern="High-Entropy String", url=url, source=source,
                                       line_num=lineno, snippet=line.strip(), entropy=round(e, 2))
                    self.secret_findings.append(sf)
                    self._emit({"type": "secret", "data": sf.to_dict()})
                    self._log(f"High-entropy (H={e:.2f}) in {source}:{lineno}", "warn")
                    flagged.add(lineno)
                    break

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _same_origin(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.base_host
        except Exception:
            return False

    # ── JSON report ───────────────────────────────────────────────────────────

    def to_json(self) -> str:
        return json.dumps({
            "target":        self.base_url,
            "pages_scanned": list(self.visited),
            "js_scanned":    list(self.js_scanned),
            "cookies":       [cf.to_dict() for cf in self.cookie_findings],
            "secrets":       [sf.to_dict() for sf in self.secret_findings],
            "auth_headers":  [ah.to_dict() for ah in self.auth_header_findings],
            "exposed_files": [ef.to_dict() for ef in self.exposed_file_findings],
        }, indent=2)

    # ── CLI report ────────────────────────────────────────────────────────────

    def _print_report(self):
        sep = f"{DIM}{'─'*72}{RESET}"
        print(f"\n\n{BOLD}{'═'*72}{RESET}")
        print(f"{BOLD}  SCAN REPORT — {self.base_url}{RESET}")
        print(f"{BOLD}{'═'*72}{RESET}")
        print(f"  Pages: {len(self.visited)} | JS: {len(self.js_scanned)}")
        print(f"  Cookies: {len(self.cookie_findings)} | Secrets: {len(self.secret_findings)}")
        print(f"  Auth Headers: {len(self.auth_header_findings)} | Exposed Files: {len(self.exposed_file_findings)}")

        # Exposed files
        print(f"\n{BOLD}[ EXPOSED FILES ]{RESET}  ({len(self.exposed_file_findings)} found)\n")
        if not self.exposed_file_findings:
            print("  None found.")
        else:
            for ef in self.exposed_file_findings:
                sc = RED if ef.severity == "CRITICAL" else (YELLOW if ef.severity == "HIGH" else CYAN)
                print(f"  {sc}[{ef.severity}]{RESET} {ef.path} ({ef.size} bytes)")
                if ef.secrets_found:
                    print(f"    Secrets: {', '.join(ef.secrets_found)}")

        # Secrets
        print(f"\n{sep}\n{BOLD}[ SECRETS ]{RESET}  ({len(self.secret_findings)} found)\n")
        if not self.secret_findings:
            print("  None detected.")
        else:
            grouped: Dict[str, List] = defaultdict(list)
            for sf in self.secret_findings:
                grouped[sf.pattern].append(sf)
            for pname, items in grouped.items():
                print(f"  {RED}{pname}{RESET}  ({len(items)} hit(s))")
                for item in items[:3]:
                    print(f"    {DIM}{item.source}:{item.line_num}{RESET}  {item.snippet[:100]}")

        # Cookies
        print(f"\n{sep}\n{BOLD}[ COOKIES ]{RESET}  ({len(self.cookie_findings)} found)\n")
        for cf in self.cookie_findings:
            sev = cf.severity()
            sc = RED if sev == "HIGH" else (YELLOW if sev == "MEDIUM" else GREEN)
            print(f"  {BOLD}{cf.name}{RESET} [{sc}{sev}{RESET}]  {cf.url}")
            for issue in cf.issues:
                print(f"    {YELLOW}⚠{RESET} {issue}")

        issues = sum(1 for cf in self.cookie_findings if cf.issues) + \
                 len(self.secret_findings) + len(self.auth_header_findings) + \
                 len([ef for ef in self.exposed_file_findings if ef.severity in ("CRITICAL","HIGH")])
        print(f"\n{BOLD}{'═'*72}{RESET}")
        print(f"  {RED if issues else GREEN}{'[!] ' + str(issues) + ' issue(s) found.' if issues else '[+] Clean.'}{RESET}")
        print(f"{BOLD}{'═'*72}{RESET}\n")


# ─── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="pwrLVL9000 v2.0")
    parser.add_argument("url")
    parser.add_argument("--max-pages",     type=int,   default=50)
    parser.add_argument("--timeout",       type=int,   default=15)
    parser.add_argument("--no-ssl-verify", action="store_true")
    parser.add_argument("--entropy",       type=float, default=4.5)
    parser.add_argument("--no-file-probe", action="store_true")
    parser.add_argument("-o", "--output",  metavar="FILE")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scanner = pwrLVL9000Scanner(
        base_url=url,
        max_pages=args.max_pages,
        timeout=args.timeout,
        verify_ssl=not args.no_ssl_verify,
        entropy_threshold=args.entropy,
        probe_files=not args.no_file_probe,
    )
    scanner.run()

    if args.output:
        with open(args.output, "w") as fh:
            fh.write(scanner.to_json())
        print(f"[+] JSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
