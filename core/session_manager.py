"""
AmonStrike — Session Manager
Automatically finds, manages, and validates sessions.
No manual cookie handling needed.
"""
import os, json, sqlite3, shutil, tempfile, time, subprocess
from pathlib import Path
from urllib.parse import urlparse

SESSIONS_FILE = Path.home() / ".amonstrike" / "sessions.json"


class SessionManager:
    """
    Automatically handles sessions for any target.
    1. Checks saved sessions
    2. Grabs from browser if not saved
    3. Validates session is still alive
    4. Alerts if missing + shows how to login
    """

    def __init__(self):
        self.sessions = self._load()

    def get(self, domain: str, role: str = "user") -> dict:
        """Get valid session for domain. Auto-grabs from browser."""
        base = self._base_domain(domain)
        key  = f"{base}_{role}"

        # Check saved sessions
        saved = self.sessions.get(key, {})
        if saved and self._is_alive(base, saved.get("cookies", {})):
            return saved["cookies"]

        # Try browser
        cookies = self._grab_from_browser(base)
        if cookies and self._is_alive(base, cookies):
            self._save(key, base, cookies, role)
            return cookies

        # Alert and guide user
        self._alert_missing(base, role)
        return {}

    def get_multi(self, domain: str, count: int = 2) -> list:
        """Get multiple sessions (for IDOR testing)."""
        base     = self._base_domain(domain)
        sessions = []

        # Check all saved sessions for this domain
        for key, data in self.sessions.items():
            if base in key and self._is_alive(base, data.get("cookies",{})):
                sessions.append(data["cookies"])
                if len(sessions) >= count:
                    return sessions

        # Try all Firefox profiles
        for cookies in self._grab_all_profiles(base):
            if cookies and self._is_alive(base, cookies):
                if cookies not in sessions:
                    sessions.append(cookies)
                if len(sessions) >= count:
                    return sessions

        # Alert about how many are missing
        have = len(sessions)
        need = count - have
        if need > 0:
            print(f"\n{'='*55}")
            print(f"  [SESSION] Need {count} accounts for {base}")
            print(f"  [SESSION] Found: {have} | Missing: {need}")
            print(f"\n  To add account {have+1}:")
            print(f"  1. Open new Firefox profile:")
            print(f"     firefox --no-remote --profile /tmp/ff_account{have+1} &")
            print(f"  2. Login to {base}")
            print(f"  3. Run again — session auto-detected")
            print(f"{'='*55}\n")

        return sessions

    def save_manual(self, domain: str, cookies: dict, role: str = "user"):
        """Manually save a session."""
        base = self._base_domain(domain)
        key  = f"{base}_{role}"
        self._save(key, base, cookies, role)
        print(f"  [+] Session saved for {base} ({role})")

    def _grab_from_browser(self, domain: str) -> dict:
        """Grab cookies from any browser on system."""
        cookies = {}

        # Firefox — search all profiles
        for db_path in self._find_firefox_dbs():
            tmp = tempfile.mktemp(suffix=".sqlite")
            try:
                shutil.copy2(db_path, tmp)
                con = sqlite3.connect(tmp)
                rows = con.execute(
                    "SELECT name, value FROM moz_cookies WHERE host LIKE ?",
                    (f"%{domain}%",)
                ).fetchall()
                con.close()
                for name, value in rows:
                    cookies[name] = value
                if cookies:
                    return cookies
            except Exception:
                pass
            finally:
                try: os.unlink(tmp)
                except: pass

        # Chrome/Chromium
        for db_path in self._find_chrome_dbs():
            tmp = tempfile.mktemp(suffix=".sqlite")
            try:
                shutil.copy2(db_path, tmp)
                con = sqlite3.connect(tmp)
                rows = con.execute(
                    "SELECT name, value FROM cookies WHERE host_key LIKE ?",
                    (f"%{domain}%",)
                ).fetchall()
                con.close()
                for name, value in rows:
                    cookies[name] = value
                if cookies:
                    return cookies
            except Exception:
                pass
            finally:
                try: os.unlink(tmp)
                except: pass

        return cookies

    def _grab_all_profiles(self, domain: str) -> list:
        """Grab sessions from ALL Firefox profiles."""
        all_sessions = []
        seen = set()

        for db_path in self._find_firefox_dbs():
            tmp = tempfile.mktemp(suffix=".sqlite")
            try:
                shutil.copy2(db_path, tmp)
                con = sqlite3.connect(tmp)
                rows = con.execute(
                    "SELECT name, value FROM moz_cookies WHERE host LIKE ?",
                    (f"%{domain}%",)
                ).fetchall()
                con.close()
                if rows:
                    cookies = {name: value for name, value in rows}
                    # Use session key as uniqueness check
                    session_key = cookies.get("sessionKey","") or \
                                 cookies.get("session","") or \
                                 cookies.get("PHPSESSID","") or \
                                 str(hash(str(sorted(cookies.items()))))
                    if session_key not in seen:
                        seen.add(session_key)
                        all_sessions.append(cookies)
            except Exception:
                pass
            finally:
                try: os.unlink(tmp)
                except: pass

        return all_sessions

    def _find_firefox_dbs(self) -> list:
        """Find all Firefox cookie databases on system."""
        dbs = []
        search_bases = [
            Path.home() / ".mozilla/firefox",
            Path("/root/.mozilla/firefox"),
        ]
        try:
            for h in Path("/home").iterdir():
                search_bases.append(h / ".mozilla/firefox")
        except Exception:
            pass

        # Also check /tmp for additional profiles (cookies.sqlite only)
        try:
            for d in Path("/tmp").iterdir():
                if d.is_dir():
                    db = d / "cookies.sqlite"
                    if db.exists() and db.stat().st_size > 0:
                        dbs.append(db)
        except Exception:
            pass

        for base in search_bases:
            if not base.exists():
                continue
            for profile in base.iterdir():
                if not profile.is_dir():
                    continue
                db = profile / "cookies.sqlite"
                if db.exists():
                    dbs.append(db)

        return dbs

    def _find_chrome_dbs(self) -> list:
        dbs = []
        for p in [
            Path.home() / ".config/google-chrome/Default/Cookies",
            Path.home() / ".config/chromium/Default/Cookies",
            Path("/root/.config/google-chrome/Default/Cookies"),
        ]:
            if p.exists():
                dbs.append(p)
        return dbs

    def _is_alive(self, domain: str, cookies: dict) -> bool:
        """Check if session is still valid."""
        if not cookies:
            return False
        try:
            import requests, urllib3
            urllib3.disable_warnings()
            s = requests.Session()
            s.verify = False
            s.cookies.update(cookies)
            s.headers["User-Agent"] = "Mozilla/5.0"

            # Domain-specific validation
            check_urls = {
                "claude.ai":              "https://claude.ai/api/auth/session",
                "anthropic.com":          "https://console.anthropic.com/api/auth/session",
                "console.anthropic.com":  "https://console.anthropic.com/api/auth/session",
                "api.anthropic.com":      "https://api.anthropic.com/v1/models",
                "zomato.com":             "https://www.zomato.com/webroutes/user/info",
                "army.mil":               "https://www.army.mil",
            }
            url = check_urls.get(domain, f"https://{domain}")
            r   = s.get(url, timeout=8)
            return r.status_code not in [401, 403, 302]
        except Exception:
            return len(cookies) > 0  # Assume valid if can't check

    def _alert_missing(self, domain: str, role: str):
        """Clear terminal alert about missing session."""
        print(f"""
{'='*55}
  ⚠️  SESSION REQUIRED: {domain}

  No valid {role} session found for {domain}.

  To fix:
  1. Open Firefox
  2. Login to {domain}
  3. Run scanner again — session auto-detected

  For second account (IDOR testing):
     mkdir -p /tmp/ff_account2 && firefox --no-remote --profile /tmp/ff_account2 &
     Login with second account
     Run scanner again

  Manual cookie method:
     F12 → Application → Cookies → Copy all values
     sudo python3 run.py {domain} --cookies '{{"name":"value"}}'
{'='*55}
""")

    def _base_domain(self, domain: str) -> str:
        domain = domain.replace("https://","").replace("http://","").split("/")[0]
        parts  = domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain

    def _load(self) -> dict:
        try:
            return json.loads(SESSIONS_FILE.read_text())
        except Exception:
            return {}

    def _save(self, key: str, domain: str, cookies: dict, role: str):
        self.sessions[key] = {
            "domain":  domain,
            "role":    role,
            "cookies": cookies,
            "saved":   time.time(),
        }
        SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
        SESSIONS_FILE.write_text(json.dumps(self.sessions, indent=2))
