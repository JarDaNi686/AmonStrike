#!/usr/bin/env python3
"""
AmonStrike — Browser Session Capture
Grabs session cookies from your logged-in Firefox on Kali.
No manual copy-paste needed.
"""
import os, json, sqlite3, shutil, tempfile, glob
from pathlib import Path

def get_firefox_sessions(domain_filter: str = "") -> dict:
    """Extract cookies from Firefox profiles on Kali."""
    results = {}

    # Firefox profile locations on Kali/Linux
    profiles_base = [
        Path.home() / ".mozilla/firefox",
        Path("/root/.mozilla/firefox"),
    ]

    for base in profiles_base:
        if not base.exists():
            continue
        for profile in base.glob("*.default*"):
            cookies_db = profile / "cookies.sqlite"
            if not cookies_db.exists():
                continue

            # Copy DB (Firefox locks it while open)
            tmp = tempfile.mktemp(suffix=".sqlite")
            shutil.copy2(cookies_db, tmp)

            try:
                con = sqlite3.connect(tmp)
                cur = con.cursor()
                query = "SELECT host, name, value, path, expiry FROM moz_cookies"
                if domain_filter:
                    query += f" WHERE host LIKE '%{domain_filter}%'"
                rows = cur.fetchall()
                con.execute(query)
                rows = con.fetchall()
                con.close()
                for host, name, value, path, expiry in rows:
                    h = host.lstrip(".")
                    results.setdefault(h, {})[name] = value
            except Exception as e:
                pass
            finally:
                os.unlink(tmp)

    return results


def get_chrome_sessions(domain_filter: str = "") -> dict:
    """Extract cookies from Chrome/Chromium on Kali."""
    results = {}
    cookie_paths = [
        Path.home() / ".config/google-chrome/Default/Cookies",
        Path.home() / ".config/chromium/Default/Cookies",
        Path("/root/.config/google-chrome/Default/Cookies"),
    ]
    for cookies_db in cookie_paths:
        if not cookies_db.exists():
            continue
        tmp = tempfile.mktemp(suffix=".sqlite")
        shutil.copy2(cookies_db, tmp)
        try:
            con = sqlite3.connect(tmp)
            query = "SELECT host_key, name, value FROM cookies"
            if domain_filter:
                query += f" WHERE host_key LIKE '%{domain_filter}%'"
            rows = con.execute(query).fetchall()
            con.close()
            for host, name, value in rows:
                results.setdefault(host.lstrip("."), {})[name] = value
        except Exception:
            pass
        finally:
            os.unlink(tmp)
    return results


def capture_session(target_domain: str) -> dict:
    """
    Capture session from any logged-in browser on Kali.
    Returns cookies dict ready for AmonStrike.
    """
    domain = target_domain.replace("https://","").replace("http://","").split("/")[0]
    base   = ".".join(domain.split(".")[-2:])  # e.g. zomato.com

    print(f"[*] Capturing session cookies for {base}...")

    all_cookies = {}
    for browser, fn in [("Firefox", get_firefox_sessions),
                        ("Chrome",  get_chrome_sessions)]:
        cookies = fn(base)
        for host, cookie_dict in cookies.items():
            if base in host:
                all_cookies.update(cookie_dict)
                print(f"  [+] {browser}: {len(cookie_dict)} cookies from {host}")

    if not all_cookies:
        print(f"  [!] No cookies found. Make sure you're logged into {base} in Firefox/Chrome on Kali.")
        return {}

    print(f"  [+] Total: {len(all_cookies)} cookies captured")
    return all_cookies


def get_local_storage(target_domain: str) -> dict:
    """Try to extract localStorage tokens (JWT etc) from browser storage."""
    domain = target_domain.replace("https://","").replace("http://","").split("/")[0]
    storage = {}
    # Firefox localStorage location
    storage_path = Path.home() / ".mozilla/firefox"
    for profile in storage_path.glob("*.default*"):
        ls_dir = profile / "storage/default"
        for d in ls_dir.glob(f"*{domain}*"):
            ls_db = d / "ls/data.sqlite"
            if ls_db.exists():
                try:
                    tmp = tempfile.mktemp(suffix=".sqlite")
                    shutil.copy2(ls_db, tmp)
                    con = sqlite3.connect(tmp)
                    rows = con.execute("SELECT key, utf16_length, value FROM data").fetchall()
                    con.close()
                    os.unlink(tmp)
                    for key, _, value in rows:
                        storage[key] = str(value)[:200]
                except Exception:
                    pass
    return storage


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "zomato.com"
    cookies = capture_session(target)
    if cookies:
        # Print as credentials JSON for terminator
        creds = json.dumps([{"cookies": cookies, "role": "user"}])
        print(f"\n[+] Use with terminator:")
        print(f"sudo python3 terminator.py --target https://{target} --credentials '{creds}'")
        # Also save to file
        out = Path("output/session_cookies.json")
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps({"domain": target, "cookies": cookies}, indent=2))
        print(f"[+] Saved to: {out}")
