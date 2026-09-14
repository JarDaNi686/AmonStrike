"""
AmonStrike — Browser Session Capture
Grabs cookies from logged-in Firefox/Chrome on Kali.
"""
import os, json, sqlite3, shutil, tempfile, glob, subprocess
from pathlib import Path


def find_firefox_profiles() -> list:
    """Find all Firefox profile directories on Kali."""
    paths = []
    
    # Common locations
    search_dirs = [
        Path.home() / ".mozilla/firefox",
        Path("/root/.mozilla/firefox"),
        Path("/home") ,
    ]
    
    # Also search all home directories
    try:
        for user_home in Path("/home").iterdir():
            search_dirs.append(user_home / ".mozilla/firefox")
    except Exception:
        pass
    
    for base in search_dirs:
        if not base.exists():
            continue
        # Find profile directories
        for pattern in ["*.default*", "*.esr", "*release*"]:
            for profile in base.glob(pattern):
                cookies_db = profile / "cookies.sqlite"
                if cookies_db.exists():
                    paths.append(cookies_db)
    
    return paths


def read_firefox_cookies(domain_filter: str = "") -> dict:
    """Read cookies from all Firefox profiles."""
    results = {}
    
    profile_dbs = find_firefox_profiles()
    
    if not profile_dbs:
        # Try finding with find command
        try:
            out = subprocess.run(
                ["find", "/", "-name", "cookies.sqlite", 
                 "-path", "*/firefox/*", "-not", "-path", "*/snap/*"],
                capture_output=True, text=True, timeout=10
            ).stdout
            for line in out.strip().splitlines():
                p = Path(line.strip())
                if p.exists():
                    profile_dbs.append(p)
        except Exception:
            pass
    
    for cookies_db in profile_dbs:
        tmp = tempfile.mktemp(suffix=".sqlite")
        try:
            shutil.copy2(str(cookies_db), tmp)
            con = sqlite3.connect(tmp)
            
            if domain_filter:
                base = domain_filter.replace("https://","").replace("http://","")
                base = ".".join(base.split(".")[-2:])
                rows = con.execute(
                    "SELECT host, name, value FROM moz_cookies WHERE host LIKE ?",
                    (f"%{base}%",)
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT host, name, value FROM moz_cookies"
                ).fetchall()
            
            con.close()
            
            for host, name, value in rows:
                h = host.lstrip(".")
                results.setdefault(h, {})[name] = value
                
        except Exception as e:
            pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
    
    return results


def capture_session(target_domain: str) -> dict:
    """
    Capture session cookies for a domain.
    Returns flat cookie dict ready for requests.
    """
    domain = target_domain.replace("https://","").replace("http://","").split("/")[0]
    base   = ".".join(domain.split(".")[-2:])
    
    print(f"[*] Capturing session cookies for {base}...")
    
    # Try Firefox
    all_cookies = {}
    ff_cookies  = read_firefox_cookies(base)
    
    for host, cookie_dict in ff_cookies.items():
        if base in host:
            all_cookies.update(cookie_dict)
    
    if all_cookies:
        print(f"  [+] Firefox: {len(all_cookies)} cookies from {base}")
        return all_cookies
    
    # Try Chrome/Chromium
    chrome_paths = [
        Path.home() / ".config/google-chrome/Default/Cookies",
        Path.home() / ".config/chromium/Default/Cookies",
        Path("/root/.config/google-chrome/Default/Cookies"),
        Path("/root/.config/chromium/Default/Cookies"),
    ]
    
    for cookie_path in chrome_paths:
        if not cookie_path.exists():
            continue
        tmp = tempfile.mktemp(suffix=".sqlite")
        try:
            shutil.copy2(str(cookie_path), tmp)
            con = sqlite3.connect(tmp)
            rows = con.execute(
                "SELECT host_key, name, value FROM cookies WHERE host_key LIKE ?",
                (f"%{base}%",)
            ).fetchall()
            con.close()
            for host, name, value in rows:
                all_cookies[name] = value
            if all_cookies:
                print(f"  [+] Chrome: {len(all_cookies)} cookies")
                return all_cookies
        except Exception:
            pass
        finally:
            try: os.unlink(tmp)
            except: pass
    
    # Last resort: ask user to paste cookies manually
    print(f"  [!] Could not find {base} cookies automatically")
    print(f"\n  Manual method:")
    print(f"  1. Open Firefox → F12 → Network tab")
    print(f"  2. Refresh claude.ai page")  
    print(f"  3. Click any request → Headers → copy 'Cookie:' value")
    print(f"  4. Run: python3 anthropic_scan.py --cookies 'PASTE_HERE'")
    
    return {}


def list_all_domains() -> list:
    """List all domains that have cookies in Firefox."""
    cookies = read_firefox_cookies()
    domains = set()
    for host in cookies:
        h = host.lstrip(".")
        parts = h.split(".")
        if len(parts) >= 2:
            domains.add(".".join(parts[-2:]))
    return sorted(domains)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "list":
        print("Domains with cookies in Firefox:")
        for d in list_all_domains():
            print(f"  {d}")
    elif len(sys.argv) > 1:
        domain = sys.argv[1]
        cookies = capture_session(domain)
        if cookies:
            print(f"\n[+] Cookies for {domain}:")
            for k, v in list(cookies.items())[:10]:
                print(f"  {k}: {v[:40]}...")
            print(f"\n[+] Use with scanner:")
            print(f"  sudo python3 anthropic_scan.py --session-a '{json.dumps(cookies)}'")
    else:
        print("Usage:")
        print("  python3 core/browser_session.py claude.ai")
        print("  python3 core/browser_session.py list")
