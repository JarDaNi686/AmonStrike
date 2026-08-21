#!/usr/bin/env python3
"""
AmonStrike Diagnostics
Run this when you get zero output to find the exact problem.

Usage: python3 diagnose.py --url https://target.com
"""

import sys
import json
import time as time
import socket
import requests
import urllib3
urllib3.disable_warnings()
sys.path.insert(0, '.')

R="\033[91m"; G="\033[92m"; Y="\033[93m"
C="\033[96m"; W="\033[97m"; D="\033[90m"; X="\033[0m"

def ok(msg):  print(f"  {G}[OK]{X} {msg}")
def fail(msg):print(f"  {R}[FAIL]{X} {msg}")
def warn(msg):print(f"  {Y}[WARN]{X} {msg}")
def info(msg):print(f"  {C}[INFO]{X} {msg}")

def check(label, result, detail=""):
    if result:
        ok(f"{label}{' — ' + detail if detail else ''}")
    else:
        fail(f"{label}{' — ' + detail if detail else ''}")
    return result

def run_diagnostics(url: str, cookies: str = "", headers: str = "{}"):
    print(f"\n{W}{'═'*60}{X}")
    print(f"{W}  AmonStrike Diagnostics — {url}{X}")
    print(f"{W}{'═'*60}{X}\n")

    all_ok = True

    # ─── 1. NETWORK ──────────────────────────────────────────
    print(f"{W}1. Network Connectivity{X}")
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host   = parsed.hostname
    port   = parsed.port or (443 if parsed.scheme == "https" else 80)

    # DNS
    try:
        ip = socket.gethostbyname(host)
        ok(f"DNS resolves: {host} → {ip}")
    except Exception as e:
        fail(f"DNS FAILED: {host} — {e}")
        fail("Cannot continue — host unreachable")
        return

    # TCP
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.close()
        ok(f"TCP port {port} open")
    except Exception as e:
        fail(f"TCP connection to {host}:{port} — {e}")
        all_ok = False

    # ─── 2. HTTP RESPONSE ─────────────────────────────────────
    print(f"\n{W}2. HTTP Response{X}")
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0"

    # Parse cookies
    if cookies:
        for pair in cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                sess.cookies.set(k.strip(), v.strip())

    # Parse headers
    try:
        extra_headers = json.loads(headers)
        sess.headers.update(extra_headers)
    except Exception:
        pass

    try:
        t0 = __import__("time").time()
        r  = sess.get(url, timeout=15, allow_redirects=True)
        ms = (__import__("time").time()-t0)*1000
        ok(f"HTTP {r.status_code} in {ms:.0f}ms — {len(r.text)} bytes")

        # WAF detection
        waf_headers = {
            "cf-ray":         "Cloudflare",
            "x-sucuri-id":    "Sucuri",
            "x-cache":        "Cache/CDN",
            "x-iinfo":        "Incapsula",
            "x-powered-by":   None,
            "server":         None,
        }
        for hdr, waf in waf_headers.items():
            val = r.headers.get(hdr,"")
            if val:
                if waf:
                    warn(f"WAF/CDN detected: {waf} ({hdr}: {val[:40]})")
                else:
                    info(f"Header: {hdr}: {val[:40]}")

        # Status analysis
        if r.status_code == 200:
            ok("Status 200 — target responding normally")
        elif r.status_code == 403:
            warn("Status 403 — Forbidden. WAF or IP block likely.")
            warn("Try: --waf-bypass flag")
            all_ok = False
        elif r.status_code == 401:
            warn("Status 401 — Auth required. Use --cookies or --credentials")
            all_ok = False
        elif r.status_code in [301,302]:
            ok(f"Redirect → {r.headers.get('Location','?')}")
        elif r.status_code == 429:
            warn("Status 429 — Rate limited immediately. Slow down.")
            all_ok = False

        # Content type
        ct = r.headers.get("content-type","")
        info(f"Content-Type: {ct[:60]}")

        # Cloudflare challenge
        if "cf-challenge" in r.text.lower() or "just a moment" in r.text.lower():
            fail("Cloudflare challenge page detected — browser required")
            fail("AmonStrike cannot bypass JS challenges automatically")
            all_ok = False

    except requests.exceptions.SSLError as e:
        warn(f"SSL Error: {e}")
        warn("Try: requests with verify=False (already set in modules)")
    except requests.exceptions.ConnectionError as e:
        fail(f"Connection refused: {e}")
        all_ok = False
    except requests.exceptions.Timeout:
        fail("Timeout after 15s — server too slow or blocking")
        all_ok = False

    # ─── 3. MODULE TEST ───────────────────────────────────────
    print(f"\n{W}3. Module Instantiation{X}")
    test_modules = ["sqli","xss","headers","cookies","cors","csrf"]
    for mod_name in test_modules:
        try:
            mod = __import__(f"modules.{mod_name}", fromlist=[mod_name])
            cls_name = [c for c in dir(mod) if c.endswith("Module") and c != "BaseModule"][0]
            cls      = getattr(mod, cls_name)
            inst     = cls(url=url, timeout=10)
            ok(f"modules.{mod_name} — instantiated OK")
        except Exception as e:
            fail(f"modules.{mod_name} — {e}")
            all_ok = False

    # ─── 4. LIVE MODULE TEST ──────────────────────────────────
    print(f"\n{W}4. Live Module Test (headers module){X}")
    try:
        from modules.headers import HeadersModule
        # Parse cookies
        cookie_dict = {}
        if cookies:
            for pair in cookies.split(";"):
                if "=" in pair:
                    k,v = pair.strip().split("=",1)
                    cookie_dict[k.strip()] = v.strip()

        m      = HeadersModule(url=url, timeout=15, cookies=cookie_dict)
        result = m.run()
        finds  = result.get("findings",[])
        info(f"Headers module: {len(finds)} findings")

        if finds:
            ok(f"Module WORKS — found: {finds[0]['title']}")
        else:
            warn("Headers module ran but found nothing")
            warn("Possible: site has perfect security headers (unlikely)")
            warn("More likely: all requests blocked by WAF")

    except Exception as e:
        fail(f"Headers module error: {e}")
        import traceback
        print(traceback.format_exc())
        all_ok = False

    # ─── 5. LIVE SQLi TEST ────────────────────────────────────
    print(f"\n{W}5. Live SQL Injection Test{X}")
    try:
        test_url = url + ("?id=1'" if "?" not in url else "&id=1'")
        r2 = sess.get(test_url, timeout=10)
        errors = ["mysql","syntax","sql","ora-","pg::","sqlite","error in your sql"]
        found  = [e for e in errors if e in r2.text.lower()]
        if found:
            ok(f"SQLi error visible: {found} — target IS vulnerable")
        elif r2.status_code == 403:
            warn("WAF blocked SQLi payload — try --waf-bypass")
        elif r2.status_code == 200:
            info(f"No SQLi error in response ({len(r2.text)} bytes)")
        info(f"Test URL: {test_url}")
    except Exception as e:
        warn(f"SQLi test error: {e}")

    # ─── 6. SCOPE CHECK ──────────────────────────────────────
    print(f"\n{W}6. Scope Validator Check{X}")
    try:
        from core.scope_validator import ScopeValidator
        sv = ScopeValidator(url)
        result = sv.is_in_scope(url)
        check("Base URL in scope", result, url)
        # Test a subpath
        sub = url + "/api/test"
        result2 = sv.is_in_scope(sub)
        check("Subpath in scope", result2, sub)
    except Exception as e:
        warn(f"Scope validator: {e}")

    # ─── 7. REPORT TEST ──────────────────────────────────────
    print(f"\n{W}7. Report Generation Test{X}")
    try:
        import tempfile, os, time
        from reports.generator import ReportGenerator
        tmp    = tempfile.mkdtemp()
        gen    = ReportGenerator(f"diag_{int(time.time())}", url, tmp)
        gen.add_finding({
            "title":"Test Finding","severity":"HIGH","module":"diag",
            "url":url,"parameter":"test","payload":"test",
            "description":"Diagnostic test finding",
            "evidence":"This is a test","remediation":"Fix it",
            "cve":"CWE-TEST","timestamp":time.strftime("%Y-%m-%dT%H:%M:%S")
        })
        paths = gen.generate_all()
        for fmt, path in paths.items():
            size = os.path.getsize(path) if os.path.exists(path) else 0
            check(f"{fmt.upper()} report", size > 100, f"{size} bytes → {path}")
    except Exception as e:
        fail(f"Report generation: {e}")
        import traceback; print(traceback.format_exc())
        all_ok = False

    # ─── SUMMARY ─────────────────────────────────────────────
    print(f"\n{W}{'═'*60}{X}")
    if all_ok:
        print(f"{G}  ALL CHECKS PASSED{X}")
        print(f"  Run the full scan:")
        print(f"  {C}sudo python3 amonstrike.py --url {url} --mode deep --no-ui{X}")
    else:
        print(f"{R}  ISSUES FOUND — fix the [FAIL] items above{X}")
    print(f"{W}{'═'*60}{X}\n")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--url",     required=True)
    p.add_argument("--cookies", default="")
    p.add_argument("--headers", default="{}")
    args = p.parse_args()
    run_diagnostics(args.url, args.cookies, args.headers)
