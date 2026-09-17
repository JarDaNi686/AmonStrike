#!/usr/bin/env python3
"""Debug tool - shows exactly what session returns on each endpoint."""
import sys, json, requests, urllib3
sys.path.insert(0, '.')
urllib3.disable_warnings()

from core.session_manager import SessionManager

sm      = SessionManager()
cookies = sm._grab_from_browser("claude.ai")
print(f"Cookies found: {list(cookies.keys())}")
print(f"Has sessionKey: {'sessionKey' in cookies}")

if not cookies:
    print("\nFAIL: No cookies. Login to claude.ai in Firefox first.")
    sys.exit(1)

s = requests.Session()
s.verify = False
s.cookies.update(cookies)
s.headers.update({
    "User-Agent":       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "X-HackerOne-Handle": "jardani101",
    "Accept":           "application/json",
    "Referer":          "https://claude.ai/",
})

# Test each endpoint and show exactly what we get
endpoints = [
    "https://claude.ai/api/auth/session",
    "https://claude.ai/api/bootstrap",
    "https://claude.ai/api/organizations",
    "https://claude.ai/api/account",
    "https://api.anthropic.com/v1/models",
]

print("\n=== ENDPOINT PROBE ===")
for url in endpoints:
    try:
        r = s.get(url, timeout=10, allow_redirects=False)
        ct = r.headers.get("content-type","")[:30]
        print(f"\n{url}")
        print(f"  Status: {r.status_code} | CT: {ct} | Size: {len(r.content)}b")
        if r.status_code == 200 and "json" in ct:
            try:
                data = r.json()
                print(f"  Data: {json.dumps(data, indent=2)[:500]}")
            except:
                print(f"  Body: {r.text[:200]}")
        elif r.status_code in [301,302]:
            print(f"  Redirect: {r.headers.get('Location','')}")
        else:
            print(f"  Body: {r.text[:150]}")
    except Exception as e:
        print(f"\n{url}")
        print(f"  ERROR: {e}")
