#!/usr/bin/env python3
"""
AmonStrike — One URL in. Everything out.
Chains: 7-layer AI → Ghost Protocol → Surface Discovery →
        58 exploit classes → Cross-account IDOR →
        Burp Scanner → Report → H1 Portal

Usage: sudo python3 run.py https://target.com [program]
"""
import sys, os
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

if len(sys.argv) < 2:
    print("Usage: sudo python3 run.py https://target.com [program]")
    sys.exit(1)

url     = sys.argv[1]
program = sys.argv[2] if len(sys.argv) > 2 else ""

print(f"\n{'='*60}")
print(f"  AMONSTRIKE — AUTONOMOUS PENTEST ENGINE")
print(f"  Target:  {url}")
print(f"  Program: {program or 'none'}")
print(f"{'='*60}")

# Phase 1: 7-layer AI analysis
print("\n[AI] Initializing 7-layer AI engine...")
try:
    from core.ai_engine import AmonStrikeAI
    ai     = AmonStrikeAI()
    status = ai.status()
    print(f"  L1 Classical AI: {status['classical_ai']}")
    print(f"  L2 ML:           {status['ml']}")
    print(f"  L3 Neural Net:   {status['neural_net']}")
    print(f"  L7 AGI:          {status['agi']}")
except Exception as e:
    print(f"  AI engine: {e}")
    ai = None

# Phase 2: Ghost Protocol
print("\n[GHOST] Activating stealth layer...")
try:
    from core.ghost_protocol import GhostProtocol
    ghost = GhostProtocol()
    intel = ghost.mission_briefing(url, [url])
    subs  = intel.get("passive_recon",{}).get("subdomains",[])
    hist  = intel.get("passive_recon",{}).get("historical_urls",[])
    print(f"  Passive OSINT: {len(subs)} subdomains, {len(hist)} historical URLs")
except Exception as e:
    print(f"  Ghost Protocol: {e}")
    intel = {}

# Phase 3: Professional pentest engine
print("\n[PENTEST] Running professional pentest engine...")
try:
    from core.pro_engine import ProPentest
    engine   = ProPentest(url, program)
    results  = engine.run()
    findings = results.get("findings", [])
    app_map  = results.get("map", {})
except Exception as e:
    print(f"  Pro engine: {e}")
    findings = []
    app_map  = {}

# Phase 4: CAI-level deep scan
print("\n[CAI] Running CAI-level autonomous scan...")
try:
    from core.cai_engine import CAIOrchestrator
    cai         = CAIOrchestrator(url, program)
    cai_results = cai.run()
    cai_findings= cai_results.get("confirmed",[])
    findings.extend(cai_findings)
    print(f"  CAI found: {len(cai_findings)} confirmed findings")
except Exception as e:
    print(f"  CAI engine: {e}")

# Phase 5: Cross-account IDOR
print("\n[IDOR] Running automated cross-account tests...")
try:
    from core.api_interceptor import BrowserAPICapture
    from core.session_manager import SessionManager
    import requests, urllib3
    urllib3.disable_warnings()
    sm  = SessionManager()
    c1  = sm._grab_from_browser("claude.ai")
    c2  = sm._grab_from_browser("console.anthropic.com")
    if c1 and c2:
        org_id = app_map.get("org_id","")
        if not org_id:
            s = requests.Session()
            s.verify = False
            s.cookies.update(c1)
            r = s.get("https://claude.ai/api/bootstrap", timeout=10)
            if r.status_code == 200:
                m = r.json().get("account",{}).get("memberships",[])
                if m:
                    org_id = m[0].get("organization",{}).get("uuid","")
        if org_id:
            tester   = BrowserAPICapture(url, org_id, c1, c2)
            idor_f   = tester.run()
            findings.extend(idor_f)
            print(f"  IDOR found: {len(idor_f)} findings")
except Exception as e:
    print(f"  IDOR tester: {e}")

# Phase 6: AI validation
if ai and findings:
    print("\n[AI] Validating all findings through 7-layer AI...")
    validated = []
    for f in findings:
        result = ai.analyze(
            {"body": f.get("evidence",""), "status_code": 200, "headers": {}},
            {"module": f.get("module",""), "payload": f.get("payload","")}
        )
        # Only reject if AI is very confident it is a FP (confidence > 0.8)
        if result.get("is_real", True) or result.get("confidence", 1.0) < 0.8:
            f["ai_confidence"] = result.get("confidence", 0.5)
            f["ai_layers"]     = result.get("layers_used", {})
            validated.append(f)
        else:
            print(f"  [AI REJECTED] {f.get('title','')[:50]} — {result.get('reason','')}")
    findings = validated

    # Chain detection
    chains = ai.chain_findings(findings)
    if chains:
        print(f"\n  [CHAINS] {len(chains)} attack chains found:")
        for c in chains:
            print(f"    {c['name']} → {c['combined_severity']} (~${c.get('bounty_estimate',0):,})")

    # AGI learns from this scan
    ai.learn(findings, url, app_map.get("tech",[]))

# Phase 7: Final report
print(f"\n{'='*60}")
print(f"  FINAL RESULTS")
print(f"{'='*60}")

if not findings:
    print("\n  No findings. Target is well-secured.")
    print(f"  Try: sudo bash dod_expand.sh")
else:
    by_sev = {}
    for f in findings:
        s = f.get("severity","MEDIUM")
        by_sev[s] = by_sev.get(s,0) + 1

    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        if by_sev.get(sev,0):
            print(f"  {sev}: {by_sev[sev]}")

    # Generate H1 portal
    try:
        from urllib.parse import urlparse
        output_dir = Path(f"output/{urlparse(url).netloc}")
        output_dir.mkdir(parents=True, exist_ok=True)
        from reports.hackerone_format import generate_h1_package
        pkg = generate_h1_package(findings, str(output_dir),
                                  program_handle=program, target_url=url)
        if pkg.get("portal"):
            print(f"\n  H1 Portal: {pkg['portal']}")
            print(f"  Open it → read each finding → click Submit")
    except Exception as e:
        print(f"  Report: {e}")

print(f"\n  Done. Output: output/{urlparse(url).netloc}/")
from urllib.parse import urlparse
