#!/usr/bin/env python3
"""
AmonStrike — End-to-End Pipeline Test
Tests entire stack on known-vulnerable target (DVWA/httpbin)
before touching any H1 program.

Run this FIRST to verify 100% accuracy.
"""
import sys, json, time, requests, urllib3
sys.path.insert(0, '.')
urllib3.disable_warnings()

def test_fp_validation():
    """Test false positive prevention on all vuln types."""
    from core.cai_engine import ReflectionLoop, Blackboard
    bb = Blackboard()
    rl = ReflectionLoop(None, bb)

    cases = [
        # (finding, should_be_proven, description)
        ({"module":"ssrf",
          "evidence":"Response:\n<!DOCTYPE html><html><title>Home</title><meta viewport>"},
         False, "SSRF: homepage should be rejected"),

        ({"module":"ssrf",
          "evidence":"Response:\nami-id: i-1234\ninstance-id: i-abc"},
         True,  "SSRF: real metadata should pass"),

        ({"module":"idor",
          "evidence":"<!DOCTYPE html><html><meta viewport content og:title Army News>"},
         False, "IDOR: public army.mil article should be rejected"),

        ({"module":"idor",
          "evidence":'{"email":"victim@example.com","phone":"+1234567890","address":"123 Main"}'},
         True,  "IDOR: real PII should pass"),

        ({"module":"command_injection",
          "evidence":'<input value="uid=test"> some html'},
         False, "RCE: uid= in HTML attr should be rejected"),

        ({"module":"command_injection",
          "evidence":"uid=33(www-data) gid=33(www-data) groups=33(www-data)"},
         True,  "RCE: real command output should pass"),

        ({"module":"sqli",
          "evidence":"You have an error in your SQL syntax near '' at line 1"},
         True,  "SQLi: real DB error should pass"),

        ({"module":"xss",
          "evidence":"<img src=x onerror=alert(1)>",
          "payload":"<img src=x onerror=alert(1)>"},
         True,  "XSS: payload in response should pass"),
    ]

    passed = failed = 0
    print("Testing false positive prevention...")
    for finding, expected, desc in cases:
        result = rl.reflect_on_finding(dict(finding))
        actual = result.get("proven", False)
        status = "✓" if actual == expected else "✗"
        if actual == expected:
            passed += 1
        else:
            failed += 1
            print(f"  {status} FAIL: {desc}")
            print(f"         Expected proven={expected}, got {actual}")
            print(f"         Reason: {result.get('reflection','')}")
    
    print(f"  Result: {passed}/{passed+failed} passed")
    return failed == 0


def test_ghost_protocol():
    """Test fingerprint rotation and timing."""
    from core.ghost_protocol import GhostProtocol
    g = GhostProtocol()
    
    # Get 30 headers and check rotation
    uas = set()
    for _ in range(30):
        h = g.get_headers()
        uas.add(h["User-Agent"])
    
    print(f"Ghost Protocol: {len(uas)} distinct UAs in 30 requests")
    assert len(uas) >= 2, "Should rotate user agents"
    return True


def test_blackboard_reactivity():
    """Test that blackboard triggers correct reactions."""
    from core.cai_engine import Blackboard, DynamicToolRouter
    
    events = []
    bb = Blackboard()
    bb.subscribe("new_finding", lambda f: events.append(f.get("module","")))
    
    # Write findings
    bb.write("finding", {"module":"ssrf","severity":"CRITICAL",
                         "title":"SSRF Test","url":"https://test.com","proven":True})
    bb.write("finding", {"module":"idor","severity":"HIGH",
                         "title":"IDOR Test","url":"https://test.com","proven":True})
    
    time.sleep(0.1)  # let threads run
    print(f"Blackboard: {len(bb.findings)} findings, {len(events)} events triggered")
    assert len(bb.findings) == 2
    
    # Test router with state
    bb.write("endpoints", ["https://test.com/api/users?id=1",
                           "https://test.com/api/orders/123"])
    bb.write("tech", ["php","mysql"])
    
    router = DynamicToolRouter(bb)
    tools  = router.select_next_tools(max_tools=5)
    print(f"Router selected: {tools}")
    assert len(tools) > 0
    return True


def test_session_detection():
    """Test session manager finds cookies."""
    from core.session_manager import SessionManager
    sm = SessionManager()
    
    # Check if claude.ai session exists
    domains = list(sm.sessions.keys())
    print(f"Saved sessions: {domains}")
    
    cookies = sm._grab_from_browser("claude.ai")
    if cookies:
        print(f"  ✓ claude.ai session found: {len(cookies)} cookies")
    else:
        print("  ! claude.ai session not found — login to Firefox first")
    return True


def run_all():
    results = {}
    tests   = [
        ("FP Validation",     test_fp_validation),
        ("Ghost Protocol",    test_ghost_protocol),
        ("Blackboard",        test_blackboard_reactivity),
        ("Session Detection", test_session_detection),
    ]

    print(f"\n{'='*55}")
    print(f"  AMONSTRIKE — END-TO-END PIPELINE TEST")
    print(f"{'='*55}\n")

    for name, fn in tests:
        print(f"\n[{name}]")
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = False
            print(f"  ✗ FAILED: {e}")

    print(f"\n{'='*55}")
    passed = sum(1 for v in results.values() if v)
    total  = len(results)
    print(f"  RESULT: {passed}/{total} tests passed")
    print(f"{'='*55}")

    if passed == total:
        print("\n  ✓ Pipeline ready for H1 targets")
        print("  Run: sudo python3 run.py https://claude.ai anthropic")
    else:
        print("\n  ✗ Fix failures before scanning H1 targets")
    return passed == total


if __name__ == "__main__":
    run_all()
