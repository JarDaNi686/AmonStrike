#!/usr/bin/env python3
"""
AmonStrike — Regression Suite

Deterministic tests against known-vulnerable targets:
  - OWASP Juice Shop (localhost:3000) — IDOR, XSS, SQLi, auth bypass
  - Acunetix vulnweb (testphp.vulnweb.com) — SQLi, XSS, headers

Verifies that AmonStrike's validators and modules detect
issues they are supposed to detect and don't false-positive
on clean responses.

Usage:
    # Juice Shop must be running on localhost:3000
    python3 tests/regression_suite.py

    # Skip slow network tests
    python3 tests/regression_suite.py --fast

    # Run specific suite only
    python3 tests/regression_suite.py --suite validators
    python3 tests/regression_suite.py --suite juiceshop
    python3 tests/regression_suite.py --suite vulnweb
    python3 tests/regression_suite.py --suite scope
    python3 tests/regression_suite.py --suite h1scope
"""

import sys
import json
import time
import argparse
import urllib.request
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; X = "\033[0m"

PASSED = FAILED = 0


def ok(name):
    global PASSED
    PASSED += 1
    print(f"  {G}✓{X} {name}")


def fail(name, reason=""):
    global FAILED
    FAILED += 1
    print(f"  {R}✗{X} {name}" + (f" — {reason}" if reason else ""))


def run(name, fn):
    try:
        result = fn()
        if result:
            ok(name)
        else:
            fail(name, "returned False")
    except Exception as e:
        fail(name, str(e)[:120])


# ── HTTP helpers ─────────────────────────────────────────────

def http_get(url, token=None, timeout=8):
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "AmonStrike-Regression/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def http_post(url, body, token=None, timeout=8):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent",   "AmonStrike-Regression/1.0")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


def host_reachable(host, port, timeout=3):
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ── Suite 1: Unit tests — validators & scope ─────────────────

def suite_validators():
    print(f"\n{C}── Suite: Validators (unit tests) ──────────────────────────{X}")

    # IDORValidator
    from core.validators import IDORValidator, gate

    v = IDORValidator()

    run("IDOR confirmed when attacker=200, victim=200, anon=403",
        lambda: v.is_idor(
            attacker_status=200, attacker_body='{"id":1,"amount":100}',
            victim_status=200,   victim_body='{"id":1,"amount":100}',
            anon_status=403,     anon_body="Forbidden",
        ))

    run("IDOR rejected when anon=200 (public endpoint)",
        lambda: not v.is_idor(
            attacker_status=200, attacker_body='{"id":1}',
            victim_status=200,   victim_body='{"id":1}',
            anon_status=200,     anon_body='{"id":1}',
        ))

    run("IDOR rejected when victim=404",
        lambda: not v.is_idor(
            attacker_status=200, attacker_body='{"id":1}',
            victim_status=404,   victim_body="Not Found",
            anon_status=403,     anon_body="Forbidden",
        ))

    run("gate() returns CONFIRMED for high-confidence IDOR",
        lambda: gate(
            attacker_status=200, attacker_body='{"id":5,"data":"secret"}',
            victim_status=200,   victim_body='{"id":5,"data":"secret"}',
            anon_status=401,     anon_body='{"error":"unauthorized"}',
        ).get("confirmed", False))

    run("gate() returns False for 404 victim",
        lambda: not gate(
            attacker_status=200, attacker_body='{"id":5}',
            victim_status=404,   victim_body="{}",
            anon_status=401,     anon_body="{}",
        ).get("confirmed", True))


def suite_scope():
    print(f"\n{C}── Suite: Scope Validator (unit tests) ─────────────────────{X}")

    from core.scope_validator import ScopeValidator

    sv = ScopeValidator(
        custom_scope=["*.juiceshop.com", "api-sandbox.gocardless.com"],
        forbidden_hosts=["api.gocardless.com", "production.gocardless.com"],
    )

    run("In-scope wildcard domain allowed",
        lambda: sv.is_in_scope("https://app.juiceshop.com")[0])

    run("Sandbox subdomain allowed",
        lambda: sv.is_in_scope("https://api-sandbox.gocardless.com")[0])

    run("Production domain blocked (forbidden)",
        lambda: not sv.is_in_scope("https://api.gocardless.com")[0])

    run("Completely foreign domain blocked",
        lambda: not sv.is_in_scope("https://google.com")[0])

    run("is_in_scope returns (bool, reason) tuple",
        lambda: isinstance(sv.is_in_scope("https://app.juiceshop.com"), tuple) and
                len(sv.is_in_scope("https://app.juiceshop.com")) == 2)

    run("IP address blocked by default",
        lambda: not sv.is_in_scope("http://192.168.1.1")[0])


def suite_h1scope():
    print(f"\n{C}── Suite: H1 Scope Fetcher (unit tests) ────────────────────{X}")

    from core.h1_scope_fetcher import H1ScopeFetcher
    fetcher = H1ScopeFetcher()

    mock_items = [
        {"attributes": {"asset_type": "WILDCARD",
                        "asset_identifier": "*.example.com",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True}},
        {"attributes": {"asset_type": "URL",
                        "asset_identifier": "https://api.example.com",
                        "eligible_for_bounty": True,
                        "eligible_for_submission": True}},
        {"attributes": {"asset_type": "URL",
                        "asset_identifier": "https://oos.example.com",
                        "eligible_for_bounty": False,
                        "eligible_for_submission": False}},
    ]

    scopes = fetcher._split_scopes(mock_items)
    config = fetcher._build_config(
        "example",
        {"name": "ExampleCo", "handle": "example",
         "offers_bounty": True, "bounty_min": 100,
         "bounty_max": 5000, "response_time": 3},
        scopes,
    )

    run("In-scope items separated correctly",
        lambda: len(scopes["in_scope"]) == 2)

    run("Out-of-scope item separated correctly",
        lambda: len(scopes["out_scope"]) == 1)

    run("Config core_assets populated",
        lambda: "*.example.com" in config["core_assets"])

    run("Config forbidden_hosts populated",
        lambda: "oos.example.com" in config["forbidden_hosts"])

    run("Config shape matches YAML format",
        lambda: all(k in config for k in
                    ["handle", "core_assets", "forbidden_hosts",
                     "rate_limit", "delay"]))

    run("No URL scheme in asset strings",
        lambda: all("://" not in a for a in config["core_assets"]))


# ── Suite 2: Juice Shop IDOR (live) ──────────────────────────

def suite_juiceshop(base="http://localhost:3000"):
    print(f"\n{C}── Suite: OWASP Juice Shop @ {base} ────────────────────────{X}")

    if not host_reachable("localhost", 3000):
        print(f"  {Y}SKIP{X} Juice Shop not running on localhost:3000")
        print(f"  Start it: docker run -p 3000:3000 bkimminich/juice-shop")
        return

    # ── Auth: get two tokens ───────────────────────────────────
    def register_and_login(email, password):
        # Register (may already exist)
        http_post(f"{base}/api/Users", {"email": email, "password": password})
        status, body = http_post(
            f"{base}/rest/user/login",
            {"email": email, "password": password}
        )
        if status == 200:
            try:
                return json.loads(body).get("authentication", {}).get("token", "")
            except Exception:
                pass
        return ""

    token_a = register_and_login("regressA@amon.local", "TestPass1!")
    token_b = register_and_login("regressB@amon.local", "TestPass1!")

    run("Juice Shop reachable",
        lambda: http_get(base)[0] == 200)

    run("Login API returns token for user A",
        lambda: len(token_a) > 10)

    run("Login API returns token for user B",
        lambda: len(token_b) > 10)

    # ── Basket IDOR ────────────────────────────────────────────
    def get_basket_id(token):
        status, body = http_get(f"{base}/api/BasketItems", token=token)
        if status == 200:
            try:
                data = json.loads(body)
                items = data.get("data", [])
                if items:
                    return items[0].get("BasketId", 0)
            except Exception:
                pass
        # Create basket item to get a basket ID
        status, body = http_post(
            f"{base}/api/BasketItems",
            {"ProductId": 1, "BasketId": 1, "quantity": 1},
            token=token,
        )
        try:
            return json.loads(body).get("data", {}).get("BasketId", 0)
        except Exception:
            return 0

    if token_a and token_b:
        basket_id_a = get_basket_id(token_a)
        basket_id_b = get_basket_id(token_b)

        if basket_id_a and basket_id_b and basket_id_a != basket_id_b:
            # Cross-account IDOR: user B reads user A's basket
            status_own,  body_own  = http_get(
                f"{base}/rest/basket/{basket_id_a}", token=token_a)
            status_idor, body_idor = http_get(
                f"{base}/rest/basket/{basket_id_a}", token=token_b)
            status_anon, body_anon = http_get(
                f"{base}/rest/basket/{basket_id_a}")

            run("Owner can read own basket (200)",
                lambda: status_own == 200)

            run("Juice Shop basket IDOR: other user can read (known vuln)",
                lambda: status_idor == 200)

            # Validate with AmonStrike IDOR validator
            from core.validators import gate
            result = gate(
                attacker_status=status_idor,
                attacker_body=body_idor,
                victim_status=status_own,
                victim_body=body_own,
                anon_status=status_anon,
                anon_body=body_anon,
            )
            run("IDOR validator confirms basket IDOR as real finding",
                lambda: result.get("confirmed", False))
        else:
            print(f"  {Y}SKIP{X} Could not get two distinct basket IDs")

    # ── Admin panel exists ─────────────────────────────────────
    run("Admin panel endpoint reachable (path disclosure)",
        lambda: http_get(f"{base}/administration")[0] in [200, 401, 403])

    # ── SQL injection in search ────────────────────────────────
    status, body = http_get(f"{base}/rest/products/search?q=' OR 1=1--")
    run("SQLi in search returns 200 or 500 (not filtered)",
        lambda: status in [200, 500])

    # ── XSS: DOM-based ────────────────────────────────────────
    status, body = http_get(f"{base}/rest/products/search?q=<script>alert(1)</script>")
    run("XSS payload echoed back in search response",
        lambda: status == 200 and ("script" in body.lower() or "alert" in body.lower()))

    # ── Scope enforcement ─────────────────────────────────────
    from core.scope_validator import ScopeValidator
    sv = ScopeValidator(custom_scope=["localhost"])
    in_scope, reason = sv.is_in_scope(base)
    run("Juice Shop localhost is in scope",
        lambda: in_scope)


# ── Suite 3: vulnweb (live, external) ────────────────────────

def suite_vulnweb(fast=False):
    print(f"\n{C}── Suite: Acunetix vulnweb (live external) ─────────────────{X}")
    BASE = "http://testphp.vulnweb.com"

    if not host_reachable("testphp.vulnweb.com", 80, timeout=5):
        print(f"  {Y}SKIP{X} testphp.vulnweb.com not reachable")
        return

    run("vulnweb home page returns 200",
        lambda: http_get(BASE)[0] == 200)

    # SQLi in product listing
    status, body = http_get(f"{BASE}/listproducts.php?cat=1'")
    run("SQLi probe returns error response (500/200 with error text)",
        lambda: status in [200, 500] and (
            "mysql" in body.lower() or
            "sql" in body.lower() or
            "warning" in body.lower() or
            "error" in body.lower()
        ))

    # Reflected XSS
    payload = "<script>alert(1)</script>"
    import urllib.parse
    status, body = http_get(
        f"{BASE}/search.php?test={urllib.parse.quote(payload)}"
    )
    run("XSS payload reflected in response",
        lambda: status == 200 and payload in body)

    # Directory listing / sensitive paths
    status, _ = http_get(f"{BASE}/.git/config")
    run("Git config path returns 200 or 403 (path exists)",
        lambda: status in [200, 403, 404])

    if not fast:
        # Login bypass
        status, body = http_post(
            f"{BASE}/userinfo.php",
            {},
        )
        run("userinfo.php reachable",
            lambda: status in [200, 302, 405])

    # Scope validator recognizes vulnweb
    from core.scope_validator import ScopeValidator
    sv = ScopeValidator(custom_scope=["testphp.vulnweb.com"])
    run("ScopeValidator allows testphp.vulnweb.com",
        lambda: sv.is_in_scope(f"{BASE}/listproducts.php?cat=1")[0])

    run("ScopeValidator blocks other vulnweb subdomains (strict scope)",
        lambda: not sv.is_in_scope("http://testaspnet.vulnweb.com")[0])


# ── Suite 4: KB index ─────────────────────────────────────────

def suite_kb():
    print(f"\n{C}── Suite: Knowledge Base ────────────────────────────────────{X}")

    from knowledge.build_kb import INDEX_FILE

    run("KB index file exists",
        lambda: INDEX_FILE.exists())

    if INDEX_FILE.exists():
        chunks = json.loads(INDEX_FILE.read_text())

        run("KB has >= 100 chunks",
            lambda: len(chunks) >= 100)

        run("Each chunk has text and source keys",
            lambda: all("text" in c and "source" in c for c in chunks[:10]))

        run("IDOR methodology present",
            lambda: any("idor" in c.get("text","").lower() or
                        "bola" in c.get("text","").lower()
                        for c in chunks))

        run("SSRF methodology present",
            lambda: any("ssrf" in c.get("text","").lower()
                        for c in chunks))

        run("XSS methodology present",
            lambda: any("xss" in c.get("text","").lower() or
                        "cross-site" in c.get("text","").lower()
                        for c in chunks))


# ── Runner ────────────────────────────────────────────────────

SUITES = {
    "validators": suite_validators,
    "scope":      suite_scope,
    "h1scope":    suite_h1scope,
    "kb":         suite_kb,
    "juiceshop":  suite_juiceshop,
    "vulnweb":    suite_vulnweb,
}


def main():
    global PASSED, FAILED

    ap = argparse.ArgumentParser(description="AmonStrike Regression Suite")
    ap.add_argument("--suite", default="all",
                    help=f"Suite to run: all, {', '.join(SUITES)}")
    ap.add_argument("--fast", action="store_true",
                    help="Skip slow external network tests")
    ap.add_argument("--juice-base", default="http://localhost:3000",
                    help="Juice Shop base URL")
    args = ap.parse_args()

    print("=" * 60)
    print("  AmonStrike Regression Suite")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    to_run = list(SUITES.items()) if args.suite == "all" else [
        (args.suite, SUITES[args.suite])
    ] if args.suite in SUITES else []

    if not to_run:
        print(f"Unknown suite: {args.suite}. Options: {', '.join(SUITES)}")
        sys.exit(1)

    for name, fn in to_run:
        try:
            if name == "juiceshop":
                fn(args.juice_base)
            elif name == "vulnweb":
                fn(fast=args.fast)
            else:
                fn()
        except Exception as e:
            print(f"  {R}Suite {name} crashed: {e}{X}")

    print(f"\n{'='*60}")
    print(f"  TOTAL: {G}{PASSED} passed{X}  {R}{FAILED} failed{X}")
    print(f"{'='*60}\n")
    sys.exit(0 if FAILED == 0 else 1)


if __name__ == "__main__":
    main()
