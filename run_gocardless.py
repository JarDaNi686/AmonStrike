#!/usr/bin/env python3
"""
AmonStrike — GoCardless Sandbox Runner

Legal basis: GoCardless public bug bounty on HackerOne.
  Policy URL: https://hackerone.com/gocardless
  Program says: "do not conduct testing on production environments"
  → Only sandbox hosts are testable (enforced by scope validator + forbidden_hosts).

Target: api-sandbox.gocardless.com + manage-sandbox.gocardless.com

This runner:
  1. Loads gocardless_program.yaml (scope + forbidden_hosts)
  2. Enforces scope: production gocardless.com → BLOCKED
  3. Recon: enumerate accessible endpoints via API
  4. IDOR/BOLA: cross-account object access on payments, mandates, customers
  5. Deterministic validator confirms findings (no LLM decides verdict)
  6. HackerOne report package generated for confirmed findings only

Requirements:
  - GC sandbox API keys (env: GC_SANDBOX_ACCESS_TOKEN_A, GC_SANDBOX_ACCESS_TOKEN_B)
  - Or pass --token-a / --token-b on CLI
  Get a free sandbox key: https://manage-sandbox.gocardless.com

Usage:
  export GC_SANDBOX_ACCESS_TOKEN_A="sandbox-xxxx"
  export GC_SANDBOX_ACCESS_TOKEN_B="sandbox-yyyy"
  python3 run_gocardless.py
"""

import sys, os, json, time, argparse, urllib.request, urllib.error
sys.path.insert(0, ".")

import yaml
from core.scope_validator import ScopeValidator
from core.validators import IDORValidator, gate
from reports.hackerone_format import generate_h1_package

BASE     = "https://api-sandbox.gocardless.com"
MANAGE   = "https://manage-sandbox.gocardless.com"
H1_HANDLE = "jardani101"


def http(method, url, token=None, body=None, extra_headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type",  "application/json")
    req.add_header("GoCardless-Version", "2015-07-06")
    req.add_header("X-HackerOne-Handle", H1_HANDLE)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        return 0, str(e)


def load_config(path="configs/gocardless_program.yaml"):
    with open(path) as f:
        return yaml.safe_load(f)


def build_scope(cfg):
    allowed = cfg.get("core_assets", []) + cfg.get("non_core_assets", [])
    forbidden = cfg.get("forbidden_hosts", [])
    from urllib.parse import urlparse
    hosts = [urlparse("https://" + h).hostname for h in allowed]
    return ScopeValidator(custom_scope=hosts, forbidden_hosts=forbidden)


def list_resources(base, token, resource, max_items=20):
    """Paginate through a GC resource endpoint."""
    items = []
    url   = f"{base}/{resource}?limit=10"
    while url and len(items) < max_items:
        code, body = http("GET", url, token=token)
        if code != 200:
            print(f"  [{code}] GET {resource}")
            break
        data = json.loads(body)
        key  = list(data.keys())[0]        # "payments", "mandates", etc.
        items.extend(data[key])
        meta = data.get("meta", {})
        cur  = meta.get("cursors", {})
        after = cur.get("after")
        url  = f"{base}/{resource}?limit=10&after={after}" if after else None
    return items


def detect_idor(base, scope, token_a, token_b, resource, id_field="id"):
    """
    BOLA/IDOR: token_a tries to access each resource owned by token_b.
    Returns list of raw candidate findings.
    """
    print(f"\n  [Recon] Listing /{resource} for account B...")
    b_items = list_resources(base, token_b, resource)
    if not b_items:
        print(f"  [SKIP] No /{resource} found in account B")
        return []

    findings = []
    print(f"  [Test] Account A token accessing {len(b_items)} account B {resource}...")

    for item in b_items[:5]:        # Test first 5 to stay polite
        obj_id = item.get(id_field)
        if not obj_id:
            continue
        url = f"{base}/{resource}/{obj_id}"
        ok, reason = scope.is_in_scope(url)
        if not ok:
            print(f"    [SCOPE BLOCK] {url}")
            continue

        code, body = http("GET", url, token=token_a)
        print(f"    [{code}] {resource}/{obj_id}")

        if code == 200:
            findings.append({
                "module":    "idor",
                "severity":  "HIGH",
                "url":       url,
                "parameter": f"{resource[:-1]}_id (path)",
                "payload":   obj_id,
                "description": (
                    f"Account A token can access {resource[:-1]} {obj_id} "
                    f"owned by account B. Broken Object Level Authorization "
                    f"on /{resource}/{{id}} endpoint."
                ),
                "evidence":    (
                    f"Request:  GET /{resource}/{obj_id}  "
                    f"Authorization: Bearer <account_A_token>\n"
                    f"Response: HTTP 200"
                ),
                "impact": (
                    f"Any authenticated merchant can read other merchants' "
                    f"{resource[:-1]} objects by guessing/enumerating IDs."
                ),
                "remediation": (
                    f"Enforce merchant-level ownership check on /{resource}/:id. "
                    f"Verify the object belongs to the authenticated account "
                    f"before returning it."
                ),
                "cve":       "CWE-639",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "proven":    False,  # validator sets this
                "_obj_id":   obj_id,
                "_resource": resource,
            })
            time.sleep(cfg.get("delay", 1.0))   # GoCardless rate limit: 2 req/s

    return findings


def validate_idor_findings(findings, token_a, scope):
    """Run deterministic differential validation on all candidates."""

    def owner_of(body_text):
        """Extract account/merchant link from GC API response."""
        try:
            d = json.loads(body_text)
            # GC embeds 'links': {'creditor': 'CR...', ...}
            # We use the URL itself as proxy — if account A reads it -> IDOR
            # Real ownership check: compare 'links.creditor' across accounts
            links = None
            for key in d:
                obj = d[key]
                if isinstance(obj, dict) and "links" in obj:
                    links = obj["links"]
                    break
            if links:
                # Return any account-identifying link value as owner
                for k in ["creditor", "customer", "mandate", "creditor_bank_account"]:
                    if k in links:
                        return links[k]
        except Exception:
            pass
        return None

    idv     = IDORValidator(owner_of)
    results = []

    for f in findings:
        url = f["url"]
        ok, reason = scope.is_in_scope(url)
        if not ok:
            continue

        verdict = idv.validate(url, attacker_token=token_a, attacker_principal="__attacker__")
        print(f"  {verdict}")
        f = gate(f, verdict)
        if f["reportable"]:
            results.append(f)

    return results


def main():
    global cfg
    ap = argparse.ArgumentParser()
    ap.add_argument("--token-a", default=os.environ.get("GC_SANDBOX_ACCESS_TOKEN_A"))
    ap.add_argument("--token-b", default=os.environ.get("GC_SANDBOX_ACCESS_TOKEN_B"))
    ap.add_argument("--config",  default="configs/gocardless_program.yaml")
    ap.add_argument("--out",     default="output/gocardless")
    args = ap.parse_args()

    cfg = load_config(args.config)

    print("=" * 60)
    print("  AmonStrike — GoCardless Sandbox")
    print(f"  Target: {BASE}")
    print("=" * 60)

    # ── Scope enforcement ────────────────────────────────────────────
    scope = build_scope(cfg)

    # Prove production is blocked
    prod = "https://api.gocardless.com/payments"
    ok, reason = scope.is_in_scope(prod)
    print(f"\n[Scope] {prod}")
    print(f"        → {'ALLOWED' if ok else 'BLOCKED'} ({reason})")

    sandbox = f"{BASE}/payments"
    ok, reason = scope.is_in_scope(sandbox)
    print(f"[Scope] {sandbox}")
    print(f"        → {'ALLOWED' if ok else 'BLOCKED'} ({reason})")

    if not args.token_a or not args.token_b:
        print("""
[!] No tokens provided. Set environment variables:

    export GC_SANDBOX_ACCESS_TOKEN_A="sandbox-xxxx..."
    export GC_SANDBOX_ACCESS_TOKEN_B="sandbox-yyyy..."

Or get a free sandbox account at: https://manage-sandbox.gocardless.com
Then pass --token-a / --token-b.

Exiting (scope test above still proves enforcement works).
""")
        return

    # ── Verify auth ──────────────────────────────────────────────────
    print("\n[Auth] Checking sandbox tokens...")
    for label, tok in [("A", args.token_a), ("B", args.token_b)]:
        code, body = http("GET", f"{BASE}/creditors", token=tok)
        if code == 200:
            creditors = json.loads(body).get("creditors", [])
            name = creditors[0].get("name", "?") if creditors else "?"
            print(f"  Token {label}: OK — creditor: {name}")
        else:
            print(f"  [!] Token {label}: HTTP {code} — {body[:120]}")
            sys.exit(1)

    # ── IDOR detection across key resource types ─────────────────────
    print("\n[Test] BOLA/IDOR sweep (account A token vs account B objects)...")
    all_candidates = []
    for resource in ["payments", "mandates", "customers", "creditors"]:
        candidates = detect_idor(BASE, scope, args.token_a, args.token_b, resource)
        all_candidates.extend(candidates)

    print(f"\n[Detect] Candidates: {len(all_candidates)}")
    if not all_candidates:
        print("  No 200 cross-account responses. Access control looks correct.")
        return

    # ── Deterministic validation ─────────────────────────────────────
    print("\n[Validate] Differential IDOR test (confirmed = auth 200 + anon 4xx)...")
    confirmed = validate_idor_findings(all_candidates, args.token_a, scope)

    print(f"\n[Result] Confirmed: {len(confirmed)} / {len(all_candidates)} candidates")
    if not confirmed:
        print("  Nothing confirmed. Either patched or public data (anon accessible).")
        return

    # ── Report ───────────────────────────────────────────────────────
    pkg = generate_h1_package(
        confirmed, args.out,
        program_handle="gocardless",
        target_url=BASE,
    )
    print("\n[Report] HackerOne package:")
    for k, v in pkg.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
