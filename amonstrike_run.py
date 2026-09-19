#!/usr/bin/env python3
"""
AmonStrike — Master Runner

One command, full pipeline:
  1. Scope enforcement (ScopeValidator)
  2. Recon (subfinder→dnsx→naabu→httpx→katana→nuclei)
  3. KB-augmented vulnerability planning (OWASP/PATT methodology)
  4. IDOR/BOLA differential testing (IDORValidator)
  5. HackerOne report package (confirmed findings only)

Usage:
  # GoCardless sandbox (authorized target):
  python3 amonstrike_run.py --config configs/gocardless_program.yaml \\
    --token-a sandbox-xxx --token-b sandbox-yyy

  # OWASP Juice Shop (self-owned lab):
  python3 amonstrike_run.py --target http://localhost:3000

  # Recon only (any in-scope domain):
  python3 amonstrike_run.py --config configs/gocardless_program.yaml --recon-only
"""

import sys, os, json, argparse, time
from pathlib import Path
sys.path.insert(0, ".")


def banner(target):
    print("=" * 60)
    print("  AmonStrike — Automated Bug Bounty Engine")
    print(f"  Target : {target}")
    print(f"  Time   : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


def load_config(path):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def build_scope(cfg=None, target=None):
    from core.scope_validator import ScopeValidator
    from urllib.parse import urlparse

    if cfg:
        allowed  = cfg.get("core_assets", []) + cfg.get("non_core_assets", [])
        forbidden = cfg.get("forbidden_hosts", [])
        hosts = [urlparse("https://" + h).hostname for h in allowed]
        return ScopeValidator(custom_scope=hosts, forbidden_hosts=forbidden)
    elif target:
        host = urlparse(target).hostname
        return ScopeValidator(custom_scope=[host])
    else:
        raise ValueError("Need --config or --target")


def run_recon(domain, out_dir, scope, config_path=None):
    from recon.pipeline import run_pipeline, TOOLS
    steps = TOOLS  # all steps; pipeline skips missing tools gracefully
    return run_pipeline(domain, Path(out_dir) / "recon", steps, scope)


def run_idor_sweep(base_url, scope, token_a, token_b, out_dir, cfg=None):
    """Cross-account IDOR sweep with deterministic validation."""
    import urllib.request, urllib.error
    from core.validators import IDORValidator, gate
    from reports.hackerone_format import generate_h1_package

    delay = (cfg or {}).get("delay", 0.5)

    def http(method, url, token=None, body=None):
        import json as _json
        data = _json.dumps(body).encode() if body is not None else None
        req  = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()
        except Exception as e:
            return 0, str(e)

    # Juice Shop basket IDOR
    if "localhost" in base_url or "3000" in base_url:
        from run_juiceshop import detect_basket_idor
        findings = detect_basket_idor(base_url, scope, token_a,
                                      "attacker@wearehackerone.com")
    else:
        # Generic REST API IDOR sweep
        from run_gocardless import detect_idor, validate_idor_findings
        findings = []
        for resource in ["payments", "mandates", "customers", "subscriptions"]:
            candidates = detect_idor(base_url, scope, token_a, token_b, resource)
            findings.extend(candidates)
        findings = validate_idor_findings(findings, token_a, scope)

    if not findings:
        print("\n[IDOR] No confirmed findings.")
        return []

    # Generate report
    program = (cfg or {}).get("handle", "lab")
    pkg = generate_h1_package(findings, out_dir, program_handle=program,
                              target_url=base_url)
    print("\n[Report] HackerOne package:")
    for k, v in pkg.items():
        print(f"  {k}: {v}")
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config",     default=None, help="Program YAML (e.g. configs/gocardless_program.yaml)")
    ap.add_argument("--target",     default=None, help="Target URL (lab mode, e.g. http://localhost:3000)")
    ap.add_argument("--token-a",    default=os.environ.get("TOKEN_A"), help="Auth token account A")
    ap.add_argument("--token-b",    default=os.environ.get("TOKEN_B"), help="Auth token account B")
    ap.add_argument("--out",        default="output/run", help="Output directory")
    ap.add_argument("--recon-only", action="store_true", help="Recon only, skip exploitation")
    ap.add_argument("--idor-only",  action="store_true", help="IDOR sweep only, skip recon")
    args = ap.parse_args()

    if not args.config and not args.target:
        ap.error("Provide --config (program) or --target (lab)")

    cfg    = load_config(args.config) if args.config else None
    scope  = build_scope(cfg=cfg, target=args.target)

    # Determine primary domain
    if cfg:
        assets = cfg.get("core_assets", [])
        domain = assets[0] if assets else None
        base   = f"https://{domain}" if domain else None
    else:
        from urllib.parse import urlparse
        base   = args.target
        domain = urlparse(base).hostname

    banner(base or domain)

    # Scope proof
    ok, reason = scope.is_in_scope(base or f"https://{domain}")
    print(f"\n[Scope] {domain} → {'ALLOWED' if ok else 'BLOCKED'} ({reason})")
    if not ok:
        sys.exit(1)

    # KB status
    from knowledge.build_kb import INDEX_FILE
    kb_chunks = 0
    if INDEX_FILE.exists():
        import json as _j
        kb_chunks = len(_j.loads(INDEX_FILE.read_text()))
    print(f"[KB]    {kb_chunks} methodology chunks loaded")

    Path(args.out).mkdir(parents=True, exist_ok=True)

    # ── Recon ────────────────────────────────────────────────────────
    if not args.idor_only:
        print("\n" + "─" * 60)
        print("  PHASE 1: Recon")
        print("─" * 60)
        recon_results = run_recon(domain, args.out, scope,
                                  config_path=args.config)

    # ── Exploitation ─────────────────────────────────────────────────
    if not args.recon_only:
        if not args.token_a:
            print("\n[!] --token-a required for exploitation phase.")
            print("    Recon complete. Skipping IDOR sweep.")
            return

        print("\n" + "─" * 60)
        print("  PHASE 2: IDOR/BOLA Sweep")
        print("─" * 60)
        token_b = args.token_b or args.token_a  # single-account fallback
        run_idor_sweep(base, scope, args.token_a, token_b,
                       args.out, cfg=cfg)

    print(f"\n[Done] Output: {args.out}/")


if __name__ == "__main__":
    main()
