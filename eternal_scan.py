#!/usr/bin/env python3
"""
AmonStrike — Eternal (Zomato/Blinkit) Scanner
Configured specifically for hackerone.com/eternal program rules.

Campaign: SQLi 1.5x multiplier (ends Sept 13, 2026)
  Critical SQLi: $3,000-$6,000
  High SQLi:     $1,500-$3,000
  First Blood Critical: +$500

Usage:
  sudo python3 eternal_scan.py --target zomato.com --username jardani101
  sudo python3 eternal_scan.py --discover --username jardani101
"""

import os
import sys
import json
import time
import argparse
import subprocess
import shutil
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# Required header on ALL requests per program rules
H1_HEADER_NAME  = "X-Hackerone"

# Shodan API key (provided)
SHODAN_API_KEY  = "byVaAzNjWhaPB59X6TvCiTAvsgaPoXeh"

# Tier definitions from program
TIER1 = ["zomato.com","zomans.com","runnr.in","blinkit.com"]
TIER2 = ["blinkit.com","hyperpure.com","grofer.io","grofers.com"]
TIER3 = ["district.in","insider.in","edition.in","ticketnew.com","eternal.com"]

# What NOT to test — explicitly OOS
OOS_MODULES = [
    "headers","clickjacking","rate_limit","ssl_tls","cookies",
    "email_injection","formula_injection","error_disclosure",
    "open_redirect",  # only if extra impact
]

# Campaign focus — SQLi today
CAMPAIGN_MODULES = ["sqli","nosql_injection","ssti"]  # injection campaign

# Priority for this program
PRIORITY_MODULES = [
    "sqli",            # CAMPAIGN — 1.5x today
    "idor",            # HIGH — PII access
    "ssrf",            # CRITICAL — internal pivot
    "lfi",             # CRITICAL
    "command_injection",# CRITICAL
    "ssti",            # CRITICAL — RCE possible
    "xss",             # HIGH — stored with cookies
    "jwt_deep",        # HIGH — auth bypass
    "account_takeover",# HIGH
    "file_upload",     # CRITICAL
    "graphql_deep",    # MEDIUM-HIGH
    "deserialization", # CRITICAL
    "nosql_injection", # CRITICAL
    "race_condition",  # HIGH
    "cors",            # MEDIUM
    "csrf",            # only if leads to ATO
]


def discover_targets(domain: str, h1_username: str) -> list:
    """Discover all subdomains for a domain using multiple sources."""
    print(f"\n[*] Discovering subdomains for {domain}...")
    targets = set()

    # 1. Subfinder
    if shutil.which("subfinder"):
        try:
            out = subprocess.run(
                ["subfinder", "-d", domain, "-silent", "-timeout", "30"],
                capture_output=True, text=True, timeout=120
            ).stdout
            for line in out.strip().splitlines():
                if line.strip():
                    targets.add(f"https://{line.strip()}")
            print(f"  [+] Subfinder: {len(targets)} subdomains")
        except Exception as e:
            print(f"  [!] Subfinder: {e}")

    # 2. Shodan
    try:
        import requests, urllib3
        urllib3.disable_warnings()
        r = requests.get(
            f"https://api.shodan.io/dns/domain/{domain}",
            params={"key": SHODAN_API_KEY},
            timeout=15
        )
        if r.status_code == 200:
            data = r.json()
            for sub in data.get("subdomains", []):
                targets.add(f"https://{sub}.{domain}")
            print(f"  [+] Shodan: {len(data.get('subdomains',[]))} subdomains")
    except Exception as e:
        print(f"  [!] Shodan: {e}")

    # 3. crt.sh
    try:
        import requests
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": "Mozilla/5.0"}
        )
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value","").strip()
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(domain):
                        targets.add(f"https://{n}")
            print(f"  [+] crt.sh: targets collected")
    except Exception as e:
        print(f"  [!] crt.sh: {e}")

    # 4. Check alive with httpx
    alive = []
    if shutil.which("httpx") and targets:
        print(f"  [*] Checking {len(targets)} targets alive...")
        try:
            inp = "\n".join(targets)
            out = subprocess.run(
                ["httpx", "-silent", "-timeout", "10", "-rate-limit", "20"],
                input=inp, capture_output=True, text=True, timeout=180
            ).stdout
            alive = [l.strip() for l in out.strip().splitlines() if l.strip()]
            print(f"  [+] Alive: {len(alive)}")
        except Exception:
            alive = list(targets)
    else:
        alive = list(targets)

    return alive


def get_tier(url: str) -> tuple:
    """Return (tier_number, bounty_multiplier) for a URL."""
    host = urlparse(url).netloc.lower()
    for t1 in TIER1:
        if host.endswith(t1):
            return (1, 1.5 if True else 1.0)  # campaign 1.5x
    for t2 in TIER2:
        if host.endswith(t2):
            return (2, 1.0)
    return (3, 1.0)


def scan_target(target: str, h1_username: str,
                output_dir: str, credentials: list = None) -> dict:
    """Run AmonStrike pipeline on one target with Eternal-specific config."""

    tier, multiplier = get_tier(target)
    print(f"\n{'='*60}")
    print(f"  TARGET: {target}")
    print(f"  TIER:   {tier} | Multiplier: {multiplier}x")
    print(f"{'='*60}")

    from core.pipeline import AmonStrikePipeline

    # Build scope for Eternal program
    scope = {
        "target":        target,
        "program_handle":"eternal",
        "allowed_hosts": [urlparse(target).netloc],
        "wildcards":     TIER1 + TIER2 + TIER3,
        "out_of_scope":  [],
    }

    # Required header per program rules
    required_headers = {
        H1_HEADER_NAME: h1_username,
        "User-Agent":   "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    }

    pipeline = AmonStrikePipeline(
        target       = target,
        output_dir   = output_dir,
        credentials  = credentials or [],
        program_handle = "eternal",
        debug        = False,
    )

    # Override modules based on program rules
    pipeline.state["skip_modules"]    = OOS_MODULES
    pipeline.state["priority_modules"] = PRIORITY_MODULES
    pipeline.state["required_headers"] = required_headers
    pipeline.state["shodan_key"]       = SHODAN_API_KEY
    pipeline.state["tier"]             = tier
    pipeline.state["bounty_multiplier"]= multiplier
    pipeline.state["scope"]            = scope

    # Inject required header into all module requests
    # Patch session to always add X-Hackerone header
    import requests, urllib3
    urllib3.disable_warnings()
    session = requests.Session()
    session.verify = False
    session.headers.update(required_headers)

    result = pipeline.run()

    # Filter out OOS findings
    findings = result.get("findings", [])
    oos_titles = [
        "Missing Security Header", "Clickjacking", "Rate Limit",
        "Open Redirect", "Self XSS", "Username Enum",
        "SSL", "Cookie", "CSRF on unauthenticated",
    ]
    filtered = []
    oos_count = 0
    for f in findings:
        if any(oos in f.get("title","") for oos in oos_titles):
            oos_count += 1
            continue
        filtered.append(f)

    if oos_count:
        print(f"\n  [i] Filtered {oos_count} OOS findings (not rewarded by Eternal)")

    result["findings"] = filtered
    result["tier"]     = tier
    result["multiplier"] = multiplier

    # Calculate estimated bounties
    bounty_estimate = _estimate_bounties(filtered, tier, multiplier)
    result["bounty_estimate"] = bounty_estimate
    _print_bounty_summary(filtered, bounty_estimate, tier)

    return result


def _estimate_bounties(findings: list, tier: int, multiplier: float) -> dict:
    """Estimate bounties based on Eternal program table."""

    BOUNTY_TABLE = {
        1: {  # Tier 1 — *.zomato.com
            "CRITICAL": (2000, 4000),
            "HIGH":     (1000, 2000),
            "MEDIUM":   (300, 1000),
            "LOW":      (100, 300),
        },
        2: {  # Tier 2 — *.blinkit.com
            "CRITICAL": (1000, 2000),
            "HIGH":     (500,  1000),
            "MEDIUM":   (200,  500),
            "LOW":      (100,  200),
        },
        3: {  # Tier 3
            "CRITICAL": (500, 1000),
            "HIGH":     (250, 500),
            "MEDIUM":   (100, 250),
            "LOW":      (50,  100),
        },
    }

    estimates = {"total_min": 0, "total_max": 0, "findings": []}
    table = BOUNTY_TABLE.get(tier, BOUNTY_TABLE[3])

    is_sqli_campaign = True  # Campaign active

    for f in findings:
        sev    = f.get("severity","LOW")
        module = f.get("module","")
        min_b, max_b = table.get(sev, (0,0))

        # Apply campaign multiplier to SQLi findings
        if is_sqli_campaign and module in ["sqli","nosql_injection"]:
            min_b = int(min_b * multiplier)
            max_b = int(max_b * multiplier)
            campaign_bonus = True
        else:
            campaign_bonus = False

        estimates["findings"].append({
            "title":   f.get("title","")[:60],
            "severity": sev,
            "module":   module,
            "min":      min_b,
            "max":      max_b,
            "campaign": campaign_bonus,
        })
        estimates["total_min"] += min_b
        estimates["total_max"] += max_b

    return estimates


def _print_bounty_summary(findings: list, estimates: dict, tier: int):
    """Print bounty summary."""
    if not findings:
        print("\n  No rewarded findings for this target")
        return

    print(f"\n{'='*60}")
    print(f"  BOUNTY ESTIMATE (Tier {tier})")
    print(f"{'='*60}")
    for f in estimates["findings"]:
        campaign = " [1.5x SQLi CAMPAIGN]" if f["campaign"] else ""
        print(f"  [{f['severity']}] {f['title'][:45]}")
        print(f"         Est: ${f['min']:,} – ${f['max']:,}{campaign}")
    print(f"{'─'*60}")
    print(f"  TOTAL ESTIMATE: ${estimates['total_min']:,} – ${estimates['total_max']:,}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="AmonStrike — Eternal (Zomato/Blinkit) H1 Scanner"
    )
    parser.add_argument("--target",    help="Single target URL (e.g. https://api.zomato.com)")
    parser.add_argument("--discover",  action="store_true", help="Discover all Eternal subdomains")
    parser.add_argument("--username",  required=True, help="Your HackerOne username")
    parser.add_argument("--credentials", default="[]", help="JSON credentials array")
    parser.add_argument("--output",    default="output/eternal", help="Output directory")
    parser.add_argument("--tier",      choices=["1","2","3","all"], default="all",
                        help="Which tier to scan")
    parser.add_argument("--sqli-only", action="store_true",
                        help="SQLi campaign mode — SQLi modules only")

    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  AmonStrike — Eternal Bug Bounty Scanner                 ║
║  Program: hackerone.com/eternal                          ║
║  Campaign: SQLi 1.5x (ENDS TODAY Sept 13 2026)          ║
║  Critical SQLi: $3,000–$6,000 + $500 First Blood        ║
╚══════════════════════════════════════════════════════════╝
  H1 Username: {args.username}
  Shodan:      configured
  Header:      X-Hackerone: {args.username} (required)
""")

    creds = json.loads(args.credentials)
    os.makedirs(args.output, exist_ok=True)
    all_findings = []

    if args.target:
        # Single target
        result = scan_target(args.target, args.username, args.output, creds)
        all_findings.extend(result.get("findings", []))

    elif args.discover:
        # Discover all Eternal targets
        domains_to_scan = []
        if args.tier in ["1","all"]:
            domains_to_scan.extend(TIER1)
        if args.tier in ["2","all"]:
            domains_to_scan.extend(TIER2)
        if args.tier in ["3","all"]:
            domains_to_scan.extend(TIER3)

        all_targets = []
        for domain in domains_to_scan[:5]:  # Start with first 5
            targets = discover_targets(domain, args.username)
            all_targets.extend(targets[:10])  # Max 10 per domain

        print(f"\n[*] Total discovered targets: {len(all_targets)}")
        print("[*] Starting scans...")

        for target in all_targets[:20]:  # Max 20 targets total
            try:
                result = scan_target(target, args.username, args.output, creds)
                all_findings.extend(result.get("findings", []))
                # Rate limit between targets
                time.sleep(5)
            except Exception as e:
                print(f"  [!] {target}: {e}")
    else:
        print("Use --target <url> or --discover")
        parser.print_help()
        return

    # Final summary
    if all_findings:
        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE — {len(all_findings)} total findings")
        sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in all_findings:
            sev[f.get("severity","LOW")] = sev.get(f.get("severity","LOW"),0) + 1
        for s,c in sev.items():
            if c: print(f"  {s}: {c}")
        print(f"\n  Reports: {args.output}/")
        print(f"  H1 Portal: {args.output}/H1_Submission_Portal.html")
        print(f"{'='*60}")
        print("\n  NEXT STEP: Open H1_Submission_Portal.html → read each finding → submit to H1")
        print("  Remember: First Blood on Critical = +$500 extra!")


if __name__ == "__main__":
    main()
