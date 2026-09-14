#!/usr/bin/env python3
"""
AmonStrike — DoD Bug Bounty Scanner
Program: hackerone.com/dod
Scope: All .mil publicly accessible assets
No login needed. Massive scope.
"""
import os, sys, json, subprocess, shutil, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

H1_USERNAME = "jardani101"
PROGRAM     = "dod"

# High-value DoD targets to start
DOD_TARGETS = [
    "https://www.army.mil",
    "https://www.navy.mil", 
    "https://www.af.mil",
    "https://www.marines.mil",
    "https://www.defense.gov",
    "https://www.disa.mil",
    "https://www.dla.mil",
    "https://www.dimoc.mil",
    "https://www.eucom.mil",
]

# DoD skip list — OOS
DOD_OOS = [
    "rate_limit", "headers", "clickjacking",
    "ssl_tls", "cookies", "email_injection",
]

def discover_dod_assets(seed_domain: str) -> list:
    """Discover DoD subdomains."""
    assets = set()
    domain = seed_domain.replace("https://","").replace("http://","")
    
    # subfinder
    if shutil.which("subfinder"):
        try:
            out = subprocess.run(
                ["subfinder","-d",domain,"-silent","-timeout","30"],
                capture_output=True, text=True, timeout=90
            ).stdout
            for line in out.strip().splitlines():
                if line.strip().endswith(".mil"):
                    assets.add(f"https://{line.strip()}")
        except Exception: pass

    # crt.sh
    try:
        import requests, urllib3; urllib3.disable_warnings()
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={"User-Agent":"Mozilla/5.0"}
        )
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value","").strip()
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n.endswith(".mil"):
                        assets.add(f"https://{n}")
    except Exception: pass

    print(f"  [+] {domain}: {len(assets)} subdomains found")
    return list(assets)


def scan_target(target: str):
    from terminator import Terminator
    t = Terminator(
        target      = target,
        credentials = [],
        h1_username = H1_USERNAME,
        profiles    = ["sqli","idor","ssrf","recon","xss","api"],
        output_dir  = f"output/dod/{target.split('//')[1].split('/')[0]}",
    )
    t.run()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--target",   help="Single .mil target")
    p.add_argument("--discover", action="store_true")
    p.add_argument("--all",      action="store_true", help="Scan all DoD targets")
    args = p.parse_args()

    print(f"""
╔══════════════════════════════════════════════╗
║  AmonStrike — DoD Bug Bounty Scanner         ║
║  Program: hackerone.com/dod                  ║
║  Scope: All publicly accessible .mil assets  ║
╚══════════════════════════════════════════════╝
""")

    if args.target:
        scan_target(args.target)
    elif args.all or args.discover:
        all_targets = []
        for seed in DOD_TARGETS[:3]:
            all_targets.extend(discover_dod_assets(seed))
        # Check alive
        if shutil.which("httpx"):
            inp = "\n".join(all_targets)
            out = subprocess.run(
                ["httpx","-silent","-timeout","10"],
                input=inp, capture_output=True, text=True, timeout=180
            ).stdout
            alive = [l.strip() for l in out.strip().splitlines() if l.strip()]
            print(f"\n[+] {len(alive)} alive .mil targets")
            for t in alive[:10]:
                scan_target(t)
        else:
            for t in all_targets[:5]:
                scan_target(t)
    else:
        # Default: scan army.mil
        scan_target("https://www.army.mil")
