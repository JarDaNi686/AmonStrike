#!/usr/bin/env python3
"""
AmonStrike — ProjectDiscovery Recon Pipeline

Full chain: subfinder → dnsx → naabu → httpx → katana → nuclei

Methodology source: OWASP WSTG OTG-INFO, PayloadsAllTheThings recon section,
and standard H1 bug bounty recon methodology.

Install tools on Kali:
  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  go install github.com/projectdiscovery/httpx/cmd/httpx@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Or: sudo apt install -y subfinder dnsx naabu httpx katana nuclei

Usage:
  python3 recon/pipeline.py --domain api-sandbox.gocardless.com --out output/recon
  python3 recon/pipeline.py --domain api-sandbox.gocardless.com --steps subfinder,httpx,nuclei
"""

from __future__ import annotations
import os, sys, json, subprocess, argparse, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.scope_validator import ScopeValidator


# ── Tool availability check ────────────────────────────────────────────────
TOOLS = ["subfinder", "dnsx", "naabu", "httpx", "katana", "nuclei"]

def check_tools() -> dict[str, bool]:
    return {t: bool(subprocess.run(["which", t], capture_output=True).returncode == 0)
            for t in TOOLS}


def run(cmd: list[str], output_file: str = None, timeout: int = 300) -> tuple[int, str]:
    """Run a command, optionally tee to file, return (returncode, stdout)."""
    print(f"  $ {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        out = result.stdout.strip()
        if output_file and out:
            Path(output_file).write_text(out)
            print(f"    → {len(out.splitlines())} lines → {output_file}")
        return result.returncode, out
    except subprocess.TimeoutExpired:
        print(f"  [TIMEOUT] {cmd[0]} after {timeout}s")
        return 1, ""
    except FileNotFoundError:
        print(f"  [MISSING] {cmd[0]} not found — install on Kali first")
        return 1, ""


# ── Pipeline steps ─────────────────────────────────────────────────────────

def step_subfinder(domain: str, out_dir: Path, scope: ScopeValidator) -> list[str]:
    """Enumerate subdomains passively."""
    out_file = str(out_dir / "subdomains.txt")
    rc, out = run([
        "subfinder", "-d", domain,
        "-silent", "-all",
        "-o", out_file,
    ], timeout=120)
    if rc != 0 or not out:
        # Try reading output file directly
        if Path(out_file).exists():
            out = Path(out_file).read_text().strip()

    subs = [s.strip() for s in out.splitlines() if s.strip()]

    # Scope filter
    in_scope = []
    for s in subs:
        ok, _ = scope.is_in_scope(f"https://{s}")
        if ok:
            in_scope.append(s)
        else:
            print(f"    [SCOPE BLOCK] {s}")

    print(f"  Subdomains: {len(subs)} found, {len(in_scope)} in scope")
    (out_dir / "subdomains_in_scope.txt").write_text("\n".join(in_scope))
    return in_scope


def step_dnsx(subdomains: list[str], out_dir: Path) -> list[str]:
    """Resolve subdomains, filter live ones."""
    if not subdomains:
        return []
    subs_file = str(out_dir / "subdomains_in_scope.txt")
    out_file   = str(out_dir / "resolved.txt")
    rc, out = run([
        "dnsx", "-l", subs_file,
        "-silent", "-a", "-resp",
        "-o", out_file,
    ], timeout=120)
    resolved = [s.strip() for s in out.splitlines() if s.strip()]
    print(f"  Resolved: {len(resolved)} live hosts")
    return resolved


def step_naabu(hosts_file: str, out_dir: Path) -> list[str]:
    """Port scan — web ports only (80,443,8080,8443,3000,4000,5000,8000,9000)."""
    out_file = str(out_dir / "open_ports.txt")
    rc, out = run([
        "naabu", "-l", hosts_file,
        "-p", "80,443,8080,8443,3000,4000,5000,8000,9000",
        "-silent", "-rate", "500",
        "-o", out_file,
    ], timeout=180)
    ports = [s.strip() for s in out.splitlines() if s.strip()]
    print(f"  Open ports: {len(ports)}")
    return ports


def step_httpx(hosts_file: str, out_dir: Path) -> list[dict]:
    """Probe live HTTP services, extract tech stack, status codes."""
    out_file = str(out_dir / "live_urls.json")
    rc, out = run([
        "httpx", "-l", hosts_file,
        "-silent", "-json",
        "-status-code", "-title", "-tech-detect",
        "-follow-redirects", "-threads", "50",
        "-o", out_file,
    ], timeout=180)

    results = []
    if Path(out_file).exists():
        for line in Path(out_file).read_text().splitlines():
            try:
                results.append(json.loads(line))
            except Exception:
                pass
    print(f"  Live URLs: {len(results)}")
    return results


def step_katana(urls_file: str, out_dir: Path) -> list[str]:
    """Crawl live URLs, discover endpoints, JS files, parameters."""
    out_file = str(out_dir / "endpoints.txt")
    rc, out = run([
        "katana", "-l", urls_file,
        "-silent", "-jc",          # JavaScript crawling
        "-d", "3",                  # depth 3
        "-c", "10",                 # 10 concurrent
        "-ef", "css,png,jpg,gif,ico,woff,ttf",  # exclude static assets
        "-o", out_file,
    ], timeout=300)
    endpoints = [s.strip() for s in out.splitlines() if s.strip()]
    print(f"  Endpoints discovered: {len(endpoints)}")
    return endpoints


def step_nuclei(urls_file: str, out_dir: Path, severity: str = "medium,high,critical") -> list[dict]:
    """Run Nuclei template scan on discovered URLs."""
    out_file = str(out_dir / "nuclei_findings.json")
    rc, out = run([
        "nuclei", "-l", urls_file,
        "-silent", "-json",
        "-severity", severity,
        "-t", "exposures/",         # exposure templates
        "-t", "misconfiguration/",
        "-t", "vulnerabilities/",
        "-t", "token-spray/",
        "-rl", "10",                # rate limit: 10 req/s (polite)
        "-timeout", "10",
        "-o", out_file,
    ], timeout=600)

    findings = []
    if Path(out_file).exists():
        for line in Path(out_file).read_text().splitlines():
            try:
                findings.append(json.loads(line))
            except Exception:
                pass
    print(f"  Nuclei findings: {len(findings)}")
    return findings


# ── KB-augmented analysis ──────────────────────────────────────────────────

def analyze_with_kb(httpx_results: list[dict], endpoints: list[str]) -> list[dict]:
    """
    Map discovered tech stack and endpoints to relevant KB methodology.
    Returns prioritized test targets with KB context attached.
    """
    try:
        from core.kb_executor import get_kb_context
    except ImportError:
        return []

    targets = []
    for r in httpx_results:
        tech = r.get("tech", [])
        url  = r.get("url", "")
        if not url:
            continue

        # Map tech to vuln classes
        vuln_classes = []
        tech_lower = " ".join(str(t).lower() for t in tech)
        if any(k in tech_lower for k in ["jwt", "bearer", "oauth"]):
            vuln_classes.append("jwt")
        if "graphql" in tech_lower or any("/graphql" in e for e in endpoints):
            vuln_classes.append("graphql")
        if any(k in tech_lower for k in ["rest", "api", "json"]):
            vuln_classes.extend(["idor", "ssrf"])
        if not vuln_classes:
            vuln_classes = ["idor", "xss"]  # default for any web app

        for vc in set(vuln_classes):
            ctx = get_kb_context(vc, top_k=2)
            targets.append({
                "url":        url,
                "tech":       tech,
                "vuln_class": vc,
                "kb_context": ctx[:500],  # first 500 chars for summary
            })

    return targets


# ── Main ───────────────────────────────────────────────────────────────────

def run_pipeline(domain: str, out_dir: Path, steps: list[str],
                 scope: ScopeValidator) -> dict:

    out_dir.mkdir(parents=True, exist_ok=True)
    results = {"domain": domain, "steps": {}, "targets": []}

    print(f"\n{'='*60}")
    print(f"  Recon pipeline: {domain}")
    print(f"  Steps: {', '.join(steps)}")
    print(f"{'='*60}")

    available = check_tools()
    missing = [t for t in steps if t in TOOLS and not available.get(t)]
    if missing:
        print(f"\n[!] Missing tools (install on Kali): {', '.join(missing)}")
        print("    apt install -y " + " ".join(missing))
        print("    Skipping unavailable steps.\n")

    subdomains = [domain]

    # 1. Subfinder
    if "subfinder" in steps and available.get("subfinder"):
        print("\n[1/6] subfinder — subdomain enumeration")
        subdomains = step_subfinder(domain, out_dir, scope) or [domain]
        results["steps"]["subfinder"] = len(subdomains)

    subs_file = str(out_dir / "subdomains_in_scope.txt")
    if not Path(subs_file).exists():
        Path(subs_file).write_text("\n".join(subdomains))

    # 2. dnsx
    if "dnsx" in steps and available.get("dnsx"):
        print("\n[2/6] dnsx — DNS resolution")
        resolved = step_dnsx(subdomains, out_dir)
        results["steps"]["dnsx"] = len(resolved)

    # 3. naabu
    if "naabu" in steps and available.get("naabu"):
        print("\n[3/6] naabu — port scan")
        ports = step_naabu(subs_file, out_dir)
        results["steps"]["naabu"] = len(ports)

    # 4. httpx
    live_urls = []
    if "httpx" in steps and available.get("httpx"):
        print("\n[4/6] httpx — HTTP probing")
        live_urls = step_httpx(subs_file, out_dir)
        results["steps"]["httpx"] = len(live_urls)
        # Write URLs for next steps
        urls_file = str(out_dir / "live_urls.txt")
        Path(urls_file).write_text(
            "\n".join(r.get("url", "") for r in live_urls if r.get("url"))
        )

    urls_file = str(out_dir / "live_urls.txt")
    if not Path(urls_file).exists():
        Path(urls_file).write_text(f"https://{domain}")

    # 5. katana
    endpoints = []
    if "katana" in steps and available.get("katana"):
        print("\n[5/6] katana — endpoint crawl")
        endpoints = step_katana(urls_file, out_dir)
        results["steps"]["katana"] = len(endpoints)

    # 6. nuclei
    if "nuclei" in steps and available.get("nuclei"):
        print("\n[6/6] nuclei — template scan")
        findings = step_nuclei(urls_file, out_dir)
        results["steps"]["nuclei"] = len(findings)
        results["nuclei_findings"] = findings

    # KB-augmented target prioritization
    if live_urls:
        print("\n[KB] Mapping tech stack to vulnerability classes...")
        targets = analyze_with_kb(live_urls, endpoints)
        results["targets"] = targets
        print(f"  Prioritized targets: {len(targets)}")

    # Summary
    summary_file = out_dir / "recon_summary.json"
    summary_file.write_text(json.dumps(results, indent=2))
    print(f"\n[Done] Summary: {summary_file}")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--domain",  required=True, help="Target domain (must be in scope)")
    ap.add_argument("--out",     default="output/recon", help="Output directory")
    ap.add_argument("--steps",   default=",".join(TOOLS),
                    help="Comma-separated steps: subfinder,dnsx,naabu,httpx,katana,nuclei")
    ap.add_argument("--config",  default=None, help="Program YAML config")
    args = ap.parse_args()

    steps = [s.strip() for s in args.steps.split(",")]

    # Build scope from config or domain-only
    if args.config and Path(args.config).exists():
        import yaml
        cfg = yaml.safe_load(Path(args.config).read_text())
        allowed  = cfg.get("core_assets", []) + cfg.get("non_core_assets", [])
        forbidden = cfg.get("forbidden_hosts", [])
        from urllib.parse import urlparse
        hosts = [urlparse("https://" + h).hostname for h in allowed]
        scope = ScopeValidator(custom_scope=hosts, forbidden_hosts=forbidden)
    else:
        # Single-domain scope
        scope = ScopeValidator(custom_scope=[args.domain, f"*.{args.domain}"])

    # Scope check
    ok, reason = scope.is_in_scope(f"https://{args.domain}")
    if not ok:
        print(f"[BLOCKED] {args.domain} is out of scope: {reason}")
        sys.exit(1)
    print(f"[Scope] {args.domain} → ALLOWED ({reason})")

    run_pipeline(args.domain, Path(args.out), steps, scope)


if __name__ == "__main__":
    main()
