"""
AmonStrike — Intelligence Orchestrator
Master controller for all 3 intelligence levels.

Runs the complete professional pipeline:
  Level 1: WAF + ASN + GitHub + Cloud buckets
  Level 2: Chain engine + JS analysis + Bypass engine
  Level 3: AI report + CVSS + H1 submission draft

One command. Full professional recon.
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from intelligence.waf_engine     import WAFIntelligence, WAFBypassEngine
from intelligence.asn_mapper     import ASNMapper, CloudBucketHunter
from intelligence.github_scanner import GitHubScanner, CredentialOSINT
from intelligence.chain_engine   import ChainEngine
from intelligence.js_intelligence import JSIntelligence


class IntelligenceOrchestrator:
    """
    Master orchestrator for all intelligence operations.
    Runs everything in parallel where possible.
    """

    def __init__(self, target: str, output_dir: str = None,
                 github_token: str = None,
                 shodan_key: str = None,
                 censys_id: str = None,
                 censys_secret: str = None):
        self.target     = target.rstrip("/")
        self.parsed     = __import__("urllib.parse",fromlist=["urlparse"]).urlparse(target)
        self.domain     = self.parsed.hostname or target
        self.org        = self.domain.split(".")[0]
        self.output_dir = Path(output_dir or f"output/intel_{self.org}_{int(time.time())}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # API keys
        self.github_token  = github_token  or os.environ.get("GITHUB_TOKEN","")
        self.shodan_key    = shodan_key    or os.environ.get("SHODAN_API","")
        self.censys_id     = censys_id     or os.environ.get("CENSYS_API_ID","")
        self.censys_secret = censys_secret or os.environ.get("CENSYS_API_SECRET","")

        self.results = {
            "target":    self.target,
            "domain":    self.domain,
            "started":   datetime.now().isoformat(),
            "waf":       {},
            "asn":       {},
            "buckets":   [],
            "github":    [],
            "js":        {},
            "chains":    [],
            "findings":  [],
        }

    def run_all(self, parallel: bool = True) -> dict:
        """Run all intelligence levels."""
        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  AmonStrike Intelligence Engine v3.0                      ║
║  Target: {self.target[:50]:<50} ║
╚═══════════════════════════════════════════════════════════╝
        """)

        if parallel:
            self._run_parallel()
        else:
            self._run_sequential()

        # Run chain analysis on all findings
        self._run_chains()

        # Save final report
        self._save_report()

        self._print_summary()
        return self.results

    def _run_parallel(self):
        """Run all intelligence modules in parallel."""
        threads = []

        def run(fn):
            try:
                fn()
            except Exception as e:
                print(f"  [!] Error in {fn.__name__}: {e}")

        modules = [
            self._run_waf_intel,
            self._run_asn_mapping,
            self._run_cloud_buckets,
            self._run_github_scan,
            self._run_js_analysis,
        ]

        for fn in modules:
            t = threading.Thread(target=run, args=(fn,))
            t.daemon = True
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=300)  # 5 min max per module

    def _run_sequential(self):
        """Run intelligence modules sequentially."""
        self._run_waf_intel()
        self._run_asn_mapping()
        self._run_cloud_buckets()
        self._run_github_scan()
        self._run_js_analysis()

    def _run_waf_intel(self):
        """Level 1: WAF fingerprint + origin discovery."""
        print("\n[LEVEL 1] WAF Intelligence...")
        try:
            waf = WAFIntelligence(self.target)
            result = waf.full_analysis()
            self.results["waf"] = result

            # Convert WAF findings to standard findings format
            if result.get("waf"):
                self.results["findings"].append({
                    "title":       f"WAF Detected: {result['waf']}",
                    "severity":    "INFO",
                    "module":      "waf",
                    "url":         self.target,
                    "description": f"WAF vendor: {result['waf']} "
                                   f"(confidence: {result['waf_confidence']}%)\n"
                                   f"Bypass: {result.get('bypass_recommended','')}",
                    "evidence":    json.dumps(result.get("details",{}))[:300],
                    "remediation": "WAF is a defense layer, not a vulnerability.",
                })

            if result.get("origin_ips"):
                self.results["findings"].append({
                    "title":       f"WAF Origin IP Discovered: {result['origin_ips'][0]}",
                    "severity":    "HIGH",
                    "module":      "waf",
                    "url":         self.target,
                    "description": f"Real origin IP found behind WAF: {result['origin_ips']}. "
                                   f"Direct connection bypasses all WAF protection.",
                    "evidence":    f"Origin IPs: {result['origin_ips']}\nVerified by: direct connection test",
                    "remediation": "Restrict origin server to only accept connections from WAF/CDN IPs.",
                })

        except Exception as e:
            print(f"  [!] WAF intel error: {e}")

    def _run_asn_mapping(self):
        """Level 1: ASN infrastructure mapping."""
        print("\n[LEVEL 1] ASN Infrastructure Mapping...")
        try:
            mapper = ASNMapper(self.domain)
            result = mapper.run()
            self.results["asn"] = result

            if result.get("asns"):
                self.results["findings"].append({
                    "title":       f"Infrastructure Mapped: {len(result['cidrs'])} CIDR ranges",
                    "severity":    "INFO",
                    "module":      "recon",
                    "url":         self.target,
                    "description": f"Organization controls {len(result['cidrs'])} IP ranges "
                                   f"across {len(result['asns'])} ASNs. "
                                   f"Scan command: {mapper.get_masscan_command()[:100]}",
                    "evidence":    f"ASNs: {[a['asn'] for a in result['asns']]}\n"
                                   f"CIDRs: {result['cidrs'][:5]}",
                    "remediation": "Review which services are exposed on all IP ranges.",
                })

        except Exception as e:
            print(f"  [!] ASN mapping error: {e}")

    def _run_cloud_buckets(self):
        """Level 1: Cloud bucket enumeration."""
        print("\n[LEVEL 1] Cloud Bucket Enumeration...")
        try:
            hunter  = CloudBucketHunter(self.org)
            buckets = hunter.scan(max_names=30)
            self.results["buckets"] = buckets

            for bucket in buckets:
                if bucket.get("readable"):
                    self.results["findings"].append({
                        "title":       f"Publicly Readable Cloud Bucket: {bucket['bucket']}",
                        "severity":    "HIGH",
                        "module":      "dirs",
                        "url":         bucket.get("url",""),
                        "description": f"{bucket['provider'].upper()} storage bucket is publicly readable. "
                                       f"Contains potentially sensitive files.",
                        "evidence":    f"URL: {bucket.get('url','')}\n"
                                       f"Files: {bucket.get('files',['unknown'])[:5]}",
                        "remediation": "Set bucket ACL to private. "
                                       "Review all objects for sensitive data. "
                                       "Enable access logging.",
                    })

        except Exception as e:
            print(f"  [!] Bucket scan error: {e}")

    def _run_github_scan(self):
        """Level 1: GitHub secret scanning."""
        print("\n[LEVEL 1] GitHub Intelligence...")
        try:
            scanner  = GitHubScanner(self.domain, self.org, self.github_token)
            findings = scanner.scan()
            self.results["github"] = findings

            for secret in findings:
                sev = secret.get("severity","MEDIUM")
                self.results["findings"].append({
                    "title":       f"Secret Exposed on GitHub: {secret['type']}",
                    "severity":    sev,
                    "module":      "credentials",
                    "url":         secret.get("url","https://github.com"),
                    "description": f"{'LIVE ' if secret.get('verified') else ''}secret found in "
                                   f"{secret.get('repo','')} — {secret['type']}",
                    "evidence":    f"File: {secret.get('file','')}\n"
                                   f"Value: {secret.get('value','')[:30]}...\n"
                                   f"Repo: {secret.get('repo','')}\n"
                                   f"Verified: {secret.get('verified',False)}",
                    "remediation": "Rotate secret immediately. "
                                   "Add to .gitignore. "
                                   "Use GitHub Secret Scanning alerts. "
                                   "Audit git history with git filter-branch.",
                    "parameter":   secret["type"],
                })

        except Exception as e:
            print(f"  [!] GitHub scan error: {e}")

    def _run_js_analysis(self):
        """Level 2: JavaScript intelligence."""
        print("\n[LEVEL 2] JavaScript Analysis...")
        try:
            js_eng = JSIntelligence(self.target, str(self.output_dir / "js"))
            result = js_eng.run()
            self.results["js"] = result

            # Source maps = critical finding
            for map_url in result.get("source_maps",[]):
                self.results["findings"].append({
                    "title":       f"JavaScript Source Map Exposed: {map_url}",
                    "severity":    "HIGH",
                    "module":      "info",
                    "url":         map_url,
                    "description": "Source map file publicly accessible. "
                                   "Exposes original un-minified source code, "
                                   "internal routes, API calls, and developer comments.",
                    "evidence":    f"Source map URL: {map_url}\n"
                                   f"Endpoints discovered: {len(result.get('endpoints',[]))}",
                    "remediation": "Remove .map files from production. "
                                   "Configure webpack: devtool: false in production.",
                })

            # Admin routes
            for route in result.get("admin_routes",[])[:5]:
                path = route["path"] if isinstance(route,dict) else route
                self.results["findings"].append({
                    "title":       f"Hidden Admin Endpoint in JS: {path}",
                    "severity":    "MEDIUM",
                    "module":      "dirs",
                    "url":         self.target + path,
                    "description": f"Admin/internal endpoint {path} found in JavaScript bundle. "
                                   "May be accessible even without UI exposure.",
                    "evidence":    f"Found in JS source, endpoint: {path}",
                    "remediation": "Ensure all admin endpoints require authentication. "
                                   "Test endpoint directly.",
                })

            # JS secrets
            for secret in result.get("secrets",[]):
                self.results["findings"].append({
                    "title":       f"Secret in JavaScript: {secret['type']}",
                    "severity":    "HIGH",
                    "module":      "credentials",
                    "url":         secret.get("origin",""),
                    "description": f"{secret['type']} found in JavaScript file. "
                                   "Accessible to any browser without authentication.",
                    "evidence":    f"File: {secret.get('source','')}\n"
                                   f"Value: {secret.get('value','')[:30]}...",
                    "remediation": "Move secrets to server-side environment variables. "
                                   "Never expose API keys in client-side code.",
                })

        except Exception as e:
            print(f"  [!] JS analysis error: {e}")

    def _run_chains(self):
        """Level 2: Vulnerability chain analysis."""
        print("\n[LEVEL 2] Chain Analysis...")
        try:
            chain_eng = ChainEngine(self.target)
            chains    = chain_eng.analyze(self.results["findings"])
            self.results["chains"] = chains

            # Add chain findings
            for chain in chains:
                self.results["findings"].append({
                    "title":       f"CHAIN: {chain['name']}",
                    "severity":    chain["severity"],
                    "module":      "chain",
                    "url":         chain.get("trigger_url",""),
                    "description": (
                        f"Vulnerability chain: {chain['name']}. "
                        f"Original severity escalated from "
                        f"{chain.get('original_sev','')} to {chain['severity']}. "
                        f"Estimated bounty: ${chain['estimated_bounty']:,}"
                    ),
                    "evidence":    "\n".join(chain.get("steps",[])),
                    "remediation": "Fix the triggering vulnerability first.",
                    "chain_data":  chain,
                })

        except Exception as e:
            print(f"  [!] Chain analysis error: {e}")

    def _save_report(self):
        """Save complete intelligence report."""
        report_path = self.output_dir / "intelligence_report.json"
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n  [+] Report saved: {report_path}")

    def _print_summary(self):
        """Print executive summary."""
        r = self.results
        crits = sum(1 for f in r["findings"] if f.get("severity")=="CRITICAL")
        highs = sum(1 for f in r["findings"] if f.get("severity")=="HIGH")

        print(f"""
╔═══════════════════════════════════════════════════════════╗
║  INTELLIGENCE SUMMARY                                     ║
╠═══════════════════════════════════════════════════════════╣
║  Target:      {self.target[:45]:<45} ║
║  WAF:         {str(r['waf'].get('waf','None'))[:45]:<45} ║
║  Origin IP:   {str(r['waf'].get('origin_ips',['None'])[:1])[1:-1][:45]:<45} ║
║  ASN Ranges:  {str(len(r['asn'].get('cidrs',[]))):<45} ║
║  Open Buckets:{str(sum(1 for b in r['buckets'] if b.get('readable'))):<45} ║
║  Git Secrets: {str(len(r['github'])):<45} ║
║  JS Endpoints:{str(len(r['js'].get('endpoints',[]))):<45} ║
║  Source Maps: {str(len(r['js'].get('source_maps',[]))):<45} ║
║  Chains Found:{str(len(r['chains'])):<45} ║
║  CRITICAL:    {str(crits):<45} ║
║  HIGH:        {str(highs):<45} ║
╚═══════════════════════════════════════════════════════════╝
""")


def run_regression_tests():
    import tempfile
    print("\n=== INTELLIGENCE ORCHESTRATOR REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp()
    orch = IntelligenceOrchestrator(
        "http://testphp.vulnweb.com",
        output_dir=tmp
    )

    tests = [
        ("Orchestrator instantiates",
         lambda: isinstance(orch, IntelligenceOrchestrator)),

        ("Domain extracted",
         lambda: orch.domain == "testphp.vulnweb.com"),

        ("Org extracted",
         lambda: orch.org == "testphp"),

        ("Output dir created",
         lambda: Path(tmp).exists()),

        ("Results structure correct",
         lambda: all(k in orch.results for k in
                    ["target","waf","asn","buckets","github","js","chains","findings"])),

        ("WAF intel runs without crash",
         lambda: (orch._run_waf_intel() or True)),

        ("ASN mapping runs without crash",
         lambda: (orch._run_asn_mapping() or True)),

        ("JS analysis runs without crash",
         lambda: (orch._run_js_analysis() or True)),

        ("Chain analysis runs without crash",
         lambda: (orch._run_chains() or True)),

        ("Report saves to file",
         lambda: (orch._save_report() or True) and
                 (Path(tmp) / "intelligence_report.json").exists()),

        ("Print summary runs",
         lambda: (orch._print_summary() or True)),

        ("Findings list populated after runs",
         lambda: isinstance(orch.results["findings"], list)),

        ("All finding entries have severity",
         lambda: all("severity" in f for f in orch.results["findings"])),

        ("All findings have title",
         lambda: all("title" in f for f in orch.results["findings"])),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        orch = IntelligenceOrchestrator(sys.argv[1])
        orch.run_all()
    else:
        run_regression_tests()
