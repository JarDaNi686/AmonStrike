#!/usr/bin/env python3
"""
AmonStrike — TERMINATOR
Parallel multi-terminal attack system.

Opens multiple terminals simultaneously:
- Terminal 1: SQLi focused scan
- Terminal 2: IDOR/Auth bypass
- Terminal 3: SSRF/SSTI/LFI
- Terminal 4: JS analysis + secret hunting
- Terminal 5: Subdomain + port scan
- Terminal 6: Authenticated scan (if credentials)

Confuses WAF by hitting from different angles simultaneously.
Each terminal uses different User-Agents, headers, timing.
All results merge into one final report.
"""

import os
import sys
import json
import time
import subprocess
import threading
import argparse
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent))

RESULTS_DIR = Path("/tmp/amonstrike_terminator")
RESULTS_DIR.mkdir(exist_ok=True)


# ── Terminal profiles — each looks different to WAF ───────────

TERMINAL_PROFILES = {
    "sqli": {
        "name":       "SQLi Hunter",
        "color":      "\033[91m",  # red
        "modules":    ["sqli","nosql_injection","ssti"],
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "extra_headers": {"Accept-Language": "en-US,en;q=0.9"},
        "rate_limit": 3,
        "delay":      0.5,
    },
    "idor": {
        "name":       "IDOR/Auth Hunter",
        "color":      "\033[93m",  # yellow
        "modules":    ["idor","account_takeover","twofa_bypass","jwt_deep","auth"],
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "extra_headers": {"Accept": "application/json"},
        "rate_limit": 2,
        "delay":      0.8,
    },
    "ssrf": {
        "name":       "SSRF/LFI/RCE Hunter",
        "color":      "\033[95m",  # magenta
        "modules":    ["ssrf","lfi","command_injection","xxe","deserialization"],
        "user_agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101",
        "extra_headers": {"X-Forwarded-For": "127.0.0.1"},
        "rate_limit": 2,
        "delay":      1.0,
    },
    "xss": {
        "name":       "XSS/CSRF/Logic Hunter",
        "color":      "\033[96m",  # cyan
        "modules":    ["xss","csrf","cors","open_redirect","prototype_pollution"],
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
        "extra_headers": {"Origin": "https://trusted-origin.com"},
        "rate_limit": 3,
        "delay":      0.4,
    },
    "recon": {
        "name":       "Recon + Secrets",
        "color":      "\033[92m",  # green
        "modules":    ["credentials","info","osint","vhost_enum","dirs"],
        "user_agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "extra_headers": {},
        "rate_limit": 5,
        "delay":      0.2,
    },
    "api": {
        "name":       "API + GraphQL Hunter",
        "color":      "\033[94m",  # blue
        "modules":    ["graphql_deep","api","websocket","race_condition","cache_poison"],
        "user_agent": "PostmanRuntime/7.36.0",
        "extra_headers": {"Content-Type": "application/json", "Accept": "application/json"},
        "rate_limit": 3,
        "delay":      0.5,
    },
}


class TerminalWorker:
    """One terminal = one attack profile."""

    def __init__(self, profile_name: str, target: str,
                 credentials: list, h1_username: str,
                 endpoints: list, output_dir: str):
        self.profile      = TERMINAL_PROFILES[profile_name]
        self.profile_name = profile_name
        self.target       = target
        self.credentials  = credentials
        self.h1_username  = h1_username
        self.endpoints    = endpoints
        self.output_dir   = output_dir
        self.findings     = []
        self.result_file  = RESULTS_DIR / f"{profile_name}_{int(time.time())}.json"

    def run(self):
        color = self.profile["color"]
        reset = "\033[0m"
        name  = self.profile["name"]

        print(f"{color}[{name}] Starting...{reset}")

        import requests, urllib3
        urllib3.disable_warnings()

        s = requests.Session()
        s.verify = False
        s.headers.update({
            "User-Agent":  self.profile["user_agent"],
            "X-Hackerone": self.h1_username,
        })
        s.headers.update(self.profile.get("extra_headers", {}))

        # Set cookies/auth if credentials provided
        cookies = {}
        if self.credentials:
            cred = self.credentials[0]
            cookies = cred.get("cookies", {})
            if cookies:
                s.cookies.update(cookies)

        sys.path.insert(0, str(Path(__file__).parent))

        for module_name in self.profile["modules"]:
            try:
                cls_name = "".join(w.capitalize() for w in module_name.split("_")) + "Module"
                mod      = __import__(f"modules.{module_name}", fromlist=[cls_name])
                cls      = getattr(mod, cls_name)
                inst     = cls(url=self.target, timeout=12,
                              cookies=cookies, headers=dict(s.headers))
                inst.extra_endpoints = self.endpoints[:80]
                inst._waf_type       = ""

                result   = inst.run()
                findings = result.get("findings", [])

                for f in findings:
                    f.setdefault("module",    module_name)
                    f.setdefault("terminal",  self.profile_name)
                    f.setdefault("timestamp", datetime.now().isoformat())

                self.findings.extend(findings)

                if findings:
                    print(f"{color}[{name}] [{module_name}] {len(findings)} findings!{reset}")
                    for f in findings:
                        print(f"{color}  [{f['severity']}] {f['title'][:60]}{reset}")

                time.sleep(self.profile["delay"])

            except Exception as e:
                if "--debug" in sys.argv:
                    print(f"{color}[{name}] [{module_name}] error: {e}{reset}")

        # Save results
        self.result_file.write_text(json.dumps({
            "profile":  self.profile_name,
            "target":   self.target,
            "findings": self.findings,
        }, indent=2, default=str))

        print(f"{color}[{name}] Done — {len(self.findings)} findings{reset}")
        return self.findings


class Terminator:
    """
    Launches all terminal workers in parallel.
    Merges results into one report.
    """

    def __init__(self, target: str, credentials: list = None,
                 h1_username: str = "jardani101",
                 profiles: list = None, output_dir: str = "output"):
        self.target      = target
        self.credentials = credentials or []
        self.h1_username = h1_username
        self.profiles    = profiles or list(TERMINAL_PROFILES.keys())
        self.output_dir  = output_dir
        self.all_findings= []
        os.makedirs(output_dir, exist_ok=True)

    def run(self):
        print(f"""
\033[1m{'='*60}
  AMONSTRIKE TERMINATOR
  Target: {self.target}
  Profiles: {len(self.profiles)} parallel terminals
  Username: {self.h1_username}
{'='*60}\033[0m
""")

        # Step 1: Discover endpoints once, share with all terminals
        endpoints = self._discover_endpoints()
        print(f"\n\033[1m[*] {len(endpoints)} endpoints discovered. Launching {len(self.profiles)} terminals...\033[0m\n")

        # Step 2: Launch all terminals in parallel
        workers = []
        threads = []

        for profile_name in self.profiles:
            if profile_name not in TERMINAL_PROFILES:
                continue
            worker = TerminalWorker(
                profile_name = profile_name,
                target       = self.target,
                credentials  = self.credentials,
                h1_username  = self.h1_username,
                endpoints    = endpoints,
                output_dir   = self.output_dir,
            )
            workers.append(worker)
            t = threading.Thread(target=worker.run, daemon=True)
            threads.append(t)

        # Start all simultaneously
        for t in threads:
            t.start()

        # Wait for all to complete
        for t in threads:
            t.join(timeout=600)

        # Step 3: Merge all findings
        seen = set()
        for worker in workers:
            for f in worker.findings:
                sig = f"{f.get('module','')}|{f.get('url','')}|{f.get('title','')[:30]}"
                if sig not in seen:
                    seen.add(sig)
                    self.all_findings.append(f)

        # Step 4: Generate report
        self._generate_report()

        return self.all_findings

    def _discover_endpoints(self) -> list:
        """Discover all endpoints before launching terminals."""
        print("[*] Discovering attack surface...")
        endpoints = set()

        try:
            import requests, urllib3
            urllib3.disable_warnings()
            s = requests.Session()
            s.verify = False
            s.headers.update({
                "User-Agent":  "Mozilla/5.0",
                "X-Hackerone": self.h1_username,
            })
            from core.surface_discovery import AggressiveSurfaceDiscovery
            disc   = AggressiveSurfaceDiscovery(self.target, s, {"X-Hackerone": self.h1_username})
            result = disc.run()
            endpoints.update(result.get("endpoints", []))
            endpoints.update(result.get("api_calls", []))
        except Exception as e:
            print(f"  [!] Surface discovery: {e}")

        return list(endpoints)

    def _generate_report(self):
        """Generate final merged report."""
        if not self.all_findings:
            print("\n\033[91m[!] No findings across all terminals\033[0m")
            return

        print(f"\n\033[1m{'='*60}")
        print(f"  TERMINATOR COMPLETE — {len(self.all_findings)} FINDINGS")
        print(f"{'='*60}\033[0m")

        sev = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
        for f in self.all_findings:
            s = f.get("severity","LOW")
            sev[s] = sev.get(s,0)+1

        for s,c in sev.items():
            if c:
                color = {"CRITICAL":"\033[91m","HIGH":"\033[93m","MEDIUM":"\033[96m","LOW":"\033[92m"}.get(s,"")
                print(f"  {color}{s}: {c}\033[0m")

        print()
        for f in sorted(self.all_findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO") if x.get("severity","INFO") in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] else "INFO")):
            sev_color = {"CRITICAL":"\033[91m","HIGH":"\033[93m","MEDIUM":"\033[96m","LOW":"\033[92m"}.get(f.get("severity","LOW"),"")
            print(f"  {sev_color}[{f['severity']}] {f.get('title','')[:65]}\033[0m")
            print(f"         Terminal: {f.get('terminal','')} | {f.get('url','')[:50]}")

        # Generate H1 report
        try:
            from reports.hackerone_format import generate_h1_package
            pkg = generate_h1_package(
                self.all_findings, self.output_dir,
                program_handle="eternal", target_url=self.target
            )
            if pkg.get("portal"):
                print(f"\n\033[1m  H1 Portal: {pkg['portal']}\033[0m")
        except Exception as e:
            print(f"  [!] Report error: {e}")


def open_tmux_terminals(target: str, username: str,
                        credentials_json: str, profiles: list):
    """
    Open real tmux terminals — one per profile.
    Each terminal runs independently.
    """
    session = "amonstrike"

    # Kill existing session
    subprocess.run(["tmux","kill-session","-t",session],
                  capture_output=True)

    # Create new session
    subprocess.run(["tmux","new-session","-d","-s",session,
                   "-x","220","-y","50"])

    cred_arg = f"--credentials '{credentials_json}'" if credentials_json != "[]" else ""

    for i, profile in enumerate(profiles[:6]):
        cmd = (f"sudo python3 eternal_scan.py "
               f"--target {target} "
               f"--username {username} "
               f"--profile {profile} "
               f"{cred_arg} ; "
               f"echo 'Terminal {profile} done. Press Enter.'; read")

        if i == 0:
            subprocess.run(["tmux","send-keys","-t",session,cmd,"Enter"])
        else:
            subprocess.run(["tmux","split-window","-t",session,"-v"])
            subprocess.run(["tmux","send-keys","-t",session,cmd,"Enter"])
            if i % 2 == 0:
                subprocess.run(["tmux","select-layout","-t",session,"tiled"])

    subprocess.run(["tmux","select-layout","-t",session,"tiled"])
    subprocess.run(["tmux","attach-session","-t",session])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AmonStrike Terminator — Parallel Attack System")
    parser.add_argument("--target",      required=True)
    parser.add_argument("--username",    default="jardani101")
    parser.add_argument("--credentials", default="[]")
    parser.add_argument("--profiles",    default="all",
                        help="Comma-separated profiles or 'all': sqli,idor,ssrf,xss,recon,api")
    parser.add_argument("--output",      default="output/terminator")
    parser.add_argument("--tmux",        action="store_true",
                        help="Open real tmux terminals (requires tmux)")
    parser.add_argument("--debug",       action="store_true")

    args = parser.parse_args()

    creds   = json.loads(args.credentials)
    profiles = list(TERMINAL_PROFILES.keys()) if args.profiles == "all" \
               else args.profiles.split(",")

    if args.tmux:
        open_tmux_terminals(args.target, args.username,
                           args.credentials, profiles)
    else:
        t = Terminator(
            target      = args.target,
            credentials = creds,
            h1_username = args.username,
            profiles    = profiles,
            output_dir  = args.output,
        )
        t.run()
