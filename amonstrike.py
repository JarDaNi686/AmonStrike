#!/usr/bin/env python3
"""
AmonStrike — Hidden Reconnaissance, Precise Strike
Author: JarDani
Version: 2.0

The Never Dead-End Bug Bounty Recon Framework.
Every finding feeds the next attack. Every dead-end has a fallback.
A real target is NEVER clean. There is ALWAYS something.

Usage:
    sudo python3 amonstrike.py
    sudo python3 amonstrike.py --url http://target.com
    sudo python3 amonstrike.py --url http://target.com --modules all
    sudo python3 amonstrike.py --url http://target.com --mode fast
    sudo python3 amonstrike.py --url http://target.com --mode deep
    sudo python3 amonstrike.py --url http://target.com --no-ui
"""

import os
import sys
import time
import json
import argparse
import threading
import signal
from datetime import datetime
from urllib.parse import urlparse

# AmonStrike core imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.config import Config
from core.shell_manager import ShellManager, ProfessionalUI
from core.auth_engine import ScanAuthEngine
from core.endpoint_distributor import EndpointDistributor, ToolIntegrator
from core.scan_state import ScanState

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Colors ───────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; W = "\033[97m"; D = "\033[90m"
X = "\033[0m";  BLD = "\033[1m"

BANNER = f"""
{D}  ════════════════════════════════════════════════════════════════════{X}
{R}{BLD}
    ░█████╗░███╗░░░███╗░█████╗░███╗░░██╗░██████╗████████╗██████╗░██╗██╗░░██╗███████╗
    ██╔══██╗████╗░████║██╔══██╗████╗░██║██╔════╝╚══██╔══╝██╔══██╗██║██║░██╔╝██╔════╝
    ███████║██╔████╔██║██║░░██║██╔██╗██║╚█████╗░░░░██║░░░██████╔╝██║█████═╝░█████╗░░
    ██╔══██║██║╚██╔╝██║██║░░██║██║╚████║░╚═══██╗░░░██║░░░██╔══██╗██║██╔═██╗░██╔══╝░░
    ██║░░██║██║░╚═╝░██║╚█████╔╝██║░╚███║██████╔╝░░░██║░░░██║░░██║██║██║░╚██╗███████╗
    ╚═╝░░╚═╝╚═╝░░░░╚═╝░╚════╝░╚═╝░░╚══╝╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝╚═╝╚═╝░░╚═╝╚══════╝
{X}
{D}         Hidden Reconnaissance. Precise Strike. Professional Report.{X}
{D}  ════════════════════════════════════════════════════════════════════{X}
{D}         Author: JarDani    Version: 2.0    Never Dead-End Edition{X}
{D}  ════════════════════════════════════════════════════════════════════{X}
"""

# ── Scan modes ────────────────────────────────────────────────
SCAN_MODES = {
    "fast": {
        "desc": "Quick scan — essential checks only (~5 min)",
        "modules": ["recon", "headers", "cookies", "cors", "info", "dirs"],
        "nde":     False,
    },
    "normal": {
        "desc": "Standard scan — all modules (~15 min)",
        "modules": "all",
        "nde":     True,
    },
    "deep": {
        "desc": "Deep scan — all modules + NDE + tool chaining (~45 min)",
        "modules": "all",
        "nde":     True,
    },
    "nde": {
        "desc": "Never Dead-End mode — full autonomous recon",
        "modules": "all",
        "nde":     True,
    },
}

# ── Module list ───────────────────────────────────────────────
ALL_MODULES = [
    "recon", "headers", "sqli", "xss", "csrf", "cors",
    "cookies", "dirs", "lfi", "ssrf", "idor", "rce",
    "auth", "api", "info", "ports", "osint", "waf",
    "takeover", "credentials", "ssti", "jwt_deep",
    "race_condition", "http_smuggling", "xxe",
    "graphql_deep", "oauth", "business_logic",
    "cache_poison", "deserialization",
    "open_redirect", "rate_limit", "twofa_bypass",
    "file_upload", "nosql_injection", "clickjacking", "ssl_tls", "error_disclosure", "vhost_enum", "command_injection", "session_fixation", "email_injection", "formula_injection", "account_takeover", "csp_bypass", "firebase", "websocket", "parameter_pollution", "timing_attack", "saml_bypass", "prototype_pollution",
]

def log(msg, level="*"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"*": D, "!": R, "+": G, "~": Y, "i": C}
    c = colors.get(level, D)
    print(f"[{ts}] {c}[AS/{level}]{X} {msg}")

def get_input(prompt, default=None):
    d_str = f" [{D}{default}{X}]" if default else ""
    result = input(f"  {W}{prompt}{X}{d_str}: ").strip()
    return result if result else default

def validate_url(url):
    if not url:
        return None
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        p = urlparse(url)
        if not p.netloc:
            return None
        return url.rstrip("/")
    except Exception:
        return None

def detect_kali_ip():
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def setup_output_dir(url):
    parsed = urlparse(url)
    safe = parsed.netloc.replace(":", "_").replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "output", f"{safe}_{ts}"
    )
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


class AmonStrike:
    """
    Main orchestrator.
    Wires together: UI + Installer + NDE Engine + Modules + Report.
    """

    def __init__(self, args):
        self.args      = args
        self.url       = args.url
        self.mode      = args.mode
        self.use_ui    = not args.no_ui
        self.use_nde   = not args.no_nde
        self.output_dir = None
        self.ui        = None
        self.nde       = None
        self.results   = {}
        self.all_findings = []
        self._stop     = threading.Event()

    def run(self):
        """Main entry point."""
        print(BANNER)

        # Check root
        if os.geteuid() != 0:
            print(f"{R}[!]{X} Run with sudo: sudo python3 amonstrike.py")
            sys.exit(1)

        # Get URL
        if not self.url:
            print(f"{D}  Configure your scan:{X}\n")
            raw = get_input("Target URL")
            self.url = validate_url(raw)
            if not self.url:
                print(f"{R}[!]{X} Invalid URL")
                sys.exit(1)

        # Validate URL
        self.url = validate_url(self.url)
        if not self.url:
            print(f"{R}[!]{X} Invalid URL: {self.args.url}")
            sys.exit(1)

        # Setup output
        self.output_dir = setup_output_dir(self.url)
        log(f"Output directory: {self.output_dir}", "i")

        # Get modules
        modules = self._resolve_modules()

        # Session data
        self.session_data = {
            "url":        self.url,
            "parsed":     urlparse(self.url),
            "timeout":    self.args.timeout,
            "threads":    self.args.threads,
            "proxy":      {"http": self.args.proxy, "https": self.args.proxy}
                          if self.args.proxy else None,
            "cookies":    self.args.cookies or "",
            "headers":    json.loads(self.args.headers) if self.args.headers else {},
            "wordlist":   self.args.wordlist,
            "output_dir": self.output_dir,
            "mode":       self.mode,
        }

        # Print mission brief
        self._print_brief(modules)
        # Check for resumable scan
        self._scan_state = ScanState(self.url, modules)
        if self._scan_state.has_prior_state():
            remaining = self._scan_state.remaining_modules()
            summary   = self._scan_state.summary()
            print(f"\n  {Y}[~] Resumable scan found: {summary}{X}")
            choice = input(f"  {W}Resume? (y=resume, n=restart, Enter=resume):{X} ").strip().lower()
            if choice == "n":
                self._scan_state.clear()
                print(f"  {G}[+] Starting fresh scan{X}")
            else:
                modules = remaining
                print(f"  {G}[+] Resuming — {len(modules)} modules remaining{X}")
                # Restore previous findings
                for mod in [m for m in self._scan_state._state["completed"]]:
                    self.results[mod] = self._scan_state.get_saved_result(mod)

        confirm = input(f"\n  {W}Start? (Enter to continue / Ctrl+C to cancel){X}: ")
        print()

        # Setup signal handler
        signal.signal(signal.SIGINT, self._handle_interrupt)

        # Phase 0.8: Authentication engine
        self._auth_engine = None
        creds_raw = getattr(self.args, "credentials", None)
        if creds_raw:
            try:
                creds = json.loads(creds_raw) if isinstance(creds_raw, str) else creds_raw
                self._auth_engine = ScanAuthEngine(self.url, timeout=self.args.timeout)
                for cred in creds:
                    self._auth_engine.add_credential(
                        cred.get("username",""),
                        cred.get("password",""),
                        cred.get("role","user"),
                    )
                log("Logging in with provided credentials...", "*")
                login_results = self._auth_engine.login_all()
                logged_in = sum(1 for r in login_results.values() if r.get("success"))
                log(f"Authenticated: {logged_in}/{len(creds)} accounts", "+")
                if logged_in:
                    # Update session_data with auth
                    self.session_data["cookies"] = self._auth_engine.cookies_for_module()
                    self.session_data["headers"] = {
                        **self.session_data.get("headers",{}),
                        **self._auth_engine.headers_for_module()
                    }
            except Exception as e:
                log(f"Auth setup error: {e}", "!")

        # Phase 0.9: Endpoint distributor
        self._endpoint_dist = EndpointDistributor(self.url)
        self._tool_integrator = ToolIntegrator(str(self.output_dir) + "/tools")

        # Phase 1: Auto-install tools
        tool_status = self._run_installer(modules)

        # Phase 2: Start UI
        if self.use_ui:
            self._start_ui()

        # Phase 3: Run NDE engine (if enabled)
        if self.use_nde and self.mode in ["deep", "nde", "normal"]:
            self._run_nde_engine()

        # Phase 3.5: Intelligence engine (if requested)
        bypass_headers = {}
        if getattr(self.args, "intel", False) or self.mode == "deep":
            self._run_intelligence()
        if getattr(self.args, "waf_bypass", False) or self.mode in ["deep","nde"]:
            bypass_headers = self._run_waf_bypass()

        # Phase 4: Run scan modules
        self._run_modules(modules, tool_status, bypass_headers=bypass_headers)

        # Phase 5: Stop UI
        if self.ui:
            self.ui.stop()
            time.sleep(0.5)

        # Phase 5.5: Feed discovered endpoints to distributor
        for mod_name in ["recon","dirs","osint"]:
            mod_result = self.results.get(mod_name, {})
            info = mod_result.get("info", {})
            for key in ["endpoints","urls","paths","discovered_paths"]:
                endpoints = info.get(key, [])
                if endpoints:
                    self._endpoint_dist.add_endpoints(endpoints)
        
        if self._endpoint_dist.get_all_endpoints():
            log(f"Endpoint distributor: {self._endpoint_dist.stats()['total']} endpoints for re-testing", "i")

        # Phase 6: Merge all findings
        self._merge_findings()

        # Phase 6.5: Chain engine
        if not getattr(self.args, "no_chain", False):
            self._run_chain_engine()

        # Phase 6.6: Screenshots
        if not getattr(self.args, "no_ui", False):
            self._run_screenshots()

        # Phase 7: Generate report
        self._generate_report(modules)

        # Phase 8: Print summary
        self._print_summary()

    def _resolve_modules(self):
        """Resolve which modules to run based on mode and args."""
        if self.args.modules:
            if self.args.modules.lower() == "all":
                return ALL_MODULES
            return [m.strip() for m in self.args.modules.split(",")
                   if m.strip() in ALL_MODULES]

        mode_cfg = SCAN_MODES.get(self.mode, SCAN_MODES["normal"])
        mods = mode_cfg["modules"]
        if mods == "all":
            return ALL_MODULES
        return mods

    def _print_brief(self, modules):
        """Print mission parameters."""
        mode_desc = SCAN_MODES.get(self.mode, {}).get("desc", "")
        print(f"\n{D}  {'─'*65}{X}")
        print(f"{R}  MISSION PARAMETERS{X}")
        print(f"{D}  {'─'*65}{X}")
        print(f"  {W}Target:{X}    {R}{self.url}{X}")
        print(f"  {W}Mode:{X}      {Y}{self.mode}{X} — {D}{mode_desc}{X}")
        print(f"  {W}Modules:{X}   {G}{', '.join(modules)}{X}")
        print(f"  {W}NDE:{X}       {'Enabled' if self.use_nde else 'Disabled'}")
        print(f"  {W}UI:{X}        {'Split terminal' if self.use_ui else 'Standard output'}")
        print(f"  {W}Output:{X}    {D}{self.output_dir}{X}")
        print(f"{D}  {'─'*65}{X}")

    def _run_installer(self, modules):
        """Run auto-installer for all required tools."""
        log("Checking and installing required tools...", "*")
        try:
            from core.installer import ToolInstaller

            # Map modules to required tools
            module_tools = {
                "recon":   ["nmap", "whatweb", "curl"],
                "dirs":    ["gobuster", "ffuf", "feroxbuster"],
                "sqli":    ["sqlmap"],
                "xss":     ["dalfox"],
                "cors":    [],
                "headers": [],
                "ports":   ["nmap", "masscan"],
                "api":     ["curl"],
                "auth":    ["hydra"],
                "info":    ["whatweb"],
                "lfi":     [],
                "ssrf":    [],
                "idor":    [],
                "rce":     [],
                "csrf":    [],
                "cookies": [],
            }

            # Collect needed tools
            needed = set()
            for mod in modules:
                needed.update(module_tools.get(mod, []))

            # Also need NDE tools
            if self.use_nde:
                needed.update(["nmap", "subfinder", "amass", "dnsx",
                               "ffuf", "gobuster", "whatweb", "nuclei"])

            installer = ToolInstaller(verbose=True)
            tool_status = installer.check_and_install_all(
                tools=list(needed)
            )

            if self.ui:
                available = sum(1 for s in tool_status.values()
                               if s.get("status") in ["available", "installed"])
                self.ui.log(f"Tools ready: {available}/{len(needed)}", "+", "installer")

            return tool_status

        except Exception as e:
            log(f"Installer error: {e} — continuing with built-in modules", "~")
            return {}

    def _start_ui(self):
        """Start the real-time console UI."""
        try:
            from core.console_ui import ConsoleUI
            self.ui = ConsoleUI()
            self.ui.update_stats(
                target=self.url,
                current_phase="Starting"
            )
            # Start UI in background thread
            self.ui_thread = self.ui.run_in_thread()
            time.sleep(0.3)
            self.ui.log(f"AmonStrike v4.0 started", "+")
            self.ui.log(f"Target: {self.url}", "i")
            log("Real-time UI started", "+")
        except Exception as e:
            log(f"UI error: {e} — falling back to standard output", "~")
            self.ui = None

    def _run_nde_engine(self):
        """Start the Never Dead-End engine in background."""
        try:
            from core.nde_engine import NeverDeadEndEngine

            self.nde = NeverDeadEndEngine(
                self.url,
                self.session_data,
                {},
                self.output_dir
            )

            # Monkey-patch NDE logging to go through UI
            original_log = self.nde._log
            def ui_log(msg, level="*"):
                original_log(msg, level)
                if self.ui:
                    self.ui.log(msg, level, "NDE")
            self.nde._log = ui_log

            # Monkey-patch NDE add_finding to go through UI
            original_finding = self.nde.add_finding
            def ui_finding(*args, **kwargs):
                f = original_finding(*args, **kwargs)
                if self.ui and f:
                    self.ui.add_finding(
                        f.get("title", ""),
                        f.get("severity", "INFO"),
                        f.get("module", "nde"),
                        f.get("url", "")
                    )
                return f
            self.nde.add_finding = ui_finding

            # Monkey-patch add_node to update UI graph
            original_node = self.nde.add_node
            def ui_node(node_type, value, source=None, metadata=None):
                node = original_node(node_type, value, source, metadata)
                if self.ui and node:
                    self.ui.add_graph_node(
                        node.id, node_type, value, source
                    )
                    self.ui.update_stats(nodes=self.nde.stats["nodes_created"])
                return node
            self.nde.add_node = ui_node

            # Run NDE in background thread
            if self.ui:
                self.ui.update_stats(current_phase="NDE Recon")

            def nde_runner():
                try:
                    findings = self.nde.run(self.url)
                    self.results["nde"] = {"findings": findings, "info": {}}
                    if self.ui:
                        self.ui.update_stats(
                            dead_ends=self.nde.stats["dead_ends_hit"]
                        )
                        self.ui.log(
                            f"NDE complete — {len(findings)} findings, "
                            f"{self.nde.stats['dead_ends_hit']} dead-ends escaped",
                            "+"
                        )
                except Exception as e:
                    if self.ui:
                        self.ui.log(f"NDE error: {e}", "!")
                    log(f"NDE error: {e}", "!")

            nde_thread = threading.Thread(target=nde_runner, daemon=True)
            nde_thread.start()
            log("Never Dead-End Engine started in background", "+")

        except Exception as e:
            log(f"NDE startup error: {e}", "~")

    def _run_modules(self, modules, tool_status, bypass_headers=None):
        """Run all scan modules, feeding findings to UI live."""
        total = len(modules)
        if self.ui:
            self.ui.update_stats(current_phase="Module Scanning")

        log(f"Running {total} modules against {self.url}", "+")

        for i, module_name in enumerate(modules, 1):
            if self._stop.is_set():
                break

            if self.ui:
                self.ui.update_stats(
                    current_phase=f"Module {i}/{total}: {module_name}",
                    current_tool=module_name
                )
                self.ui.log(
                    f"[{i}/{total}] Running module: {module_name}", "*",
                    tool=module_name
                )
            else:
                log(f"[{i}/{total}] Running module: {module_name}", "*")

            try:
                module_result = self._run_single_module(
                    module_name, tool_status
                )
                self.results[module_name] = module_result

                # Feed findings to UI live
                for finding in module_result.get("findings", []):
                    if self.ui:
                        self.ui.add_finding(
                            finding.get("title", ""),
                            finding.get("severity", "INFO"),
                            finding.get("module", module_name),
                            finding.get("url", self.url)
                        )
                        # Add vulnerability nodes to graph
                        if finding.get("severity") in ["CRITICAL", "HIGH"]:
                            self.ui.add_graph_node(
                                f"vuln_{len(self.all_findings)}",
                                "vulnerability",
                                finding.get("title", "")[:40],
                            )

                n_findings = len(module_result.get("findings", []))
                msg = f"Module {module_name} complete — {n_findings} findings"
                if self.ui:
                    self.ui.log(msg, "+" if n_findings else "*",
                               tool=module_name)
                else:
                    log(msg, "+" if n_findings else "*")

            except Exception as e:
                err_msg = f"Module {module_name} error: {e}"
                if self.ui:
                    self.ui.log(err_msg, "!")
                else:
                    log(err_msg, "!")
                self.results[module_name] = {"findings": [], "errors": [str(e)]}

    def _run_single_module(self, name, tool_status):
        """Load and run a single module."""
        module_map = {
            "recon":   ("modules.recon",   "ReconModule"),
            "headers": ("modules.headers", "HeadersModule"),
            "sqli":    ("modules.sqli",    "SqliModule"),
            "xss":     ("modules.xss",     "XssModule"),
            "csrf":    ("modules.csrf",    "CsrfModule"),
            "cors":    ("modules.cors",    "CorsModule"),
            "cookies": ("modules.cookies", "CookiesModule"),
            "dirs":    ("modules.dirs",    "DirModule"),
            "lfi":     ("modules.lfi",     "LfiModule"),
            "ssrf":    ("modules.ssrf",    "SsrfModule"),
            "idor":    ("modules.idor",    "IdorModule"),
            "rce":     ("modules.rce",     "RceModule"),
            "auth":    ("modules.auth",    "AuthModule"),
            "api":     ("modules.api",     "ApiModule"),
            "info":    ("modules.info",    "InfoModule"),
            "ports":       ("modules.ports",       "PortModule"),
            "osint":       ("modules.osint",       "OsintModule"),
            "waf":         ("modules.waf",         "WafModule"),
            "takeover":    ("modules.takeover",    "TakeoverModule"),
            "credentials": ("modules.credentials", "CredentialModule"),
            "ssti":        ("modules.ssti",        "SstiModule"),
            "jwt_deep":    ("modules.jwt_deep",    "JwtDeepModule"),
            "race_condition":("modules.race_condition","RaceConditionModule"),
            "http_smuggling":("modules.http_smuggling","HttpSmugglingModule"),
            "xxe":         ("modules.xxe",         "XxeModule"),
            "graphql_deep":    ("modules.graphql_deep",    "GraphqlDeepModule"),
            "oauth":           ("modules.oauth",           "OauthModule"),
            "business_logic":  ("modules.business_logic",  "BusinessLogicModule"),
            "cache_poison":    ("modules.cache_poison",    "CachePoisonModule"),
            "deserialization": ("modules.deserialization", "DeserializationModule"),
            "open_redirect":   ("modules.open_redirect",   "OpenRedirectModule"),
            "rate_limit":      ("modules.rate_limit",       "RateLimitModule"),
            "twofa_bypass":    ("modules.twofa_bypass",     "TwofaBypassModule"),
            "file_upload": ("modules.file_upload", "FileUploadModule"),
            "nosql_injection": ("modules.nosql_injection", "NosqlInjectionModule"),
            "clickjacking": ("modules.clickjacking", "ClickjackingModule"),
            "ssl_tls": ("modules.ssl_tls", "SslTlsModule"),
            "error_disclosure": ("modules.error_disclosure", "ErrorDisclosureModule"),
            "vhost_enum": ("modules.vhost_enum", "VhostEnumModule"),
            "command_injection": ("modules.command_injection", "CommandInjectionModule"),
            "session_fixation": ("modules.session_fixation", "SessionFixationModule"),
            "email_injection": ("modules.email_injection", "EmailInjectionModule"),
            "formula_injection": ("modules.formula_injection", "FormulaInjectionModule"),
            "account_takeover": ("modules.account_takeover", "AccountTakeoverModule"),
            "csp_bypass": ("modules.csp_bypass", "CspBypassModule"),
            "firebase": ("modules.firebase", "FirebaseModule"),
            "websocket": ("modules.websocket", "WebsocketModule"),
            "parameter_pollution": ("modules.parameter_pollution", "ParameterPollutionModule"),
            "timing_attack": ("modules.timing_attack", "TimingAttackModule"),
            "saml_bypass": ("modules.saml_bypass", "SamlBypassModule"),
            "prototype_pollution": ("modules.prototype_pollution", "PrototypePollutionModule"),
        }

        if name not in module_map:
            return {"findings": [], "info": {}}

        mod_path, class_name = module_map[name]
        import importlib
        mod    = importlib.import_module(mod_path)
        cls    = getattr(mod, class_name)

        # Build kwargs - pass everything the module needs
        kwargs = {
            "url":              self.url,
            "timeout":          getattr(self.args, "timeout", 10),
            "cookies":          self._parse_cookies(),
            "headers":          self._parse_headers(),
            "proxy":            getattr(self.args, "proxy", None),
            "scope_validator":  getattr(self, "_scope_validator", None),
            "bypass_headers":   tool_status.get("bypass_headers", {}),
        }

        # Add extra endpoints from recon if available
        recon_data = self.results.get("recon", {})
        if recon_data.get("endpoints"):
            kwargs["extra_endpoints"] = recon_data["endpoints"]
        if recon_data.get("forms"):
            kwargs["extra_forms"] = recon_data["forms"]

        try:
            instance = cls(**kwargs)
        except TypeError:
            # Fallback: old-style init
            instance = cls(self.url, timeout=kwargs["timeout"],
                          cookies=kwargs["cookies"],
                          headers=kwargs["headers"])

        result = instance.run()

        # Save findings to database immediately
        try:
            if hasattr(self, "_db") and self._db:
                for finding in result.get("findings", []):
                    self._db.save_finding(
                        self._scan_id,
                        finding.get("title", ""),
                        finding.get("severity", "INFO"),
                        finding.get("url", self.url),
                        finding.get("module", name),
                        finding.get("description", ""),
                        finding.get("evidence", ""),
                        finding.get("remediation", ""),
                        finding.get("payload", ""),
                        finding.get("parameter", ""),
                    )
        except Exception:
            pass

        # Update ProfessionalUI
        try:
            if hasattr(self, "pro_ui") and self.pro_ui:
                self.pro_ui.update_module(name)
                for finding in result.get("findings", []):
                    self.pro_ui.alert(finding)
                    self.pro_ui.finding_added(finding)
        except Exception:
            pass

        # Save state for resume capability
        try:
            if hasattr(self, "_scan_state"):
                self._scan_state.mark_complete(name, result)
        except Exception:
            pass
        return result

    def _merge_findings(self):
        """Merge all findings from all sources."""
        seen = set()
        for mod_name, result in self.results.items():
            for f in result.get("findings", []):
                key = (f.get("title",""), f.get("url",""))
                if key not in seen:
                    seen.add(key)
                    self.all_findings.append(f)

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.all_findings.sort(
            key=lambda f: sev_order.get(f.get("severity","INFO"), 4)
        )

        if self.ui:
            self.ui.update_stats(current_phase="Generating Report")
            self.ui.log(
                f"Total findings (deduplicated): {len(self.all_findings)}", "+"
            )
        else:
            log(f"Total findings: {len(self.all_findings)}", "+")

    def _generate_report(self, modules):
        """Generate professional HTML + JSON + Markdown reports."""
        log("Generating reports...", "*")
        try:
            from reports.generator import ReportGenerator
            import time as _time

            scan_id = getattr(self, "_scan_id",
                f"{int(_time.time())}_{self.url.split('//')[-1].split('/')[0]}")
            gen = ReportGenerator(scan_id, self.url, str(self.output_dir))

            for mod_result in self.results.values():
                if isinstance(mod_result, dict):
                    gen.add_findings(mod_result.get("findings", []))

            for chain in getattr(self, "_chains", []):
                gen.add_chain(chain)

            paths = gen.generate_all()
            self.html_report = paths.get("html", "")
            self.pdf_report  = None
            self.json_report = paths.get("json", "")
            self.md_report   = paths.get("md",   "")

            log(f"HTML report: {self.html_report}", "+")
            log(f"JSON report: {self.json_report}", "+")
            self._notify_slack()

        except Exception as e:
            import traceback
            log(f"Report error: {e}", "!")
            self.html_report = None

    def _notify_slack(self):
        """Send Slack/webhook notification on CRITICAL findings."""
        try:
            webhook = self.config.get("output","slack_webhook") if hasattr(self,"config") else ""
            if not webhook:
                return
            crits = [f for f in self.all_findings if f.get("severity")=="CRITICAL"]
            if not crits:
                return
            import requests as _req
            text = (f"*AmonStrike CRITICAL findings on {self.url}*\n"
                    + "\n".join(f"* {f.get('title','')}" for f in crits[:5]))
            _req.post(webhook, json={"text": text}, timeout=5)
            log("Slack notification sent", "+")
        except Exception:
            pass

    def _print_summary(self):
        """Print final summary to terminal."""
        if self.ui:
            self.ui.stop()
            time.sleep(0.5)

        # Count by severity
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.all_findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = (counts["CRITICAL"] * 10 + counts["HIGH"] * 7 +
                      counts["MEDIUM"] * 4 + counts["LOW"] * 1)

        risk_level = (
            "CRITICAL" if risk_score >= 20 else
            "HIGH"     if risk_score >= 10 else
            "MEDIUM"   if risk_score >= 5  else
            "LOW"      if risk_score >= 1  else
            "CLEAN"
        )

        print()
        print(f"{D}  ════════════════════════════════════════════════════════{X}")
        print(f"{R}{BLD}  AMONSTRIKE COMPLETE{X}")
        print(f"{D}  ════════════════════════════════════════════════════════{X}")
        print()
        print(f"  {W}Target:{X}       {self.url}")
        print(f"  {W}Risk Level:{X}   {R if risk_level in ['CRITICAL','HIGH'] else Y}{risk_level}{X}")
        print(f"  {W}Risk Score:{X}   {risk_score}")
        print()
        print(f"  {W}Findings:{X}")
        print(f"    {R}Critical: {counts['CRITICAL']}{X}  "
              f"{R}High: {counts['HIGH']}{X}  "
              f"{Y}Medium: {counts['MEDIUM']}{X}  "
              f"{G}Low: {counts['LOW']}{X}  "
              f"{C}Info: {counts['INFO']}{X}")
        print()

        if self.nde:
            print(f"  {W}NDE Stats:{X}")
            print(f"    Nodes processed: {self.nde.stats['nodes_processed']}")
            print(f"    Dead-ends escaped: {self.nde.stats['dead_ends_hit']}")
            print(f"    Tools used: {', '.join(self.nde.stats['tools_used']) or 'built-in only'}")
            print()

        print(f"  {W}Reports:{X}")
        if self.html_report:
            print(f"    {C}HTML:{X} {self.html_report}")
        if self.pdf_report:
            print(f"    {C}PDF: {X} {self.pdf_report}")
        print(f"    {C}JSON:{X} {self.output_dir}/findings.json")
        print()

        # Top findings
        top = [f for f in self.all_findings
               if f.get("severity") in ["CRITICAL","HIGH"]][:5]
        if top:
            print(f"  {W}Top Findings:{X}")
            for f in top:
                sev = f.get("severity","")
                c = R if sev in ["CRITICAL","HIGH"] else Y
                print(f"    {c}[{sev}]{X} {f.get('title','')[:60]}")
            print()

        if self.html_report:
            print(f"  {D}Open report:{X} firefox {self.html_report}")
        print(f"{D}  ════════════════════════════════════════════════════════{X}\n")

    def _run_intelligence(self):
        """Run Level 1/2/3 intelligence engine."""
        try:
            from intelligence.orchestrator import IntelligenceOrchestrator
            log("Running intelligence engine (WAF + ASN + GitHub + JS)...", "*")
            orch = IntelligenceOrchestrator(
                self.url,
                output_dir=str(self.output_dir / "intelligence"),
                github_token=getattr(self.args, "github_token", None),
            )
            results = orch.run_all(parallel=True)
            # Add intelligence findings to main findings
            for finding in results.get("findings", []):
                module = finding.get("module", "intel")
                if module not in self.results:
                    self.results[module] = {"findings": []}
                self.results[module]["findings"].append(finding)
            log(f"Intelligence complete: {len(results.get('findings',[]))} findings", "+")
            return results
        except Exception as e:
            log(f"Intelligence engine error: {e}", "~")
            return {}

    def _run_chain_engine(self):
        """Run chain engine on all collected findings."""
        try:
            from intelligence.chain_engine import ChainEngine
            all_findings = []
            for module_results in self.results.values():
                if isinstance(module_results, dict):
                    all_findings.extend(module_results.get("findings", []))
            
            if not all_findings:
                return []
            
            log(f"Running chain engine on {len(all_findings)} findings...", "*")
            engine = ChainEngine(self.url)
            chains = engine.analyze(all_findings)
            
            if chains:
                log(f"Chains found: {len(chains)} (escalated findings)", "!")
                for chain in chains:
                    if "chain" not in self.results:
                        self.results["chain"] = {"findings": []}
                    self.results["chain"]["findings"].append({
                        "title":       f"CHAIN: {chain['name']}",
                        "severity":    chain["severity"],
                        "module":      "chain",
                        "url":         chain.get("trigger_url", self.url),
                        "description": chain.get("impact", ""),
                        "evidence":    "\n".join(chain.get("steps", [])),
                        "remediation": "Fix triggering vulnerability",
                        "chain_data":  chain,
                    })
            return chains
        except Exception as e:
            log(f"Chain engine error: {e}", "~")
            return []

    def _run_screenshots(self):
        """Capture screenshots of all CRITICAL/HIGH findings."""
        try:
            from verify.screenshot import ScreenshotEngine
            all_findings = []
            for module_results in self.results.values():
                if isinstance(module_results, dict):
                    for f in module_results.get("findings", []):
                        if f.get("severity") in ["CRITICAL","HIGH"]:
                            all_findings.append(f)
            
            if not all_findings:
                return
            
            log(f"Capturing screenshots for {len(all_findings)} findings...", "*")
            shot_dir = str(self.output_dir / "screenshots")
            with ScreenshotEngine(shot_dir, self.url) as eng:
                for finding in all_findings[:10]:  # Limit to 10
                    try:
                        shots = eng.capture_finding(finding)
                        finding["screenshots"] = shots
                    except Exception:
                        pass
            log("Screenshots captured", "+")
        except Exception as e:
            log(f"Screenshot error: {e}", "~")

    def _run_waf_bypass(self):
        """Detect WAF and return bypass headers to inject into base modules."""
        try:
            from intelligence.waf_engine import WAFIntelligence, WAFBypassEngine
            log("Checking for WAF...", "*")
            waf = WAFIntelligence(self.url)
            result = waf.full_analysis()
            
            if result.get("origin_ips"):
                log(f"Origin IP found: {result['origin_ips'][0]} — bypassing WAF", "!")
                # Could redirect all traffic to origin IP
            
            if result.get("waf"):
                log(f"WAF detected: {result['waf']} — applying bypass headers", "!")
                byp = WAFBypassEngine()
                return byp.x_forwarded_for_bypass()
            
            return {}
        except Exception as e:
            log(f"WAF bypass error: {e}", "~")
            return {}


    def _handle_interrupt(self, sig, frame):
        """Handle Ctrl+C gracefully."""
        print(f"\n\n{Y}[~] Interrupted — generating partial report...{X}\n")
        self._stop.set()
        if self.ui:
            self.ui.stop()
        self._merge_findings()
        modules = self._resolve_modules()
        self._generate_report(modules)
        self._print_summary()
        sys.exit(0)



def run_recon_pipeline(domain: str, output_dir: str = "output/recon"):
    """Run the full ProjectDiscovery recon pipeline."""
    from recon.pipeline import ReconPipeline
    pipe = ReconPipeline(domain, output_dir)
    return pipe.run()

def run_monitor(domains: list, interval: int = 3600):
    """Start the continuous recon monitor."""
    from recon.monitor import ReconMonitor
    mon = ReconMonitor()
    for domain in domains:
        mon.add_target(domain, scan_interval=interval)
    mon.start(daemon=False)

def run_idor_scan(target: str, credentials: list = None):
    """Run authenticated IDOR scan."""
    from recon.auth_engine import SessionManager, IDORScanner
    sm = SessionManager(target)
    if credentials:
        for cred in credentials:
            sm.add_user(cred["username"], cred["password"], cred.get("role","user"))
        sm.login_all()
    scanner = IDORScanner(target, sm)
    return scanner.scan()

def main():
    parser = argparse.ArgumentParser(
        description="AmonStrike v4.0 — Never Dead-End Bug Bounty Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Modes:
  fast    Quick scan — essential checks only (~5 min)
  normal  Standard scan — all modules (~15 min)  [default]
  deep    Deep scan — all modules + NDE + tool chaining (~45 min)
  nde     Never Dead-End autonomous recon

Examples:
  sudo python3 amonstrike.py
  sudo python3 amonstrike.py --url http://192.168.178.149/dvwa
  sudo python3 amonstrike.py --url http://target.com --mode deep
  sudo python3 amonstrike.py --url http://target.com --modules sqli,xss,cors
  sudo python3 amonstrike.py --url http://target.com --no-ui --mode fast
        """
    )

    parser.add_argument("--url",      help="Target URL")
    parser.add_argument("--mode",     default="normal",
                        choices=["fast","normal","deep","nde"],
                        help="Scan mode (default: normal)")
    parser.add_argument("--modules",  help="Specific modules (comma-separated or 'all')")
    parser.add_argument("--no-ui",    action="store_true",
                        help="Disable real-time console UI")
    parser.add_argument("--no-nde",   action="store_true",
                        help="Disable Never Dead-End engine")
    parser.add_argument("--timeout",  type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads",  type=int, default=10,
                        help="Number of threads (default: 10)")
    parser.add_argument("--proxy",    help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookies",  help="Cookie string")
    parser.add_argument("--headers",  help="Extra headers as JSON string")
    parser.add_argument("--wordlist", help="Custom wordlist for directory enumeration")
    parser.add_argument("--output",   help="Output directory (default: output/)")
    parser.add_argument("--intel",     action="store_true",
                        help="Run intelligence engine (WAF + ASN + GitHub + JS analysis)")
    parser.add_argument("--recon",     action="store_true",
                        help="Run ProjectDiscovery recon pipeline (subfinder→dnsx→httpx→katana→nuclei)")
    parser.add_argument("--chain",     action="store_true", default=True,
                        help="Run chain engine on findings (default: True)")
    parser.add_argument("--no-chain",  action="store_true",
                        help="Disable chain engine")
    parser.add_argument("--waf-bypass",action="store_true",
                        help="Auto-detect WAF and apply bypass headers/payloads")
    parser.add_argument("--credentials",help="Auth credentials JSON: [{username,password,role}]")
    parser.add_argument("--github-token", help="GitHub API token for secret scanning")
    parser.add_argument("--multi-shell", action="store_true",
                        help="Open separate terminal panes for verbose output")
    parser.add_argument("--config",    help="Config file (~/.amonstrike/config.yml)")

    args = parser.parse_args()

    scanner = AmonStrike(args)
    scanner.run()


if __name__ == "__main__":
    main()
