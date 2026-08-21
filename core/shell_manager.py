"""
AmonStrike — Multi-Shell Terminal Manager
Professional UX: right information in the right shell.

Main shell:    Target info + progress % + finding counts + CRITICAL alerts only
Shell 2:       Intelligence/recon verbose output (background)
Shell 3:       Attack module output (background)
Shell 4:       Live findings stream (color-coded by severity)

Detection:     tmux (preferred) → gnome-terminal → xterm → log files
"""

import os
import sys
import time
import queue
import shutil
import threading
import subprocess
from datetime import datetime
from typing import Optional, Callable

# ── Colors ────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"
C="\033[96m"; W="\033[97m"; D="\033[90m"
B="\033[94m"; M="\033[95m"; X="\033[0m"
BOLD="\033[1m"

SEV_COLOR = {
    "CRITICAL": R, "HIGH": Y, "MEDIUM": C,
    "LOW":      G, "INFO": D,
}


class ShellManager:
    """
    Manages multiple terminal panes for clean output separation.
    Detects available terminal multiplexer and uses it.
    """

    def __init__(self, target: str, output_dir: str = "output"):
        self.target     = target
        self.output_dir = output_dir
        self.session    = f"amonstrike_{int(time.time())}"
        self._backend   = self._detect_backend()
        self._panes     = {}  # name → pane_id or log_file
        self._queues    = {
            "recon":    queue.Queue(),
            "attack":   queue.Queue(),
            "findings": queue.Queue(),
        }
        self._threads   = []
        self._running   = False

        os.makedirs(output_dir, exist_ok=True)

    def _detect_backend(self) -> str:
        """Detect available terminal backend."""
        if shutil.which("tmux"):
            return "tmux"
        elif shutil.which("gnome-terminal"):
            return "gnome"
        elif shutil.which("xterm"):
            return "xterm"
        else:
            return "logfile"

    def start(self, multi_shell: bool = True):
        """Start the multi-shell environment."""
        self._running = True

        if multi_shell and self._backend == "tmux":
            self._setup_tmux()
        elif multi_shell and self._backend in ["gnome","xterm"]:
            self._setup_external_terminals()
        else:
            self._setup_logfiles()

        # Start dispatch threads
        for stream in ["recon","attack","findings"]:
            t = threading.Thread(
                target=self._dispatch_loop,
                args=(stream,),
                daemon=True
            )
            t.start()
            self._threads.append(t)

    def _setup_tmux(self):
        """Create tmux session with 4 panes."""
        try:
            # Kill existing session if any
            subprocess.run(
                ["tmux","kill-session","-t",self.session],
                capture_output=True
            )
            # Create new session (main pane)
            subprocess.run([
                "tmux","new-session","-d","-s",self.session,
                "-x","220","-y","50"
            ], check=True)

            # Split: right pane for findings
            subprocess.run([
                "tmux","split-window","-h","-t",self.session,
                "-p","35"
            ])

            # Split top-right for recon
            subprocess.run([
                "tmux","split-window","-v","-t",f"{self.session}:0.1",
                "-p","50"
            ])

            # Split top-left for attacks
            subprocess.run([
                "tmux","split-window","-v","-t",f"{self.session}:0.0",
                "-p","40"
            ])

            # Label each pane
            labels = {
                "0.0": "MAIN — AmonStrike v4.0",
                "0.1": "ATTACK MODULES",
                "0.2": "RECON / INTELLIGENCE",
                "0.3": "LIVE FINDINGS",
            }
            for pane, label in labels.items():
                subprocess.run([
                    "tmux","send-keys","-t",f"{self.session}:{pane}",
                    f"echo '{self._banner(label)}'", "Enter"
                ])

            self._panes = {
                "main":     f"{self.session}:0.0",
                "attack":   f"{self.session}:0.1",
                "recon":    f"{self.session}:0.2",
                "findings": f"{self.session}:0.3",
            }

            # Attach to session
            print(f"\n{G}[+]{X} tmux session: {W}tmux attach -t {self.session}{X}")
            print(f"{G}[+]{X} Or: {W}tmux attach{X}\n")

        except Exception as e:
            print(f"{Y}[~]{X} tmux setup failed: {e} — falling back to log files")
            self._setup_logfiles()

    def _setup_external_terminals(self):
        """Open separate terminal windows."""
        log_dir = os.path.join(self.output_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        for stream in ["recon","attack","findings"]:
            log_path = os.path.join(log_dir, f"{stream}.log")
            # Create log file
            open(log_path,"w").close()
            # Tail in new terminal
            title = {
                "recon":    "AmonStrike — Recon/Intelligence",
                "attack":   "AmonStrike — Attack Modules",
                "findings": "AmonStrike — Live Findings",
            }[stream]

            try:
                if self._backend == "xterm":
                    subprocess.Popen([
                        "xterm","-title",title,
                        "-geometry","120x40",
                        "-e",f"tail -f {log_path}"
                    ])
                elif self._backend == "gnome":
                    subprocess.Popen([
                        "gnome-terminal","--title",title,
                        "--","bash","-c",f"tail -f {log_path}; read"
                    ])
                self._panes[stream] = log_path
            except Exception:
                self._panes[stream] = log_path

        print(f"{G}[+]{X} Separate terminals launched for recon/attack/findings")

    def _setup_logfiles(self):
        """Fall back to log files."""
        log_dir = os.path.join(self.output_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        for stream in ["recon","attack","findings"]:
            self._panes[stream] = os.path.join(log_dir, f"{stream}.log")
        print(f"{Y}[~]{X} No terminal multiplexer — verbose output → {log_dir}/")

    def _banner(self, title: str) -> str:
        return f"{'='*60}\\n  {title}\\n{'='*60}"

    def send(self, stream: str, message: str):
        """Send message to a stream (non-blocking)."""
        self._queues.get(stream, self._queues["attack"]).put(message)

    def _dispatch_loop(self, stream: str):
        """Dispatch messages to appropriate pane/log."""
        pane = self._panes.get(stream)
        while self._running:
            try:
                msg = self._queues[stream].get(timeout=0.5)
                if pane:
                    if self._backend == "tmux" and stream in self._panes:
                        # Send to tmux pane
                        safe_msg = msg.replace("'","\\'").replace("\n","\\n")
                        subprocess.run([
                            "tmux","send-keys","-t",pane,
                            f"echo '{safe_msg}'","Enter"
                        ], capture_output=True)
                    else:
                        # Write to log file
                        try:
                            with open(pane,"a") as f:
                                f.write(msg + "\n")
                        except Exception:
                            pass
            except queue.Empty:
                continue

    def stop(self):
        """Stop all dispatch threads."""
        self._running = False
        for t in self._threads:
            t.join(timeout=2)


class ProfessionalUI:
    """
    Clean main-shell UI showing only what matters:
      - Target + scan config
      - Module progress bar
      - Finding counts by severity
      - CRITICAL/HIGH alerts (immediately)
      - Summary on completion
    """

    WIDTH = 70  # Console width

    def __init__(self, target: str, modules: list,
                 shell_mgr: Optional[ShellManager] = None):
        self.target    = target
        self.modules   = modules
        self.total     = len(modules)
        self.completed = 0
        self.current   = ""
        self.shell_mgr = shell_mgr
        self._lock     = threading.Lock()
        self._start    = time.time()
        self._counts   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
        self._findings = []

    def start(self):
        """Print professional header."""
        elapsed = ""
        print(f"\n{D}{'═'*self.WIDTH}{X}")
        print(f"{R}{BOLD}  ⚡ AMONSTRIKE v4.0{X}{D} — Hidden Recon. Precise Strike. Proof.{X}")
        print(f"{D}{'─'*self.WIDTH}{X}")
        print(f"  {W}Target{X}    {C}{self.target}{X}")
        print(f"  {W}Modules{X}   {D}{len(self.modules)} total{X}")
        print(f"  {W}Started{X}   {D}{datetime.now().strftime('%H:%M:%S')}{X}")
        if self.shell_mgr and self.shell_mgr._backend == "tmux":
            print(f"  {W}View{X}      {G}tmux attach -t {self.shell_mgr.session}{X}")
        print(f"{D}{'─'*self.WIDTH}{X}\n")

    def update_module(self, module_name: str):
        """Update current module being run."""
        with self._lock:
            self.current   = module_name
            self.completed += 1
            self._render_progress()

    def _render_progress(self):
        """Render clean progress bar."""
        pct   = int(self.completed / max(self.total, 1) * 100)
        filled = int(pct / 100 * 40)
        bar   = f"{G}{'█'*filled}{D}{'░'*(40-filled)}{X}"
        eta   = self._estimate_eta()

        # Clear line and render
        print(f"\r  {bar} {W}{pct}%{X} {D}[{self.current}]{X} {Y}{eta}{X}", end="", flush=True)

    def _estimate_eta(self) -> str:
        """Estimate remaining time."""
        elapsed   = time.time() - self._start
        remaining = self.total - self.completed
        if self.completed == 0:
            return ""
        per_module = elapsed / self.completed
        eta_secs   = int(per_module * remaining)
        if eta_secs > 60:
            return f"~{eta_secs//60}m remaining"
        return f"~{eta_secs}s remaining"

    def alert(self, finding: dict):
        """Display CRITICAL/HIGH findings immediately on main shell."""
        sev = finding.get("severity","")
        if sev not in ["CRITICAL","HIGH"]:
            return  # Others go to findings stream silently

        with self._lock:
            self._counts[sev] = self._counts.get(sev,0) + 1
            self._findings.append(finding)

        color = R if sev == "CRITICAL" else Y
        title = finding.get("title","")[:55]
        url   = finding.get("url","")[:50]

        # Print alert on new line (interrupt progress bar)
        print(f"\n\n  {color}{BOLD}[{sev}]{X} {W}{title}{X}")
        print(f"         {D}{url}{X}")

        # Send full detail to findings stream
        if self.shell_mgr:
            detail = (
                f"[{sev}] {finding.get('title','')}\n"
                f"URL: {finding.get('url','')}\n"
                f"Evidence: {finding.get('evidence','')[:200]}\n"
                f"{'─'*50}"
            )
            self.shell_mgr.send("findings", detail)

    def finding_added(self, finding: dict):
        """Track all findings regardless of severity."""
        sev = finding.get("severity","INFO")
        with self._lock:
            self._counts[sev] = self._counts.get(sev, 0) + 1

        # Send to findings stream
        if self.shell_mgr:
            msg = (
                f"[{finding.get('severity','')}] "
                f"{finding.get('title','')} | "
                f"{finding.get('url','')[:60]}"
            )
            self.shell_mgr.send("findings", msg)

    def recon_log(self, msg: str):
        """Send recon/intelligence output to background shell."""
        if self.shell_mgr:
            self.shell_mgr.send("recon", msg)
        # Also write to log regardless

    def attack_log(self, msg: str):
        """Send attack module output to background shell."""
        if self.shell_mgr:
            self.shell_mgr.send("attack", msg)

    def complete(self, output_path: str = ""):
        """Print completion summary."""
        elapsed = int(time.time() - self._start)
        total   = sum(self._counts.values())

        print(f"\n\n{D}{'─'*self.WIDTH}{X}")
        print(f"{G}{BOLD}  ✓ SCAN COMPLETE{X} {D}({elapsed}s){X}")
        print(f"{D}{'─'*self.WIDTH}{X}")

        # Severity breakdown
        for sev, count in self._counts.items():
            if count == 0:
                continue
            color = SEV_COLOR.get(sev, D)
            bar   = "█" * min(count, 30)
            print(f"  {color}{sev:<10}{X} {W}{count:>4}{X} {D}{bar}{X}")

        print(f"\n  {W}Total{X}      {W}{total}{X}")
        if output_path:
            print(f"  {W}Report{X}     {C}{output_path}{X}")
        print(f"{D}{'═'*self.WIDTH}{X}\n")

        # Top findings
        crits = [f for f in self._findings if f.get("severity")=="CRITICAL"]
        if crits:
            print(f"{R}  TOP CRITICAL FINDINGS:{X}")
            for f in crits[:5]:
                print(f"  {R}→{X} {f.get('title','')[:60]}")
            print()


def run_regression_tests():
    import tempfile
    print("\n=== MULTI-SHELL UI REGRESSION TESTS ===")
    passed = failed = 0
    tmp = tempfile.mkdtemp()

    mgr = ShellManager("http://testphp.vulnweb.com", tmp)
    ui  = ProfessionalUI(
        "http://testphp.vulnweb.com",
        ["sqli","xss","lfi","ssrf","cors"],
        shell_mgr=None
    )

    sample_finding = {
        "title":"SQL Injection","severity":"CRITICAL",
        "module":"sqli","url":"http://testphp.vulnweb.com/artists.php",
        "description":"SQLi confirmed","evidence":"MySQL error",
        "remediation":"Use prepared statements",
    }

    tests = [
        ("ShellManager instantiates",
         lambda: isinstance(mgr, ShellManager)),

        ("Backend detected",
         lambda: mgr._backend in ["tmux","gnome","xterm","logfile"]),

        ("ProfessionalUI instantiates",
         lambda: isinstance(ui, ProfessionalUI)),

        ("Progress renders without crash",
         lambda: (ui.update_module("sqli") or True)),

        ("Alert method works",
         lambda: (ui.alert(sample_finding) or True)),

        ("Finding tracked in counts",
         lambda: ui._counts.get("CRITICAL",0) >= 1),

        ("finding_added increments count",
         lambda: (
             ui.finding_added({"severity":"HIGH","title":"XSS","url":"x","module":"xss","description":"","evidence":"","remediation":""}),
             ui._counts.get("HIGH",0) >= 1
         )[1]),

        ("Complete renders without crash",
         lambda: (ui.complete("/tmp/test_report.html") or True)),

        ("ETA estimate works",
         lambda: isinstance(ui._estimate_eta(), str)),

        ("Width constant set",
         lambda: ProfessionalUI.WIDTH >= 60),

        ("Queue system works",
         lambda: (
             mgr._queues["recon"].put("test"),
             not mgr._queues["recon"].empty()
         )[1]),

        ("Logfile setup works",
         lambda: (mgr._setup_logfiles() or True) and
                 len(mgr._panes) >= 3),

        ("SEV_COLOR has all severities",
         lambda: all(s in SEV_COLOR for s in
                    ["CRITICAL","HIGH","MEDIUM","LOW","INFO"])),
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
    rp, rf = run_regression_tests()
    __import__("sys").exit(0 if rf == 0 else 1)
