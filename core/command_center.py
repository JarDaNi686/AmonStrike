#!/usr/bin/env python3
"""
AmonStrike — Command Center TUI
Rich terminal dashboard. Run standalone: python core/command_center.py
"""
import time, json, threading
from pathlib import Path
from collections import deque

try:
    from rich.console import Console
    from rich.table   import Table
    from rich.panel   import Panel
    from rich.layout  import Layout
    from rich.live    import Live
    from rich.text    import Text
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

FINDINGS_FILE = Path("data/findings.jsonl")
LOG_FILE      = Path("data/amonstrike.log")
SCAN_LOG_FILE = Path("data/scan_log.jsonl")

console = Console()


def sev_color(sev: str) -> str:
    return {"CRITICAL":"red", "HIGH":"orange1",
            "MEDIUM":"yellow", "LOW":"cyan", "INFO":"white"}.get(sev.upper(), "white")


class CommandCenter:
    def __init__(self):
        self.findings   = deque(maxlen=200)
        self.logs       = deque(maxlen=50)
        self.stats      = {"total": 0, "critical": 0, "high": 0,
                           "medium": 0, "low": 0, "targets_scanned": 0}
        self.current    = "idle"
        self._stop      = threading.Event()
        self._load()

    def _load(self):
        if FINDINGS_FILE.exists():
            for line in FINDINGS_FILE.read_text().splitlines()[-200:]:
                try:
                    f = json.loads(line)
                    self.findings.append(f)
                    self.stats["total"] += 1
                    sev = f.get("severity","LOW").upper()
                    key = sev.lower()
                    if key in self.stats:
                        self.stats[key] += 1
                except Exception:
                    pass
        if LOG_FILE.exists():
            for line in LOG_FILE.read_text().splitlines()[-50:]:
                self.logs.append(line)

    def add_finding(self, finding: dict):
        self.findings.append(finding)
        self.stats["total"] += 1
        sev = finding.get("severity","LOW").lower()
        if sev in self.stats:
            self.stats[sev] += 1
        with open(FINDINGS_FILE, "a") as fh:
            fh.write(json.dumps(finding) + "\n")

    def log(self, msg: str):
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.logs.append(entry)
        with open(LOG_FILE, "a") as fh:
            fh.write(entry + "\n")

    def _build_stats_panel(self) -> Panel:
        t = Table.grid(expand=True)
        t.add_column(justify="left")
        t.add_column(justify="right")
        t.add_row("Total Findings", str(self.stats["total"]))
        t.add_row("[red]CRITICAL[/red]", str(self.stats["critical"]))
        t.add_row("[orange1]HIGH[/orange1]",     str(self.stats["high"]))
        t.add_row("[yellow]MEDIUM[/yellow]",  str(self.stats["medium"]))
        t.add_row("[cyan]LOW[/cyan]",     str(self.stats["low"]))
        t.add_row("Targets",  str(self.stats["targets_scanned"]))
        return Panel(t, title="[bold]Stats[/bold]", border_style="blue")

    def _build_findings_table(self) -> Table:
        tbl = Table(title="Latest Findings", show_header=True,
                    header_style="bold magenta", box=None)
        tbl.add_column("Sev",  width=8)
        tbl.add_column("Type", width=20)
        tbl.add_column("URL",  width=50)
        tbl.add_column("Info", width=30)
        for f in list(self.findings)[-15:]:
            sev  = f.get("severity", "LOW")
            col  = sev_color(sev)
            tbl.add_row(
                f"[{col}]{sev}[/{col}]",
                f.get("type",""),
                f.get("url","")[:50],
                str(f.get("detail",""))[:30],
            )
        return tbl

    def _build_log_panel(self) -> Panel:
        lines = "\n".join(list(self.logs)[-10:])
        return Panel(lines or "No logs yet.", title="[bold]Activity Log[/bold]",
                     border_style="green")

    def _build_status(self) -> Text:
        t = Text()
        t.append("● AmonStrike v2 ", style="bold red")
        t.append(f"| Status: {self.current} ", style="white")
        t.append(f"| {time.strftime('%H:%M:%S')}", style="dim")
        return t

    def run(self):
        if not HAS_RICH:
            print("[AmonStrike] Install rich: pip install rich")
            return

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=1),
            Layout(name="body"),
            Layout(name="footer", size=5),
        )
        layout["body"].split_row(
            Layout(name="stats",    ratio=1),
            Layout(name="findings", ratio=3),
        )

        with Live(layout, refresh_per_second=2, screen=True):
            while not self._stop.is_set():
                self._load()
                layout["header"].update(self._build_status())
                layout["stats"].update(self._build_stats_panel())
                layout["findings"].update(
                    Panel(self._build_findings_table(), border_style="magenta"))
                layout["footer"].update(self._build_log_panel())
                time.sleep(0.5)

    def stop(self):
        self._stop.set()


if __name__ == "__main__":
    cc = CommandCenter()
    try:
        cc.run()
    except KeyboardInterrupt:
        cc.stop()
