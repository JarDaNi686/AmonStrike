#!/usr/bin/env python3
"""
AmonStrike — Professional Hunt Launcher

Usage:
  python hunt.py                    # interactive target selector
  python hunt.py gocardless         # direct H1 handle
  python hunt.py --url https://...  # direct URL
  python hunt.py --install-tools    # install missing critical tools
  python hunt.py --tools-status     # show all Kali tool status
"""
import os, sys, json, time, argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.columns import Columns
    from rich.align import Align
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None

BANNER = r"""
    _                      ___  _        _ _
   / \   _ __ ___   ___  / _ \/ |_ _ __(_) | _____
  / _ \ | '_ ` _ \ / _ \| | | | | | '__| | |/ / _ \
 / ___ \| | | | | | (_) | |_| | | | |  | |   <  __/
/_/   \_\_| |_| |_|\___/ \___/|_|_|_|  |_|_|\_\___|
"""


def print_banner():
    if not HAS_RICH:
        print(BANNER)
        return
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(Panel(
        "[white]Elite Bug Bounty Hunting System[/white]\n"
        "[dim]Multi-AI · Full Kali Arsenal · Zero-Day Hunting · Quality-First[/dim]",
        border_style="red", padding=(0, 2)
    ))
    console.print()


def show_tools_status():
    from core.kali_tools import KaliToolsMaximizer
    km = KaliToolsMaximizer()
    km.print_status()


def install_tools():
    from core.kali_tools import KaliToolsMaximizer
    km = KaliToolsMaximizer()
    km.print_status()
    if HAS_RICH:
        console.print("\n[bold yellow]Installing missing critical tools...[/bold yellow]")
    results = km.install_missing_critical(dry_run=False)
    for name, status in results:
        icon = "[green]✓[/green]" if status == "ok" else "[red]✗[/red]"
        if HAS_RICH:
            console.print(f"  {icon} {name}: {status}")
        else:
            print(f"  {'OK' if status=='ok' else 'FAIL'} {name}")


def run_hunt(handle: str = None, url: str = None,
             auto_submit: bool = False, hours: float = 0,
             no_submit: bool = True):
    """
    Main hunt launcher.
    1. Select target (from selector or args)
    2. Show pre-flight tool check
    3. Launch autonomous engine
    """
    print_banner()

    # ── Step 1: Target selection ──────────────────────────────
    if handle or url:
        target = {
            "handle":      handle or url,
            "name":        handle or url,
            "target_url":  url or None,
            "auto_submit": auto_submit and not no_submit,
            "max_hours":   hours,
            "custom_url":  bool(url),
        }
    else:
        from core.h1_selector import H1Selector
        selector = H1Selector()
        target   = selector.run()
        if not target:
            if HAS_RICH:
                console.print("[yellow]No target selected. Exiting.[/yellow]")
            return

    program = target["handle"]
    if HAS_RICH:
        submit_txt   = "[red]AUTO-SUBMIT ON[/red]" if target.get("auto_submit") else "[green]MANUAL REVIEW[/green]"
        max_hours    = target.get("max_hours")
        duration_txt = "Unlimited" if not max_hours else f"{max_hours}h"
        console.print(Panel(
            f"[bold red]TARGET LOCKED[/bold red]\n"
            f"[white]Program:[/white] [bold cyan]{program}[/bold cyan]\n"
            f"[white]Submit:[/white]  {submit_txt}\n"
            f"[white]Duration:[/white] {duration_txt}",
            border_style="red",
        ))
        console.print()

    # ── Step 2: Tool pre-flight ───────────────────────────────
    from core.kali_tools import KaliToolsMaximizer
    km = KaliToolsMaximizer()
    report = km.status_report()
    available_count = len(report["available"])
    missing_critical = [t for t in report["missing"] if t in __import__('core.kali_tools', fromlist=['CRITICAL_TOOLS']).CRITICAL_TOOLS]

    if HAS_RICH:
        console.print(f"[dim]Tool preflight: [green]{available_count} ready[/green]"
                      f"  [yellow]{len(missing_critical)} critical missing[/yellow][/dim]")
        if missing_critical:
            console.print(f"[dim]Missing critical: {', '.join(missing_critical[:10])}[/dim]")
            from rich.prompt import Confirm
            if Confirm.ask("Auto-install missing critical tools now?", default=False):
                install_tools()
        console.print()

    # ── Step 3: Launch hunt ───────────────────────────────────
    if HAS_RICH:
        console.rule("[bold red]HUNT STARTED[/bold red]")
        console.print()

    from core.autonomous_engine import AutonomousEngine
    engine = AutonomousEngine(
        program     = program,
        max_hours   = target.get("max_hours", hours),
        auto_submit = target.get("auto_submit", False),
    )

    # Override target URL if custom
    if target.get("custom_url") and target.get("target_url"):
        engine._custom_target_url = target["target_url"]

    try:
        engine.run()
    except KeyboardInterrupt:
        if HAS_RICH:
            console.print("\n[yellow]Hunt interrupted by user.[/yellow]")
        else:
            print("\nInterrupted.")


def main():
    p = argparse.ArgumentParser(
        description="AmonStrike — Elite Bug Bounty Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python hunt.py                         # interactive target selector
  python hunt.py gocardless              # hunt gocardless program
  python hunt.py --url https://api.ex.com
  python hunt.py gocardless --hours 8
  python hunt.py --tools-status          # show all tool status
  python hunt.py --install-tools         # install missing tools
        """,
    )
    p.add_argument("program",          nargs="?",         help="H1 program handle")
    p.add_argument("--url",                               help="Direct target URL")
    p.add_argument("--hours",          type=float, default=0, help="Max hunt hours (0=unlimited)")
    p.add_argument("--no-submit",      action="store_true", help="Never auto-submit (default)")
    p.add_argument("--auto-submit",    action="store_true", help="Auto-submit CRITICAL/HIGH to H1")
    p.add_argument("--tools-status",   action="store_true", help="Show Kali tools status table")
    p.add_argument("--install-tools",  action="store_true", help="Install missing critical tools")
    args = p.parse_args()

    if args.tools_status:
        print_banner()
        show_tools_status()
        return

    if args.install_tools:
        print_banner()
        install_tools()
        return

    run_hunt(
        handle      = args.program,
        url         = args.url,
        auto_submit = args.auto_submit,
        hours       = args.hours,
        no_submit   = args.no_submit or not args.auto_submit,
    )


if __name__ == "__main__":
    main()
