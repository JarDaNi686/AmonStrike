#!/usr/bin/env python3
"""
AmonStrike — HackerOne Interactive Target Selector

Browse live H1 programs, filter by bounty/severity, pick target.
Runs as a Rich TUI — user selects program, AmonStrike locks on.
"""
import os, sys, json, time, requests
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    from rich.columns import Columns
    from rich.live import Live
    from rich.spinner import Spinner
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console() if HAS_RICH else None


class H1Selector:
    """
    Interactive HackerOne program browser and target selector.
    Uses H1 API to browse live programs with bounty data.
    """

    H1_API    = "https://api.hackerone.com/v1"
    CACHE_DIR = Path("data/scope_cache")
    PAGE_SIZE = 25

    def __init__(self):
        self.username = os.environ.get("H1_USERNAME", "")
        self.token    = os.environ.get("H1_API_TOKEN", "")
        self.auth     = (self.username, self.token) if self.username and self.token else None
        self.session  = requests.Session()
        self.session.headers.update({
            "Accept":     "application/json",
            "User-Agent": "AmonStrike/2.0 Security Research Tool",
        })
        self.CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Program listing ───────────────────────────────────────

    def fetch_programs(self, page: int = 1, filter_bounty: bool = True,
                       min_bounty: int = 0, sort: str = "launched_at") -> list:
        """Fetch paginated list of H1 programs."""
        params = {
            "page[number]": page,
            "page[size]":   self.PAGE_SIZE,
        }
        try:
            url  = f"{self.H1_API}/hackers/programs"
            resp = self.session.get(url, auth=self.auth, params=params, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                programs = []
                for item in data:
                    attrs = item.get("attributes", {})
                    prog  = {
                        "handle":        attrs.get("handle", ""),
                        "name":          attrs.get("name", ""),
                        "state":         attrs.get("state", ""),
                        "offers_bounty": attrs.get("offers_bounties", False),
                        "bounty_min":    attrs.get("minimum_bounty_table_value") or 0,
                        "bounty_max":    attrs.get("maximum_bounty_table_value") or 0,
                        "response_time": (attrs.get("average_time_to_first_response_in_minutes") or 0) // 1440,
                        "submission_state": attrs.get("submission_state", ""),
                    }
                    if filter_bounty and not prog["offers_bounty"]:
                        continue
                    if prog["bounty_max"] >= min_bounty:
                        programs.append(prog)
                return programs
        except Exception as e:
            if HAS_RICH:
                console.print(f"[red]H1 API error: {e}[/red]")
        return []

    def search_program(self, query: str) -> list:
        """Search programs by handle or name."""
        params = {
            "page[size]": 50,
            "query":      query,
        }
        try:
            resp = self.session.get(
                f"{self.H1_API}/hackers/programs",
                auth=self.auth, params=params, timeout=15
            )
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                results = []
                for item in data:
                    attrs = item.get("attributes", {})
                    handle = attrs.get("handle", "")
                    name   = attrs.get("name", "")
                    if query.lower() in handle.lower() or query.lower() in name.lower():
                        results.append({
                            "handle":        handle,
                            "name":          name,
                            "offers_bounty": attrs.get("offers_bounties", False),
                            "bounty_max":    attrs.get("maximum_bounty_table_value") or 0,
                            "state":         attrs.get("state", ""),
                            "response_time": (attrs.get("average_time_to_first_response_in_minutes") or 0) // 1440,
                        })
                return results
        except Exception:
            pass
        return []

    # ── Interactive TUI ───────────────────────────────────────

    def _print_banner(self):
        if not HAS_RICH:
            return
        console.print(Panel.fit(
            "[bold red]AmonStrike[/bold red] [white]— Target Acquisition System[/white]\n"
            "[dim]Live HackerOne Program Browser[/dim]",
            border_style="red",
        ))

    def _build_program_table(self, programs: list, selected: int = -1) -> Table:
        table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            padding=(0, 1),
        )
        table.add_column("#",      style="dim",        width=4)
        table.add_column("Handle", style="bold white", width=25)
        table.add_column("Name",   style="white",      width=30)
        table.add_column("Bounty", style="green",      width=12, justify="right")
        table.add_column("Max $",  style="bold green", width=10, justify="right")
        table.add_column("Resp",   style="yellow",     width=8,  justify="right")

        for i, p in enumerate(programs):
            row_style = "on dark_green" if i == selected else ""
            bounty_txt = "[green]✓[/green]" if p["offers_bounty"] else "[red]✗[/red]"
            max_b      = f"${p['bounty_max']:,}" if p["bounty_max"] else "—"
            resp       = f"{p['response_time']}d" if p.get("response_time") else "—"
            table.add_row(
                str(i + 1),
                p["handle"],
                p["name"][:30],
                bounty_txt,
                max_b,
                resp,
                style=row_style,
            )
        return table

    def run(self) -> dict | None:
        """
        Interactive target selection.
        Returns selected program dict, or None if cancelled.
        """
        if not HAS_RICH:
            return self._run_simple()

        self._print_banner()
        console.print()

        # Mode selection
        console.print("[bold]How do you want to select a target?[/bold]")
        console.print("  [cyan]1[/cyan] Browse top bounty programs")
        console.print("  [cyan]2[/cyan] Search by handle/name")
        console.print("  [cyan]3[/cyan] Enter handle directly")
        console.print("  [cyan]4[/cyan] Scan a specific URL (non-H1)")
        console.print()

        choice = Prompt.ask("Select", choices=["1","2","3","4"], default="1")

        if choice == "1":
            return self._browse_programs()
        elif choice == "2":
            return self._search_programs()
        elif choice == "3":
            return self._enter_handle()
        elif choice == "4":
            return self._enter_url()
        return None

    def _browse_programs(self) -> dict | None:
        console.print("\n[dim]Fetching live H1 programs...[/dim]")
        page = 1
        while True:
            with console.status("[bold green]Loading programs from HackerOne...[/bold green]"):
                programs = self.fetch_programs(page=page, filter_bounty=True)

            if not programs:
                console.print("[red]No programs found or API error.[/red]")
                return None

            console.print(f"\n[dim]Page {page} — {len(programs)} programs[/dim]\n")
            console.print(self._build_program_table(programs))
            console.print()
            console.print("[dim]Enter number to select  |  n = next page  |  p = prev  |  q = quit[/dim]")

            inp = Prompt.ask("Choice").strip().lower()

            if inp == "q":
                return None
            elif inp == "n":
                page += 1
            elif inp == "p":
                page = max(1, page - 1)
            else:
                try:
                    idx = int(inp) - 1
                    if 0 <= idx < len(programs):
                        return self._confirm_target(programs[idx])
                except ValueError:
                    console.print("[red]Invalid input[/red]")

    def _search_programs(self) -> dict | None:
        query = Prompt.ask("Search handle or name").strip()
        if not query:
            return None

        with console.status(f"[bold green]Searching for '{query}'...[/bold green]"):
            results = self.search_program(query)

        if not results:
            # Try direct handle
            return self._confirm_target({"handle": query, "name": query,
                                         "offers_bounty": True, "bounty_max": 0})

        console.print(f"\n[dim]{len(results)} results[/dim]\n")
        console.print(self._build_program_table(results))
        console.print()

        inp = Prompt.ask("Select number (or Enter for first)").strip()
        try:
            idx = int(inp) - 1 if inp else 0
            if 0 <= idx < len(results):
                return self._confirm_target(results[idx])
        except ValueError:
            pass
        return None

    def _enter_handle(self) -> dict | None:
        handle = Prompt.ask("H1 program handle (e.g. gocardless)").strip()
        if not handle:
            return None
        return self._confirm_target({"handle": handle, "name": handle,
                                     "offers_bounty": True, "bounty_max": 0})

    def _enter_url(self) -> dict | None:
        url = Prompt.ask("Target URL (e.g. https://api.example.com)").strip()
        if not url:
            return None
        if not url.startswith("http"):
            url = f"https://{url}"
        return {
            "handle":        url,
            "name":          url,
            "target_url":    url,
            "offers_bounty": False,
            "bounty_max":    0,
            "custom_url":    True,
        }

    def _confirm_target(self, program: dict) -> dict | None:
        console.print()
        console.print(Panel(
            f"[bold white]Target:[/bold white] [bold cyan]{program['handle']}[/bold cyan]\n"
            f"[bold white]Name:[/bold white]   {program.get('name','')}\n"
            f"[bold white]Bounty:[/bold white] {'Yes' if program.get('offers_bounty') else 'No'}"
            + (f"  (max ${program['bounty_max']:,})" if program.get('bounty_max') else ""),
            title="[bold red]TARGET LOCK[/bold red]",
            border_style="red",
        ))

        # Scan options
        console.print("\n[bold]Scan options:[/bold]")
        console.print("  [cyan]1[/cyan] Full autonomous scan (no submit — review first)")
        console.print("  [cyan]2[/cyan] Full autonomous scan with auto-submit CRITICAL/HIGH")
        console.print("  [cyan]3[/cyan] Recon only")
        console.print("  [cyan]4[/cyan] Attack only (assumes recon done)")

        mode = Prompt.ask("Scan mode", choices=["1","2","3","4"], default="1")

        hours = Prompt.ask("Max hours (0 = unlimited)", default="0")
        try:
            hours = float(hours)
        except ValueError:
            hours = 0.0

        return {
            **program,
            "scan_mode":   mode,
            "auto_submit": mode == "2",
            "max_hours":   hours,
        }

    def _run_simple(self) -> dict | None:
        """Fallback when Rich not available."""
        print("\n=== AmonStrike Target Selector ===")
        print("1. Enter H1 program handle")
        print("2. Enter URL directly")
        choice = input("Choice [1/2]: ").strip()
        if choice == "2":
            url = input("URL: ").strip()
            return {"handle": url, "name": url, "target_url": url,
                    "auto_submit": False, "max_hours": 0, "custom_url": True}
        handle = input("H1 handle: ").strip()
        submit = input("Auto-submit? [y/N]: ").strip().lower() == "y"
        hours  = input("Max hours (0=unlimited): ").strip()
        return {
            "handle":      handle,
            "name":        handle,
            "auto_submit": submit,
            "max_hours":   float(hours) if hours else 0.0,
        }


# ── Standalone target browser ─────────────────────────────────

if __name__ == "__main__":
    selector = H1Selector()
    target   = selector.run()
    if target:
        import json
        print(json.dumps(target, indent=2))
    else:
        print("No target selected.")
