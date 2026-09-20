#!/usr/bin/env python3
"""
AmonStrike — Autonomous Bug Bounty Engine
One command → runs forever → hunts bugs → submits H1 reports → repeats.

Usage:
  python core/autonomous_engine.py --program gocardless
  python core/autonomous_engine.py --program gocardless --hours 8 --no-submit
"""
import os, sys, time, json, random, argparse
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

LOOP_LOG  = Path("data/autonomous_log.jsonl")
DONE_FILE = Path("data/completed_targets.json")
SUBMIT_LOG = Path("data/submitted_reports.jsonl")


class AutonomousEngine:
    def __init__(self, program: str, max_hours: float = 0,
                 auto_submit: bool = True):
        self.program        = program
        self.max_hours      = max_hours
        self.auto_submit    = auto_submit
        self.start_ts       = time.time()
        self.iteration      = 0
        self.total_findings = 0
        self.total_submitted = 0
        for p in [LOOP_LOG, DONE_FILE, SUBMIT_LOG]:
            p.parent.mkdir(parents=True, exist_ok=True)

    def _log(self, msg: str):
        entry = {"ts": datetime.now().isoformat(), "msg": msg}
        with open(LOOP_LOG, "a") as fh:
            fh.write(json.dumps(entry) + "\n")
        print(f"[AmonStrike] {msg}")

    def _time_ok(self) -> bool:
        if self.max_hours <= 0:
            return True
        return (time.time() - self.start_ts) / 3600 < self.max_hours

    def _load_done(self) -> set:
        if DONE_FILE.exists():
            try:
                return set(json.loads(DONE_FILE.read_text()))
            except Exception:
                pass
        return set()

    def _save_done(self, done: set):
        DONE_FILE.write_text(json.dumps(list(done)))

    def _pick_target(self, done: set) -> dict | None:
        try:
            import os
            from core.h1_scope_fetcher import H1ScopeFetcher
            fetcher  = H1ScopeFetcher(
                h1_username=os.environ.get("H1_USERNAME",""),
                h1_token=os.environ.get("H1_API_TOKEN",""),
            )
            scope    = fetcher.fetch(self.program)

            # Build target list from structured in_scope or fall back to core_assets
            raw_in_scope = scope.get("scope_raw", {}).get("in_scope", [])
            if raw_in_scope:
                candidates_pool = [
                    {"target": t.get("target", t.get("asset_identifier","")),
                     "asset_type": t.get("asset_type","url"),
                     "max_severity": t.get("max_severity","high")}
                    for t in raw_in_scope
                    if t.get("asset_type","") in ("url","wildcard","URL","WILDCARD")
                ]
            else:
                # Fallback: use core_assets list
                candidates_pool = [
                    {"target": a, "asset_type": "wildcard", "max_severity": "critical"}
                    for a in scope.get("core_assets", [])
                ] + [
                    {"target": a, "asset_type": "url", "max_severity": "high"}
                    for a in scope.get("non_core_assets", [])
                ]

            if not candidates_pool:
                return None

            candidates = [t for t in candidates_pool
                          if t.get("target","") not in done]
            if not candidates:
                done.clear()
                self._save_done(done)
                candidates = candidates_pool

            candidates.sort(key=lambda t: t.get("max_severity","none"), reverse=True)
            return random.choice(candidates[:3]) if candidates else None
        except Exception as e:
            self._log(f"scope fetch failed: {e}")
            return None

    def _run_target(self, target: dict) -> list:
        url = target.get("target", target.get("asset_identifier",""))
        if not url.startswith("http"):
            url = f"https://{url.lstrip('*.')}"
        self._log(f"Scanning {url}")

        # MCTS: plan optimal attack order
        try:
            from core.mcts_planner import MCTSPlanner
            planner = MCTSPlanner(time_limit=1.0)
            plan    = planner.plan({"findings": [], "completed_actions": []})
            self._log(f"MCTS plan: {plan[:5]}")
        except Exception:
            pass

        try:
            from core.orchestrator import MasterOrchestrator
            orch   = MasterOrchestrator(target=url, program=self.program, use_burp=False)
            result = orch.run()
            return result.get("findings", [])
        except Exception as e:
            self._log(f"orchestrator error: {e}")
            return []

    def _submit(self, findings: list, url: str) -> int:
        """Submit CRITICAL/HIGH findings to HackerOne automatically."""
        reportable = [f for f in findings
                      if f.get("severity","") in ("CRITICAL","HIGH")]
        if not reportable:
            self._log(f"No high/critical findings to submit for {url}")
            return 0

        if not self.auto_submit:
            self._log(f"Auto-submit disabled. {len(reportable)} findings saved to output/.")
            return 0

        submitted = 0
        try:
            from reports.hackerone_format import generate_h1_package
            pkg = generate_h1_package(
                reportable, "output/autonomous",
                program_handle=self.program,
                target_url=url,
            )
            # Log each submitted report
            for report in pkg.get("reports", []):
                with open(SUBMIT_LOG, "a") as fh:
                    fh.write(json.dumps({
                        "ts":      datetime.now().isoformat(),
                        "program": self.program,
                        "url":     url,
                        "title":   report.get("title",""),
                        "severity":report.get("severity",""),
                        "report_id": report.get("id",""),
                    }) + "\n")
                submitted += 1

            self._log(f"Submitted {submitted} reports to H1:{self.program}")
        except Exception as e:
            self._log(f"submission error: {e}")

        return submitted

    def run(self):
        self._log(f"=== Autonomous Engine Started ===")
        self._log(f"Program={self.program} auto_submit={self.auto_submit}")

        # Direct target assignment: scan exactly the URL the user gave, once.
        custom_url = getattr(self, "_custom_target_url", "")
        if custom_url:
            self._log(f"Direct target assigned: {custom_url}")
            target   = {"target": custom_url, "asset_type": "url"}
            findings = self._run_target(target)
            self.total_findings += len(findings)
            submitted = self._submit(findings, custom_url)
            self.total_submitted += submitted
            self._log(
                f"[+] url={custom_url} | findings={len(findings)} "
                f"| submitted={submitted}"
            )
            self._log(f"=== Single-target scan complete ===")
            return

        done = self._load_done()

        while self._time_ok():
            self.iteration += 1
            self._log(f"--- Iteration {self.iteration} ---")

            # Pick next target
            target = self._pick_target(done)
            if not target:
                self._log("No new targets. Sleeping 30m then retrying.")
                time.sleep(1800)
                continue

            url = target.get("target", target.get("asset_identifier",""))

            # Full scan
            findings = self._run_target(target)
            self.total_findings += len(findings)

            # Submit
            submitted = self._submit(findings, url)
            self.total_submitted += submitted

            # Mark done
            done.add(url)
            self._save_done(done)

            self._log(
                f"[+] url={url} | findings={len(findings)} "
                f"| submitted={submitted} | total_findings={self.total_findings} "
                f"| total_submitted={self.total_submitted}"
            )

            # Rate-limit cooldown
            cooldown = random.randint(90, 300)
            self._log(f"Cooldown {cooldown}s...")
            time.sleep(cooldown)

        elapsed = (time.time() - self.start_ts) / 3600
        self._log(
            f"=== Loop Ended === "
            f"iterations={self.iteration} "
            f"findings={self.total_findings} "
            f"submitted={self.total_submitted} "
            f"elapsed={elapsed:.1f}h"
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="AmonStrike Autonomous Engine")
    p.add_argument("--program",     help="HackerOne program handle (auto-picks targets from scope)")
    p.add_argument("--url",         help="Scan this exact URL directly (skips H1 auto-pick)")
    p.add_argument("--hours",       type=float, default=0,
                   help="Max runtime hours (0=unlimited)")
    p.add_argument("--no-submit",   action="store_true",
                   help="Find bugs but don't auto-submit — save reports locally only")
    args = p.parse_args()

    if not args.program and not args.url:
        p.error("provide --program <handle> or --url <target>")

    engine = AutonomousEngine(
        program=args.program or (args.url or ""),
        max_hours=args.hours,
        auto_submit=not args.no_submit,
    )
    if args.url:
        url = args.url if args.url.startswith("http") else f"https://{args.url}"
        engine._custom_target_url = url
    try:
        engine.run()
    except KeyboardInterrupt:
        print("\n[AmonStrike] Stopped by user (Ctrl+C).")
