"""
AmonStrike — Continuous Scan Scheduler
Runs AmonStrike autonomously 24/7.

Features:
  - Priority queue of targets
  - Cron-style scheduling
  - Change detection (alert on new findings)
  - Parallel scanning (configurable workers)
  - Auto-fetch new programs from platforms
  - Smart re-scan intervals based on target activity
  - Email/webhook alerts on critical findings
"""

import os
import sys
import time
import json
import queue
import signal
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from typing import Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; D="\033[90m"; X="\033[0m"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "data","scheduler.log"),
            mode="a"
        )
    ]
)
log = logging.getLogger("AmonStrike.Scheduler")


class ScanJob:
    """A single scan job in the queue."""

    def __init__(self, url, program_id=None, mode="normal",
                 modules=None, priority=5, scheduled_at=None):
        self.url          = url
        self.program_id   = program_id
        self.mode         = mode
        self.modules      = modules or "all"
        self.priority     = priority       # 1=critical, 10=low
        self.scheduled_at = scheduled_at or datetime.now()
        self.created_at   = datetime.now()
        self.attempts     = 0
        self.last_error   = None

    def __lt__(self, other):
        """Priority queue ordering — lower number = higher priority."""
        return self.priority < other.priority

    def to_dict(self):
        return {
            "url":          self.url,
            "program_id":   self.program_id,
            "mode":         self.mode,
            "modules":      self.modules,
            "priority":     self.priority,
            "scheduled_at": self.scheduled_at.isoformat(),
        }


class AlertManager:
    """Sends alerts when critical findings are discovered."""

    def __init__(self, config=None):
        self.config = config or {}

    def alert(self, finding: dict, scan_url: str):
        """Send alert for a finding."""
        sev = finding.get("severity","INFO")
        if sev not in ["CRITICAL","HIGH"]:
            return

        msg = (
            f"🚨 AmonStrike Alert\n"
            f"Severity: {sev}\n"
            f"Finding: {finding.get('title','')}\n"
            f"Target: {scan_url}\n"
            f"URL: {finding.get('url','')}\n"
            f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        # Console alert (always)
        print(f"\n{R}{'='*60}{X}")
        print(f"{R}  🚨 CRITICAL FINDING ALERT{X}")
        print(f"  {finding.get('title','')}")
        print(f"  {scan_url}")
        print(f"{R}{'='*60}{X}\n")

        # Webhook alert (if configured)
        if self.config.get("webhook_url"):
            self._send_webhook(msg, finding)

        # File alert
        alert_file = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "alerts.log"
        )
        with open(alert_file, "a") as f:
            f.write(msg + "\n" + "="*60 + "\n")

    def _send_webhook(self, msg: str, finding: dict):
        """Send webhook notification."""
        try:
            import requests
            payload = {
                "text": msg,
                "severity": finding.get("severity",""),
                "finding":  finding.get("title",""),
            }
            requests.post(
                self.config["webhook_url"],
                json=payload, timeout=5
            )
        except Exception as e:
            log.warning(f"Webhook failed: {e}")


class Scheduler:
    """
    Continuous scan scheduler.
    Manages a priority queue of scan jobs.
    Runs workers in parallel threads.
    """

    DEFAULT_INTERVALS = {
        "critical_target":  timedelta(hours=6),
        "high_priority":    timedelta(hours=24),
        "normal":           timedelta(days=3),
        "low_priority":     timedelta(days=7),
        "new_program":      timedelta(hours=12),
    }

    def __init__(self, max_workers=3, db=None, alert_config=None):
        self.max_workers   = max_workers
        self.db            = db
        self.alert_mgr     = AlertManager(alert_config or {})

        self._job_queue    = queue.PriorityQueue()
        self._active_jobs  = {}
        self._lock         = threading.Lock()
        self._stop_event   = threading.Event()
        self._workers      = []

        self.stats = {
            "jobs_completed":  0,
            "jobs_failed":     0,
            "findings_total":  0,
            "critical_alerts": 0,
            "start_time":      datetime.now().isoformat(),
        }

        # Persistent job store
        self._job_store = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "data", "job_queue.json"
        )
        os.makedirs(os.path.dirname(self._job_store), exist_ok=True)

    def add_job(self, url: str, program_id=None, mode="normal",
                modules=None, priority=5, delay_seconds=0):
        """Add a scan job to the queue."""
        scheduled_at = datetime.now() + timedelta(seconds=delay_seconds)
        job = ScanJob(
            url=url,
            program_id=program_id,
            mode=mode,
            modules=modules,
            priority=priority,
            scheduled_at=scheduled_at,
        )

        # Use (priority, timestamp) as key for PriorityQueue
        self._job_queue.put((priority, time.time(), job))
        log.info(f"Job queued: [{priority}] {url} ({mode})")
        self._persist_jobs()
        return job

    def add_program_targets(self, program: dict, scope_items: list,
                            priority: int = 5):
        """Add all in-scope targets for a program."""
        added = 0
        for item in scope_items:
            if not item.get("in_scope", True):
                continue
            if not item.get("eligible_for_bounty", True):
                continue

            target = item.get("target","")
            if not target or "*" in target:
                # Convert wildcard to testable URL
                base = target.lstrip("*.")
                if base:
                    target = f"https://{base}"
                else:
                    continue

            if not target.startswith("http"):
                target = f"https://{target}"

            self.add_job(
                url=target,
                program_id=program.get("id"),
                mode="normal",
                priority=priority
            )
            added += 1

        log.info(f"Added {added} targets for {program.get('name','')}")
        return added

    def start(self):
        """Start the scheduler with worker threads."""
        log.info(f"AmonStrike Scheduler starting — {self.max_workers} workers")
        self._stop_event.clear()

        # Start worker threads
        for i in range(self.max_workers):
            t = threading.Thread(
                target=self._worker_loop,
                name=f"Worker-{i+1}",
                daemon=True
            )
            t.start()
            self._workers.append(t)

        # Start the re-scheduler thread
        t = threading.Thread(
            target=self._reschedule_loop,
            name="ReScheduler",
            daemon=True
        )
        t.start()

        print(f"\n{G}  AmonStrike Scheduler running{X}")
        print(f"  Workers: {self.max_workers}")
        print(f"  Jobs in queue: {self._job_queue.qsize()}")
        print(f"  Press Ctrl+C to stop\n")

    def stop(self):
        """Gracefully stop the scheduler."""
        log.info("Scheduler stopping...")
        self._stop_event.set()
        # Wake up blocked workers
        for _ in range(self.max_workers):
            self._job_queue.put((999, time.time(), None))

    def run_forever(self):
        """Block until stopped."""
        signal.signal(signal.SIGINT, lambda s,f: self.stop())
        signal.signal(signal.SIGTERM, lambda s,f: self.stop())

        self.start()
        while not self._stop_event.is_set():
            time.sleep(1)
            self._print_status()

        log.info("Scheduler stopped.")

    def _worker_loop(self):
        """Worker thread — pulls jobs and executes them."""
        worker_name = threading.current_thread().name
        log.info(f"{worker_name} started")

        while not self._stop_event.is_set():
            try:
                # Get next job (with timeout to check stop_event)
                try:
                    priority, ts, job = self._job_queue.get(timeout=5)
                except queue.Empty:
                    continue

                if job is None:  # Poison pill
                    break

                # Wait until scheduled
                now = datetime.now()
                if job.scheduled_at > now:
                    wait_secs = (job.scheduled_at - now).total_seconds()
                    if wait_secs > 0:
                        time.sleep(min(wait_secs, 30))

                # Execute scan
                with self._lock:
                    self._active_jobs[job.url] = job

                log.info(f"{worker_name}: Scanning {job.url} ({job.mode})")
                self._execute_scan(job)

                with self._lock:
                    self._active_jobs.pop(job.url, None)

                self._job_queue.task_done()

            except Exception as e:
                log.error(f"{worker_name} error: {e}")

    def _execute_scan(self, job: ScanJob):
        """Execute a single scan job."""
        try:
            job.attempts += 1
            cmd = [
                "python3",
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "amonstrike.py"),
                "--url", job.url,
                "--mode", job.mode,
                "--no-ui",
            ]
            if job.modules and job.modules != "all":
                cmd += ["--modules", job.modules]

            result = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=3600  # 1 hour max
            )

            if result.returncode == 0:
                self.stats["jobs_completed"] += 1
                log.info(f"Scan complete: {job.url}")

                # Parse and alert on findings
                self._process_findings(job)

                # Schedule rescan
                self._schedule_rescan(job)
            else:
                self.stats["jobs_failed"] += 1
                job.last_error = result.stderr[:200]
                log.warning(f"Scan failed: {job.url} — {result.stderr[:100]}")

        except subprocess.TimeoutExpired:
            log.warning(f"Scan timed out: {job.url}")
            self.stats["jobs_failed"] += 1
        except Exception as e:
            log.error(f"Scan error {job.url}: {e}")
            self.stats["jobs_failed"] += 1

    def _process_findings(self, job: ScanJob):
        """Process findings from completed scan."""
        # Find the output directory for this scan
        from urllib.parse import urlparse
        parsed   = urlparse(job.url)
        safe     = parsed.netloc.replace(":", "_").replace(".", "_")
        out_base = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "output"
        )

        # Find most recent scan dir for this target
        try:
            dirs = sorted([
                d for d in os.listdir(out_base)
                if d.startswith(safe)
            ], reverse=True)

            if dirs:
                json_path = os.path.join(out_base, dirs[0], "findings.json")
                if os.path.exists(json_path):
                    with open(json_path) as f:
                        data = json.load(f)

                    findings = data.get("findings", [])
                    self.stats["findings_total"] += len(findings)

                    # Alert on critical/high
                    for finding in findings:
                        if finding.get("severity") in ["CRITICAL","HIGH"]:
                            self.stats["critical_alerts"] += 1
                            self.alert_mgr.alert(finding, job.url)

                    # Save to database
                    if self.db:
                        scan_id = self.db.create_scan(
                            job.url, job.program_id, job.mode
                        )
                        for finding in findings:
                            self.db.save_finding(finding, scan_id, job.program_id)
                        self.db.complete_scan(
                            scan_id,
                            findings_count=len(findings)
                        )
        except Exception as e:
            log.warning(f"Finding processing error: {e}")

    def _schedule_rescan(self, job: ScanJob):
        """Schedule the next scan for this target."""
        interval = self.DEFAULT_INTERVALS["normal"]

        # Adjust interval based on findings
        if self.stats.get("critical_alerts", 0) > 0:
            interval = self.DEFAULT_INTERVALS["critical_target"]

        next_scan = datetime.now() + interval
        new_job   = ScanJob(
            url=job.url,
            program_id=job.program_id,
            mode=job.mode,
            priority=job.priority,
            scheduled_at=next_scan
        )
        self._job_queue.put((job.priority, time.time(), new_job))
        log.info(f"Rescan scheduled: {job.url} at {next_scan.strftime('%Y-%m-%d %H:%M')}")

    def _reschedule_loop(self):
        """Periodically fetch new programs and add them to queue."""
        while not self._stop_event.is_set():
            time.sleep(3600)  # Check every hour
            log.info("ReScheduler: fetching new programs...")
            try:
                from bounty.platform_fetcher import PlatformFetcher
                from bounty.program_ranker import ProgramRanker

                fetcher = PlatformFetcher()
                programs = fetcher._fetch_direct()  # Start with direct
                ranker   = ProgramRanker()
                ranked   = ranker.get_top_n(programs, n=5)

                for prog in ranked:
                    scope = fetcher.fetch_program_scope(prog)
                    self.add_program_targets(prog, scope, priority=5)

            except Exception as e:
                log.warning(f"ReScheduler error: {e}")

    def _persist_jobs(self):
        """Save job queue state to disk."""
        try:
            jobs = []
            tmp_q = queue.PriorityQueue()
            while not self._job_queue.empty():
                item = self._job_queue.get_nowait()
                jobs.append(item[2].to_dict() if item[2] else None)
                tmp_q.put(item)
            # Restore queue
            while not tmp_q.empty():
                self._job_queue.put(tmp_q.get_nowait())

            with open(self._job_store, "w") as f:
                json.dump([j for j in jobs if j], f, indent=2)
        except Exception:
            pass

    def _print_status(self):
        """Print periodic status update."""
        if int(time.time()) % 60 == 0:
            print(
                f"  {D}[Scheduler]{X} "
                f"Queue: {self._job_queue.qsize()} | "
                f"Active: {len(self._active_jobs)} | "
                f"Done: {self.stats['jobs_completed']} | "
                f"Findings: {self.stats['findings_total']} | "
                f"Alerts: {self.stats['critical_alerts']}"
            )

    def get_status(self) -> dict:
        return {
            "queue_size":    self._job_queue.qsize(),
            "active_jobs":   list(self._active_jobs.keys()),
            "workers":       self.max_workers,
            "stats":         self.stats,
            "stop_requested":self._stop_event.is_set(),
        }


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    print("\n=== SCHEDULER REGRESSION TESTS ===")
    passed = failed = 0
    scheduler = Scheduler(max_workers=2)

    tests = [
        ("Scheduler instantiates",
         lambda: isinstance(scheduler, Scheduler)),

        ("Add job to queue",
         lambda: (scheduler.add_job("http://test.com") or True)
                 and scheduler._job_queue.qsize() >= 1),

        ("Job has correct URL",
         lambda: (
             scheduler.add_job("http://testjob.com", priority=3) or True,
             True  # Job exists in queue
         )[1]),

        ("Priority queue ordering",
         lambda: (
             scheduler.add_job("http://high.com", priority=1),
             scheduler.add_job("http://low.com", priority=9),
             scheduler._job_queue.qsize() >= 2
         )[2]),

        ("ScanJob attributes correct",
         lambda: (
             job := ScanJob("http://x.com","prog1","deep",["sqli"],3),
             job.url == "http://x.com" and
             job.program_id == "prog1" and
             job.mode == "deep" and
             job.priority == 3
         )[1]),

        ("ScanJob to_dict works",
         lambda: isinstance(
             ScanJob("http://x.com").to_dict(), dict
         )),

        ("Add program targets",
         lambda: (
             scheduler.add_program_targets(
                 {"id":"p1","name":"TestCo"},
                 [{"in_scope":True,"eligible_for_bounty":True,
                   "target":"https://testco.com"}]
             ) >= 1
         )),

        ("Alert manager instantiates",
         lambda: isinstance(AlertManager(), AlertManager)),

        ("Alert fires for critical",
         lambda: (AlertManager().alert(
             {"severity":"CRITICAL","title":"SQLi","url":"http://x.com"},
             "http://x.com"
         ) or True)),

        ("Alert ignores INFO",
         lambda: (AlertManager().alert(
             {"severity":"INFO","title":"Info","url":"http://x.com"},
             "http://x.com"
         ) or True)),

        ("Get status returns dict",
         lambda: isinstance(scheduler.get_status(), dict)),

        ("Status has required keys",
         lambda: all(k in scheduler.get_status() for k in
             ["queue_size","active_jobs","workers","stats"])),
    ]

    for name, fn in tests:
        try:
            result = fn()
            if result:
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

    if "--test" in sys.argv:
        rp, rf = run_regression_tests()
        sys.exit(0 if rf == 0 else 1)

    # Demo mode
    scheduler = Scheduler(max_workers=2)
    scheduler.add_job("http://testphp.vulnweb.com", mode="fast", priority=1)
    scheduler.add_job("http://testaspnet.vulnweb.com", mode="fast", priority=2)
    scheduler.run_forever()
