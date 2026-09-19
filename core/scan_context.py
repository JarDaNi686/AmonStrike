#!/usr/bin/env python3
"""
AmonStrike — Scan Context (Shared Brain Memory)
Central state shared across ALL components during a scan.
Every module reads from and writes to this. Nothing runs blind.
"""
import json, threading, time
from pathlib import Path
from datetime import datetime
from collections import defaultdict


class ScanContext:
    """
    Thread-safe shared memory for an entire scan session.

    Every module writes what it learns here.
    Every module reads what others found here.
    The AI uses this to make decisions with full context.

    This is what makes AmonStrike think like a senior pentester
    who remembers everything they found and connects the dots.
    """

    def __init__(self, target: str, program: str = ""):
        self.target      = target
        self.program     = program
        self.session_id  = f"{target.replace('https://','').replace('/','_')}_{int(time.time())}"
        self._lock       = threading.Lock()

        # ── Core knowledge ────────────────────────────────────
        self.tech_stack      : list  = []          # detected technologies
        self.endpoints       : list  = []          # all discovered endpoints
        self.params          : dict  = {}          # endpoint → params map
        self.forms           : list  = []          # HTML forms
        self.js_endpoints    : list  = []          # endpoints from JS
        self.subdomains      : list  = []
        self.open_ports      : list  = []
        self.waf_type        : str   = ""
        self.has_graphql     : bool  = False
        self.has_websocket   : bool  = False
        self.auth_tokens     : dict  = {}          # user → token map
        self.cookies         : dict  = {}

        # ── Findings (live, shared) ───────────────────────────
        self.findings        : list  = []          # confirmed findings
        self.candidates      : list  = []          # unverified candidates
        self.rejected        : list  = []          # AI-rejected false positives
        self.chains          : list  = []          # zero-day chains

        # ── AI reasoning memory ───────────────────────────────
        self.app_behavior    : dict  = {}          # learned app behavior patterns
        self.response_baselines: dict = {}         # endpoint → baseline response
        self.anomalies       : list  = []          # statistical anomalies
        self.attack_history  : list  = []          # what was tried and result
        self.llm_analysis    : dict  = {}          # AI's analysis of target
        self.mcts_plan       : list  = []          # current attack plan

        # ── Scan state ────────────────────────────────────────
        self.completed_actions: set  = set()
        self.failed_actions   : dict = defaultdict(int)  # action → fail count
        self.start_time       : float= time.time()
        self.phase            : str  = "init"

        self._save_path = Path(f"data/contexts/{self.session_id}.json")
        self._save_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Thread-safe write operations ─────────────────────────

    def add_finding(self, finding: dict):
        with self._lock:
            finding.setdefault("ts", datetime.now().isoformat())
            finding.setdefault("session_id", self.session_id)
            self.findings.append(finding)
            self._checkpoint()

    def add_candidate(self, candidate: dict):
        with self._lock:
            candidate.setdefault("ts", datetime.now().isoformat())
            self.candidates.append(candidate)

    def promote_candidate(self, candidate: dict):
        """Move from candidates to confirmed findings."""
        with self._lock:
            if candidate in self.candidates:
                self.candidates.remove(candidate)
            candidate["verified"] = True
            self.findings.append(candidate)
            self._checkpoint()

    def reject_candidate(self, candidate: dict, reason: str):
        with self._lock:
            if candidate in self.candidates:
                self.candidates.remove(candidate)
            candidate["rejection_reason"] = reason
            self.rejected.append(candidate)

    def record_attack(self, action: str, url: str,
                      payload: str, result: str, success: bool):
        """Log every attack attempt for AI to learn from."""
        with self._lock:
            self.attack_history.append({
                "action":  action,
                "url":     url,
                "payload": payload[:200],
                "result":  result[:200],
                "success": success,
                "ts":      datetime.now().isoformat(),
            })
            if success:
                self.completed_actions.add(action)
            else:
                self.failed_actions[action] += 1

    def learn_behavior(self, endpoint: str, observation: dict):
        """Record what the app does at a specific endpoint."""
        with self._lock:
            self.app_behavior[endpoint] = observation

    def set_baseline(self, endpoint: str, response_features: dict):
        with self._lock:
            self.response_baselines[endpoint] = response_features

    def get_attack_context(self) -> str:
        """Serialize full context for AI reasoning prompt."""
        with self._lock:
            return json.dumps({
                "target":          self.target,
                "program":         self.program,
                "tech_stack":      self.tech_stack[:10],
                "endpoints_count": len(self.endpoints),
                "top_endpoints":   self.endpoints[:20],
                "waf":             self.waf_type,
                "has_graphql":     self.has_graphql,
                "findings_so_far": [
                    {"type": f.get("module",""), "severity": f.get("severity",""),
                     "url": f.get("url","")}
                    for f in self.findings[-10:]
                ],
                "failed_attacks":  dict(self.failed_actions),
                "completed":       list(self.completed_actions)[:20],
                "app_behavior":    dict(list(self.app_behavior.items())[:5]),
            }, indent=2)

    def summary(self) -> dict:
        return {
            "target":      self.target,
            "phase":       self.phase,
            "endpoints":   len(self.endpoints),
            "findings":    len(self.findings),
            "candidates":  len(self.candidates),
            "chains":      len(self.chains),
            "tech_stack":  self.tech_stack[:5],
            "waf":         self.waf_type,
            "elapsed_s":   round(time.time() - self.start_time, 1),
        }

    def _checkpoint(self):
        """Persist context to disk (called on every new finding)."""
        try:
            data = {
                "target":   self.target,
                "program":  self.program,
                "findings": self.findings,
                "chains":   self.chains,
                "tech":     self.tech_stack,
                "ts":       datetime.now().isoformat(),
            }
            self._save_path.write_text(json.dumps(data, indent=2))
        except Exception:
            pass
