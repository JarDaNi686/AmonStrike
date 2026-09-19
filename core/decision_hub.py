#!/usr/bin/env python3
"""
AmonStrike — Decision Hub
Central intelligence coordinator. Every scan decision passes through here.

This is what makes it "centralized" — no module runs blind.
Before any significant action:
  1. Hub checks ScanContext (what do we already know?)
  2. Hub asks ReasoningEngine (what should we do?)
  3. Hub checks NeuralKB (what patterns apply?)
  4. Hub checks scope (is this allowed?)
  5. Hub executes or blocks
  6. Hub records outcome (NeuralKB learns)

Every attack, every verification, every report submission = hub decision.
"""
import json, time
from datetime import datetime
from typing import Callable


class DecisionHub:
    """
    The brain stem of AmonStrike.
    Coordinates all scan decisions with full context awareness.
    """

    def __init__(self, scan_context, scope_validator=None):
        self.ctx      = scan_context
        self.scope    = scope_validator
        self.reasoning = None   # lazy-loaded
        self.kb       = None    # lazy-loaded
        self.alerts   = None    # lazy-loaded
        self._decision_log = []

    def _get_reasoning(self):
        if self.reasoning is None:
            try:
                from core.reasoning_engine import get_reasoning_engine
                self.reasoning = get_reasoning_engine()
            except Exception:
                pass
        return self.reasoning

    def _get_kb(self):
        if self.kb is None:
            try:
                from core.neural_kb import NeuralKB
                self.kb = NeuralKB()
            except Exception:
                pass
        return self.kb

    # ── Decision gates ────────────────────────────────────────

    def should_attack(self, url: str, attack_type: str) -> dict:
        """
        Gate every attack attempt. Returns {proceed, priority, reason}.
        """
        # 1. Scope check
        if self.scope and not self.scope.is_allowed(url):
            return {"proceed": False, "reason": f"Out of scope: {url}"}

        # 2. Already succeeded — skip
        if attack_type in self.ctx.completed_actions:
            return {"proceed": False, "reason": f"Already completed: {attack_type}"}

        # 3. Failed too many times — deprioritize
        fail_count = self.ctx.failed_actions.get(attack_type, 0)
        if fail_count > 5:
            return {"proceed": False, "reason": f"Too many failures ({fail_count}): {attack_type}"}

        # 4. KB confidence check
        kb = self._get_kb()
        if kb:
            patterns = kb.search(attack_type)
            if patterns:
                conf = patterns[0].get("confidence", 0.5)
                if conf < 0.2:
                    return {"proceed": False, "reason": f"KB confidence too low ({conf:.2f})"}
                return {"proceed": True, "priority": conf, "reason": "KB approved"}

        return {"proceed": True, "priority": 0.5, "reason": "default"}

    def verify_finding(self, finding: dict, evidence: str) -> dict:
        """
        Multi-source verification before any finding is recorded.
        Returns {is_real, confidence, verdict, action}
        """
        reasoning = self._get_reasoning()
        if not reasoning:
            # No AI — basic heuristic check
            return self._heuristic_verify(finding)

        scan_ctx = self.ctx.get_attack_context()
        result   = reasoning.verify_finding(finding, evidence, scan_ctx)

        # Log the decision
        self._log_decision("verify_finding", finding.get("title",""), result)

        # Post-verification: update KB
        kb = self._get_kb()
        if kb:
            module = finding.get("module","")
            kb.reinforce(module, success=result.get("is_real", False))

        # If real: add to context findings
        if result.get("is_real") and result.get("confidence", 0) > 0.5:
            finding["confidence"]   = result.get("confidence", 0.7)
            finding["ai_verdict"]   = result.get("verdict","")
            finding["ai_reasoning"] = result.get("reasoning","")[:300]
            self.ctx.add_finding(finding)

            # Alert on critical/high
            try:
                from core.alerts import alert
                alert(finding)
            except Exception:
                pass

            return {**result, "action": "confirmed", "recorded": True}

        else:
            self.ctx.reject_candidate(finding,
                reason=result.get("reasoning","AI rejected")[:200])
            return {**result, "action": "rejected", "recorded": False}

    def plan_next_action(self) -> dict:
        """
        Ask AI: given everything we know, what should we do next?
        Real-time adaptive planning.
        """
        reasoning = self._get_reasoning()
        if not reasoning:
            return self._mcts_fallback()

        scan_ctx = self.ctx.get_attack_context()
        failed   = list(self.ctx.failed_actions.keys())
        succeeded = [f.get("module","") for f in self.ctx.findings]

        plan = reasoning.plan_next_attack(scan_ctx, failed, succeeded)
        self._log_decision("plan_next_action", plan.get("next_action",""), plan)

        # Also run MCTS for a second opinion
        mcts_plan = self._mcts_fallback()

        # Merge: use AI plan if high confidence, else MCTS
        if plan.get("probability", 0) > 0.6:
            return plan
        return mcts_plan

    def decide_chain_attacks(self) -> list:
        """
        After finding X, what chain attacks does this unlock?
        """
        kb = self._get_kb()
        chains = []
        for finding in self.ctx.findings:
            ftype = finding.get("module", finding.get("vuln_class",""))
            if kb:
                unlocked = kb.get_chains_from(ftype)
                for chain in unlocked:
                    if chain["id"] not in self.ctx.completed_actions:
                        chains.append({
                            "chain_id":  chain["id"],
                            "vuln_class":chain["vuln_class"],
                            "trigger_finding": finding,
                            "payloads":  chain.get("payload_templates",[]),
                            "confidence":chain.get("confidence",0.5),
                        })
        # Also ask AI for additional chains
        reasoning = self._get_reasoning()
        if reasoning and self.ctx.findings:
            ai_chains = reasoning._call_best(
                f"Given these confirmed findings, what chain attacks are possible?\n"
                f"Findings: {json.dumps([f.get('module','') for f in self.ctx.findings[:10]])}\n"
                f"Target: {self.ctx.target}\n"
                f"Return JSON: {{\"chains\": [\"chain1\",\"chain2\"]}}"
            )
        return chains

    def generate_final_reports(self) -> list:
        """
        Generate H1 reports for all confirmed findings using AI.
        """
        reasoning = self._get_reasoning()
        reports   = []
        scan_ctx  = self.ctx.get_attack_context()

        for finding in self.ctx.findings:
            if finding.get("severity","") not in ("CRITICAL","HIGH","MEDIUM"):
                continue
            if not finding.get("url",""):
                continue

            if reasoning:
                report = reasoning.write_report(finding, scan_ctx)
            else:
                report = self._basic_report(finding)

            if report and not report.get("parse_error"):
                report["original_finding"] = finding
                reports.append(report)

        return reports

    # ── Fallbacks ─────────────────────────────────────────────

    def _mcts_fallback(self) -> dict:
        try:
            from core.mcts_planner import MCTSPlanner
            context = {
                "findings":          self.ctx.findings,
                "completed_actions": list(self.ctx.completed_actions),
            }
            plan = MCTSPlanner(time_limit=1.0).plan(context)
            return {
                "next_action": plan[0] if plan else "recon_endpoints",
                "source":      "mcts",
                "probability": 0.5,
            }
        except Exception:
            return {"next_action": "recon_endpoints", "source": "default"}

    def _heuristic_verify(self, finding: dict) -> dict:
        """Basic verification without AI."""
        sev = finding.get("severity","LOW")
        conf = {"CRITICAL":0.9,"HIGH":0.8,"MEDIUM":0.6,"LOW":0.4}.get(sev, 0.5)
        evidence = finding.get("evidence","")
        # Very basic FP signals
        fp_signals = ["theoretical","potential","possible","informational"]
        if any(s in finding.get("description","").lower() for s in fp_signals):
            conf *= 0.5
        return {
            "is_real":   conf > 0.5,
            "confidence":conf,
            "verdict":   "likely_accepted" if conf > 0.6 else "needs_more_evidence",
            "reasoning": "heuristic — no AI available",
        }

    def _basic_report(self, finding: dict) -> dict:
        return {
            "title":       finding.get("title",""),
            "severity":    finding.get("severity","MEDIUM").lower(),
            "cvss_score":  finding.get("cvss_score", 5.0),
            "vulnerability_information": finding.get("description",""),
            "steps_to_reproduce": ["See evidence in finding"],
            "impact":      "See finding evidence",
            "remediation": finding.get("remediation",""),
        }

    def _log_decision(self, decision_type: str, subject: str, result: dict):
        self._decision_log.append({
            "type":    decision_type,
            "subject": subject[:80],
            "result":  {k:v for k,v in result.items() if k != "raw"},
            "ts":      datetime.now().isoformat(),
        })

    def stats(self) -> dict:
        return {
            "decisions_made":   len(self._decision_log),
            "scan_context":     self.ctx.summary(),
            "providers":        self.reasoning.status() if self.reasoning else {},
        }
