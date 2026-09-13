"""
AmonStrike — Pentesting Task Tree (PTT)
Based on PentestGPT's architecture (USENIX Security 2024).

Not a linear pipeline. A GRAPH of tasks.
Each finding spawns new tasks.
Completed = exploited with proof. Not just detected.
"""
import json, time
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from pathlib import Path


class TaskStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"   # exploited with proof
    FAILED    = "failed"      # tested, not vulnerable
    SKIPPED   = "skipped"     # out of scope or duplicate


class TaskType(Enum):
    RECON      = "recon"
    CRAWL      = "crawl"
    AUTH       = "auth"
    ATTACK     = "attack"
    VALIDATE   = "validate"   # prove it's real
    ESCALATE   = "escalate"   # chain to higher severity
    REPORT     = "report"


@dataclass
class PentestTask:
    id:          str
    type:        TaskType
    title:       str
    target_url:  str
    module:      str          = ""
    payload:     str          = ""
    status:      TaskStatus   = TaskStatus.PENDING
    priority:    int          = 5           # 1=highest, 10=lowest
    parent_id:   str          = ""          # spawned by which task
    children:    List[str]    = field(default_factory=list)
    finding:     dict         = field(default_factory=dict)
    proof:       str          = ""          # required before reporting
    notes:       str          = ""
    created_at:  str          = field(default_factory=lambda: datetime.now().isoformat())
    completed_at:str          = ""
    mitre_technique: str      = ""          # ATT&CK mapping


class PentestTaskTree:
    """
    Structured task graph — not a linear pipeline.
    Tasks spawn children. Findings spawn validation tasks.
    Validation tasks spawn escalation tasks.
    Nothing reported without proof.
    """

    def __init__(self, target: str, session_file: str = ""):
        self.target       = target
        self.tasks        = {}   # id -> PentestTask
        self.root_id      = ""
        self.session_file = session_file or str(
            Path.home() / ".amonstrike" / "ptt_session.json"
        )
        self._load_session()

    # ── Task Management ───────────────────────────────────────

    def add_task(self, task: PentestTask) -> str:
        self.tasks[task.id] = task
        if task.parent_id and task.parent_id in self.tasks:
            self.tasks[task.parent_id].children.append(task.id)
        self._save_session()
        return task.id

    def get_next_tasks(self, limit: int = 3) -> List[PentestTask]:
        """Get highest-priority pending tasks."""
        pending = [t for t in self.tasks.values()
                  if t.status == TaskStatus.PENDING]
        return sorted(pending, key=lambda t: t.priority)[:limit]

    def complete_task(self, task_id: str, finding: dict = None,
                      proof: str = ""):
        """Mark task complete. Spawn children if finding confirmed."""
        if task_id not in self.tasks:
            return
        task = self.tasks[task_id]
        task.status       = TaskStatus.COMPLETED
        task.completed_at = datetime.now().isoformat()
        if finding:
            task.finding = finding
        if proof:
            task.proof = proof
        self._spawn_children(task)
        self._save_session()

    def fail_task(self, task_id: str, notes: str = ""):
        if task_id not in self.tasks:
            return
        self.tasks[task_id].status = TaskStatus.FAILED
        self.tasks[task_id].notes  = notes
        self._save_session()

    def _spawn_children(self, task: PentestTask):
        """Spawn follow-up tasks based on completed task."""
        finding  = task.finding
        severity = finding.get("severity","")
        module   = task.module
        url      = task.target_url

        # SQLi found → spawn: extract DB, test auth bypass, check for RCE
        if module == "sqli" and severity in ["CRITICAL","HIGH"]:
            self._add_child(task, TaskType.ESCALATE, "SQLi: Extract database contents",
                           url, "sqli", priority=1,
                           notes="Use UNION-based or error-based to dump tables")
            self._add_child(task, TaskType.ESCALATE, "SQLi: Test authentication bypass",
                           url, "sqli", priority=1,
                           notes="Try admin'-- on login form")
            self._add_child(task, TaskType.ATTACK, "SQLi: Test for RCE via INTO OUTFILE",
                           url, "command_injection", priority=2)

        # XSS found → spawn: test for stored, test cookie theft
        elif module == "xss" and severity in ["HIGH","MEDIUM"]:
            self._add_child(task, TaskType.ESCALATE, "XSS: Test for stored variant",
                           url, "xss", priority=2)
            self._add_child(task, TaskType.VALIDATE, "XSS: Confirm cookie theft possible",
                           url, "xss", priority=2)

        # IDOR found → spawn: test mass enumeration, test write access
        elif module == "idor":
            self._add_child(task, TaskType.ESCALATE, "IDOR: Mass enumerate all user IDs",
                           url, "idor", priority=1)
            self._add_child(task, TaskType.ESCALATE, "IDOR: Test write/delete on other users",
                           url, "idor", priority=1)

        # CORS found → spawn: test with credentials
        elif module == "cors":
            self._add_child(task, TaskType.VALIDATE, "CORS: Confirm credential theft PoC",
                           url, "cors", priority=2)

        # Auth bypass found → spawn: access admin endpoints
        elif module in ["auth","twofa_bypass","jwt_deep"]:
            self._add_child(task, TaskType.ESCALATE, "Auth bypass: Access admin endpoints",
                           url, "idor", priority=1)

        # Any CRITICAL → always add validation task
        if severity == "CRITICAL" and not task.proof:
            self._add_child(task, TaskType.VALIDATE,
                           f"Validate: Confirm {task.title[:40]}",
                           url, module, priority=1)

    def _add_child(self, parent: PentestTask, task_type: TaskType,
                   title: str, url: str, module: str,
                   priority: int = 5, notes: str = ""):
        task_id = f"{module}_{int(time.time()*1000)}"
        child   = PentestTask(
            id         = task_id,
            type       = task_type,
            title      = title,
            target_url = url,
            module     = module,
            priority   = priority,
            parent_id  = parent.id,
            notes      = notes,
        )
        self.add_task(child)

    # ── Session Persistence ───────────────────────────────────

    def _save_session(self):
        try:
            data = {
                "target":  self.target,
                "tasks":   {tid: self._task_to_dict(t)
                           for tid, t in self.tasks.items()},
                "root_id": self.root_id,
                "saved":   datetime.now().isoformat(),
            }
            Path(self.session_file).parent.mkdir(parents=True, exist_ok=True)
            Path(self.session_file).write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def _load_session(self):
        try:
            data = json.loads(Path(self.session_file).read_text())
            if data.get("target") == self.target:
                self.root_id = data.get("root_id","")
                for tid, td in data.get("tasks",{}).items():
                    self.tasks[tid] = self._dict_to_task(td)
        except Exception:
            pass

    def _task_to_dict(self, t: PentestTask) -> dict:
        return {
            "id": t.id, "type": t.type.value, "title": t.title,
            "target_url": t.target_url, "module": t.module,
            "payload": t.payload, "status": t.status.value,
            "priority": t.priority, "parent_id": t.parent_id,
            "children": t.children, "finding": t.finding,
            "proof": t.proof, "notes": t.notes,
            "created_at": t.created_at, "completed_at": t.completed_at,
            "mitre_technique": t.mitre_technique,
        }

    def _dict_to_task(self, d: dict) -> PentestTask:
        return PentestTask(
            id=d["id"], type=TaskType(d["type"]), title=d["title"],
            target_url=d["target_url"], module=d.get("module",""),
            payload=d.get("payload",""), status=TaskStatus(d["status"]),
            priority=d.get("priority",5), parent_id=d.get("parent_id",""),
            children=d.get("children",[]), finding=d.get("finding",{}),
            proof=d.get("proof",""), notes=d.get("notes",""),
            created_at=d.get("created_at",""), completed_at=d.get("completed_at",""),
            mitre_technique=d.get("mitre_technique",""),
        )

    # ── Summary ───────────────────────────────────────────────

    def summary(self) -> dict:
        counts = {s: 0 for s in TaskStatus}
        for t in self.tasks.values():
            counts[t.status] += 1
        confirmed = [t for t in self.tasks.values()
                    if t.status == TaskStatus.COMPLETED and t.proof]
        return {
            "total":     len(self.tasks),
            "pending":   counts[TaskStatus.PENDING],
            "completed": counts[TaskStatus.COMPLETED],
            "failed":    counts[TaskStatus.FAILED],
            "confirmed_with_proof": len(confirmed),
        }

    def get_reportable_findings(self) -> list:
        """Only return findings with proof. No exploit = no report."""
        return [
            t.finding for t in self.tasks.values()
            if t.status == TaskStatus.COMPLETED
            and t.proof
            and t.finding
        ]
