"""AmonStrike — Persistent Knowledge Base. Learns across every scan."""
import json, hashlib
from pathlib import Path
from datetime import datetime

DB_PATH = Path.home() / ".amonstrike" / "knowledge.json"

class KnowledgeBase:
    def __init__(self):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._db = self._load()

    def _load(self) -> dict:
        try:
            return json.loads(DB_PATH.read_text())
        except Exception:
            return {"patterns":[],"targets":{},"payloads":{},"fp_rules":[]}

    def save(self):
        DB_PATH.write_text(json.dumps(self._db, indent=2, default=str))

    def record_finding(self, finding: dict, target: str):
        """Store a confirmed real finding as a pattern."""
        pattern = {
            "module":    finding.get("module",""),
            "param":     finding.get("parameter",""),
            "payload":   str(finding.get("payload",""))[:100],
            "severity":  finding.get("severity",""),
            "target":    target,
            "timestamp": datetime.now().isoformat(),
        }
        self._db.setdefault("patterns",[])
        self._db["patterns"].append(pattern)
        self._db["patterns"] = self._db["patterns"][-500:]
        self.save()

    def record_fp(self, finding: dict, reason: str):
        """Store a false positive rule to avoid repeating."""
        rule = {
            "module":  finding.get("module",""),
            "pattern": reason,
            "added":   datetime.now().isoformat(),
        }
        self._db.setdefault("fp_rules",[])
        if rule not in self._db["fp_rules"]:
            self._db["fp_rules"].append(rule)
        self.save()

    def get_hints(self, target: str) -> list:
        """Return attack hints based on past successful patterns."""
        patterns = self._db.get("patterns",[])
        # Most successful modules
        from collections import Counter
        modules = Counter(p["module"] for p in patterns[-100:])
        return [f"Try {m} first — worked {c}x in past scans"
                for m,c in modules.most_common(3)]

    def get_working_payloads(self, module: str) -> list:
        """Return payloads that have worked before for this module."""
        patterns = self._db.get("patterns",[])
        return list({p["payload"] for p in patterns
                    if p["module"] == module and p["payload"]})[:10]

    def summary(self) -> dict:
        return {
            "total_patterns": len(self._db.get("patterns",[])),
            "total_targets":  len(self._db.get("targets",{})),
            "fp_rules":       len(self._db.get("fp_rules",[])),
        }
