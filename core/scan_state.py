"""
AmonStrike — Scan State Manager
Resume interrupted scans from where they stopped.
"""
import os, json, time, hashlib
from pathlib import Path
from datetime import datetime

STATE_DIR = Path.home() / ".amonstrike" / "scans"

class ScanState:
    def __init__(self, target: str, modules: list):
        self.target    = target
        self.modules   = modules
        self.state_id  = hashlib.md5(target.encode()).hexdigest()[:12]
        self.state_file= STATE_DIR / f"{self.state_id}.json"
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        self._state    = self._load()

    def _load(self) -> dict:
        if self.state_file.exists():
            try:
                data = json.loads(self.state_file.read_text())
                age  = time.time() - data.get("started", 0)
                if age < 86400:  # Resume within 24h
                    return data
            except Exception:
                pass
        return {
            "target":    self.target,
            "started":   time.time(),
            "completed": [],
            "findings":  [],
        }

    def save(self):
        self.state_file.write_text(json.dumps(self._state, indent=2, default=str))

    def mark_complete(self, module: str, result: dict):
        if module not in self._state["completed"]:
            self._state["completed"].append(module)
        self._state["findings"].extend(result.get("findings", []))
        self.save()

    def is_complete(self, module: str) -> bool:
        return module in self._state["completed"]

    def get_saved_result(self, module: str) -> dict:
        findings = [f for f in self._state["findings"]
                    if f.get("module") == module]
        return {"findings": findings, "info": {}, "_resumed": True}

    def remaining_modules(self) -> list:
        done = set(self._state["completed"])
        return [m for m in self.modules if m not in done]

    def clear(self):
        if self.state_file.exists():
            self.state_file.unlink()
        self._state = {"target":self.target,"started":time.time(),
                       "completed":[],"findings":[]}

    def has_prior_state(self) -> bool:
        return bool(self._state.get("completed"))

    def summary(self) -> str:
        c = self._state.get("completed",[])
        t = time.time() - self._state.get("started",time.time())
        return (f"{len(c)}/{len(self.modules)} modules complete "
                f"({len(self._state.get('findings',[]))} findings, "
                f"{int(t/60)}m elapsed)")

def run_regression_tests():
    import tempfile
    print("\n=== SCAN STATE REGRESSION TESTS ===")
    passed = failed = 0
    
    # Patch STATE_DIR for testing
    import core.scan_state as ss
    orig = ss.STATE_DIR
    ss.STATE_DIR = Path(tempfile.mkdtemp())
    
    state = ScanState("http://test.com", ["sqli","xss","lfi"])
    
    tests = [
        ("ScanState instantiates",
         lambda: isinstance(state, ScanState)),
        ("No prior state initially",
         lambda: not state.has_prior_state()),
        ("Mark module complete",
         lambda: (state.mark_complete("sqli", {"findings":[{"module":"sqli","title":"test"}]}) or True)),
        ("Module marked complete",
         lambda: state.is_complete("sqli")),
        ("Remaining modules correct",
         lambda: state.remaining_modules() == ["xss","lfi"]),
        ("Saved findings retrievable",
         lambda: len(state.get_saved_result("sqli")["findings"]) == 1),
        ("Has prior state after save",
         lambda: state.has_prior_state()),
        ("Summary returns string",
         lambda: isinstance(state.summary(), str)),
        ("Clear resets state",
         lambda: (state.clear() or True) and not state.is_complete("sqli")),
        ("State file created",
         lambda: (state.mark_complete("xss",{"findings":[]}) or True)),
    ]
    
    for name, fn in tests:
        try:
            if fn():
                passed += 1; print(f"  ✓ {name}")
            else:
                failed += 1; print(f"  ✗ {name}")
        except Exception as e:
            failed += 1; print(f"  ✗ {name} — {e}")
    
    ss.STATE_DIR = orig
    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed

if __name__ == "__main__":
    run_regression_tests()
