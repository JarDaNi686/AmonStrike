"""AmonStrike — Duplicate Checker. Queries H1 Hacktivity before submitting."""
import requests, hashlib, json
from pathlib import Path

CACHE = Path.home() / ".amonstrike" / "seen_bugs.json"

class DuplicateChecker:
    def __init__(self, program_handle: str = ""):
        self.handle = program_handle
        self.known  = self._load_cache()
        if program_handle:
            self._fetch_hacktivity()

    def _load_cache(self) -> set:
        try:
            return set(json.loads(CACHE.read_text()))
        except Exception:
            return set()

    def _fetch_hacktivity(self):
        try:
            r = requests.get(
                f"https://hackerone.com/{self.handle}/hacktivity.json",
                timeout=10, headers={"User-Agent":"Mozilla/5.0"}
            )
            if r.status_code == 200:
                for item in r.json().get("data",[]):
                    t = item.get("title","").lower().strip()
                    if t: self.known.add(t)
        except Exception:
            pass

    def is_duplicate(self, finding: dict) -> bool:
        title = finding.get("title","").lower().strip()
        module = finding.get("module","")
        url = finding.get("url","")
        # Check title similarity
        for known in self.known:
            if module in known or (len(title) > 10 and title[:20] in known):
                return True
        # Check local hash
        sig = hashlib.md5(f"{module}|{url}".encode()).hexdigest()
        if sig in self.known:
            return True
        return False

    def mark_submitted(self, finding: dict):
        sig = hashlib.md5(f"{finding.get('module')}|{finding.get('url')}".encode()).hexdigest()
        self.known.add(sig)
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(list(self.known)))

    def filter(self, findings: list) -> tuple:
        unique = [f for f in findings if not self.is_duplicate(f)]
        dupes  = len(findings) - len(unique)
        return unique, dupes
