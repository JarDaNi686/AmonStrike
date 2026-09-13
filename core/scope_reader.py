"""AmonStrike — H1 Scope Reader. Reads program scope before testing."""
import requests, re
from urllib.parse import urlparse

class ScopeReader:
    def __init__(self, program_handle: str = "", target: str = ""):
        self.handle = program_handle
        self.target = target
        self.in_scope = []
        self.out_scope = []
        self.wildcards = []
        self._load()

    def _load(self):
        domain = urlparse(self.target).netloc
        self.in_scope = [domain]
        if not self.handle:
            return
        try:
            r = requests.get(
                f"https://api.hackerone.com/v1/hackers/programs/{self.handle}",
                timeout=10, headers={"Accept":"application/json"}
            )
            if r.status_code == 200:
                data = r.json().get("data",{}).get("attributes",{})
                scope = data.get("structured_scope",{})
                for a in scope.get("in_scope",[]):
                    h = a.get("asset_identifier","")
                    if h.startswith("*."): self.wildcards.append(h[2:])
                    elif h: self.in_scope.append(h)
                for a in scope.get("out_of_scope",[]):
                    h = a.get("asset_identifier","")
                    if h: self.out_scope.append(h)
        except Exception:
            pass

    def is_allowed(self, url: str) -> bool:
        host = urlparse(url).netloc
        if any(o in host for o in self.out_scope):
            return False
        if host in self.in_scope:
            return True
        if any(host.endswith(w) for w in self.wildcards):
            return True
        return False

    def summary(self) -> str:
        return f"{len(self.in_scope)} in-scope, {len(self.out_scope)} out-of-scope"
