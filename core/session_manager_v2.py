#!/usr/bin/env python3
"""
AmonStrike — Session Manager v2
Maintains authenticated sessions, auto re-auth on expiry, cookie/token rotation.
"""
import time, json, requests
from pathlib import Path

SESSION_STORE = Path("data/sessions")


class SessionManager:
    def __init__(self, target: str):
        self.target    = target
        self.session   = requests.Session()
        self.auth_fn   = None   # Callable: () -> bool
        self.auth_time = 0
        self.ttl       = 1800   # re-auth after 30 min
        self._load()

    def register_auth(self, fn):
        """Register auth callable. fn() must return True on success."""
        self.auth_fn = fn

    def ensure_auth(self) -> bool:
        if time.time() - self.auth_time < self.ttl:
            return True
        if self.auth_fn:
            ok = self.auth_fn()
            if ok:
                self.auth_time = time.time()
                self._save()
            return ok
        return False

    def request(self, method: str, url: str, **kwargs):
        """Auth-aware request. Re-auths transparently on 401/403."""
        resp = self._do(method, url, **kwargs)
        if resp and resp.status_code in (401, 403):
            self.auth_time = 0   # Force re-auth
            self.ensure_auth()
            resp = self._do(method, url, **kwargs)
        return resp

    def _do(self, method, url, **kwargs):
        try:
            fn = getattr(self.session, method.lower())
            return fn(url, timeout=20, verify=False, **kwargs)
        except Exception:
            return None

    def _save(self):
        SESSION_STORE.mkdir(parents=True, exist_ok=True)
        safe = self.target.replace("://", "_").replace("/", "_")
        data = {
            "cookies":   dict(self.session.cookies),
            "headers":   dict(self.session.headers),
            "auth_time": self.auth_time,
        }
        (SESSION_STORE / f"{safe}.json").write_text(json.dumps(data))

    def _load(self):
        safe = self.target.replace("://", "_").replace("/", "_")
        f = SESSION_STORE / f"{safe}.json"
        if f.exists():
            try:
                data = json.loads(f.read_text())
                self.session.cookies.update(data.get("cookies", {}))
                self.auth_time = data.get("auth_time", 0)
            except Exception:
                pass
