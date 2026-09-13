"""AmonStrike — Continuous Monitor. Watches for new assets 24/7."""
import time, json, requests, subprocess, shutil
from pathlib import Path
from datetime import datetime

class ContinuousMonitor:
    def __init__(self, targets: list, interval_minutes: int = 60,
                 callback=None):
        self.targets  = targets
        self.interval = interval_minutes * 60
        self.callback = callback
        self.seen     = self._load_seen()

    def _load_seen(self) -> dict:
        p = Path.home() / ".amonstrike" / "monitor_state.json"
        try: return json.loads(p.read_text())
        except: return {}

    def _save_seen(self):
        p = Path.home() / ".amonstrike" / "monitor_state.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.seen, default=str))

    def _get_subdomains(self, domain: str) -> set:
        subs = set()
        if shutil.which("subfinder"):
            try:
                out = subprocess.run(
                    ["subfinder","-d",domain,"-silent","-timeout","30"],
                    capture_output=True, text=True, timeout=60
                ).stdout
                subs = set(out.strip().splitlines())
            except Exception:
                pass
        return subs

    def check_once(self) -> list:
        new_assets = []
        for target in self.targets:
            from urllib.parse import urlparse
            domain = urlparse(target).netloc
            current = self._get_subdomains(domain)
            previous = set(self.seen.get(domain, []))
            new = current - previous
            if new:
                new_assets.extend(list(new))
                self.seen[domain] = list(current)
                self._save_seen()
                if self.callback:
                    self.callback(new, domain)
        return new_assets

    def run_forever(self):
        print(f"Monitor started — checking every {self.interval//60}min")
        while True:
            new = self.check_once()
            if new:
                print(f"[{datetime.now().strftime('%H:%M')}] NEW: {new}")
            time.sleep(self.interval)
