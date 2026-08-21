"""AmonStrike - Firebase Misconfiguration Module"""
import re
from .base import BaseModule

class FirebaseModule(BaseModule):
    NAME        = "firebase"
    DESCRIPTION = "Firebase - open database, storage, exposed config"

    def run(self):
        self.log("Testing Firebase misconfiguration...")
        self._find_firebase_config()
        self._test_firebase_db()
        return self.result()

    def _find_firebase_config(self):
        r = self.get("")
        if not r: return
        # Find Firebase API key (starts with AIza)
        api_keys = re.findall(r"AIza[A-Za-z0-9_\-]{30,}", r.text)
        proj_ids = re.findall(r"projectId[^a-zA-Z]{1,5}([a-zA-Z0-9_\-]+)", r.text)
        if api_keys:
            key    = api_keys[0]
            proj   = proj_ids[0] if proj_ids else "unknown"
            self.info["firebase_api_key"] = key
            self.info["firebase_project"]  = proj
            self.add_finding(
                title       = f"Firebase API Key Exposed in Source: {proj}",
                severity    = "HIGH",
                description = (
                    f"Firebase API key found in client-side JavaScript. "
                    f"Project: {proj}. Key enables access to Firebase services. "
                    "If DB rules are permissive, data can be read/written without auth."
                ),
                evidence    = (
                    f"API Key: {key[:20]}...\n"
                    f"Project ID: {proj}\n"
                    f"Test DB: https://{proj}-default-rtdb.firebaseio.com/.json"
                ),
                remediation = (
                    "Set Firebase Realtime DB rules to require auth. "
                    "Set Firestore rules to deny unauthenticated access. "
                    "Restrict API key to specific domains in Firebase console."
                ),
                url=self.url, cve="CWE-312",
            )
            self._test_open_db(proj)

    def _test_open_db(self, proj_id):
        import requests as req
        db_url = f"https://{proj_id}-default-rtdb.firebaseio.com/.json"
        try:
            r = req.get(db_url, timeout=10)
            if r.status_code == 200 and r.text.strip() not in ["null", ""]:
                self.add_finding(
                    title       = f"Firebase Database Open - No Auth Required: {proj_id}",
                    severity    = "CRITICAL",
                    description = (
                        f"Firebase Realtime Database {db_url} is publicly readable. "
                        "All data accessible without authentication."
                    ),
                    evidence    = f"URL: {db_url}\nData: {r.text[:500]}",
                    remediation = (
                        'Set rules: {"rules": {".read": "auth != null", '
                        '".write": "auth != null"}}'
                    ),
                    url=db_url, cve="CWE-284",
                )
        except Exception:
            pass

    def _test_firebase_db(self):
        host = self.parsed.hostname or ""
        if "firebaseio.com" in host:
            r = self.get("/.json")
            if r and r.status_code == 200 and len(r.text.strip()) > 4:
                self.add_finding(
                    title       = "Firebase Database Publicly Readable",
                    severity    = "CRITICAL",
                    description = "Firebase DB root accessible without authentication.",
                    evidence    = f"URL: {self.url}/.json\nData: {r.text[:400]}",
                    remediation = "Set Firebase security rules to require authentication.",
                    url=self.url + "/.json", cve="CWE-284",
                )
