#!/usr/bin/env python3
"""
AmonStrike — Deterministic Validator Subsystem

The single most important lesson from the state-of-the-art survey:
    "The LLM finds candidate bugs but must NOT be trusted to confirm them."
Every system that gets paid on HackerOne (XBOW, Big Sleep, MAPTA) separates a
generative/exploratory layer from a DETERMINISTIC verification layer that proves
a finding with non-LLM logic. HackerOne's Code of Conduct now bans unverified
AI-generated reports outright.

This module is that verification layer. A finding is only REPORTABLE if its
class validator returns a CONFIRMED verdict backed by deterministic evidence.

Validators (per vuln class):
  IDORValidator   — differential access control: attacker reads victim's object,
                    the object provably belongs to a different principal, AND an
                    unauthenticated request is denied (rules out "public data").
  XSSValidator    — headless browser confirms the JS payload actually EXECUTED
                    (a unique marker fires), not merely that it reflected.
  SSRFValidator   — out-of-band: target must call back to a controlled listener
                    carrying a unique token (proves server-side request).

No LLM is used to decide a verdict. Ever.
"""

from __future__ import annotations
import json
import time
import uuid
import http.server
import socketserver
import threading
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional, Callable


# ── Verdict ────────────────────────────────────────────────────────
CONFIRMED   = "CONFIRMED"
UNCONFIRMED = "UNCONFIRMED"
ERROR       = "ERROR"


@dataclass
class Verdict:
    status:   str                       # CONFIRMED | UNCONFIRMED | ERROR
    vuln:     str                       # e.g. "idor", "xss", "ssrf"
    evidence: str = ""                  # deterministic proof, human-readable
    detail:   dict = field(default_factory=dict)

    @property
    def confirmed(self) -> bool:
        return self.status == CONFIRMED

    def __str__(self) -> str:
        return f"[{self.status}] {self.vuln}: {self.evidence}"


def _http(method, url, token=None, headers=None, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)


# ── IDOR / BOLA validator ──────────────────────────────────────────
class IDORValidator:
    """
    Differential access-control test. A basket/object IDOR is CONFIRMED only if
    ALL of these hold — this is what rules out false positives on public data:

      1. Attacker's token reads the victim object -> HTTP 200.
      2. The returned object provably belongs to a DIFFERENT principal
         (owner field != attacker's own id).
      3. An UNAUTHENTICATED request to the same object is denied (401/403),
         proving the data is access-controlled, not simply public.

    owner_of(body) -> principal id, supplied by the caller (app-specific).
    """

    def __init__(self, owner_field_extractor: Callable[[str], Optional[object]]):
        self.owner_of = owner_field_extractor

    def validate(self, object_url: str,
                 attacker_token: str, attacker_principal,
                 victim_token: Optional[str] = None) -> Verdict:
        # 1. Attacker reads the object
        code_a, body_a = _http("GET", object_url, token=attacker_token)
        if code_a != 200:
            return Verdict(UNCONFIRMED, "idor",
                           f"Attacker got HTTP {code_a}, not 200 — no access.")

        owner = self.owner_of(body_a)
        if owner is None:
            return Verdict(UNCONFIRMED, "idor",
                           "Could not extract an owner id from the response.")

        # 2. Object must belong to someone else
        if str(owner) == str(attacker_principal):
            return Verdict(UNCONFIRMED, "idor",
                           f"Object owner ({owner}) == attacker "
                           f"({attacker_principal}) — this is their own object.")

        # 3. Unauthenticated request must be denied (rules out public data)
        code_anon, _ = _http("GET", object_url, token=None)
        if code_anon == 200:
            return Verdict(UNCONFIRMED, "idor",
                           f"Object is readable UNAUTHENTICATED (HTTP {code_anon}) "
                           f"— public data, not an access-control bug.")

        return Verdict(
            CONFIRMED, "idor",
            f"Attacker (principal {attacker_principal}) read object owned by "
            f"principal {owner}: HTTP 200 authenticated, but HTTP {code_anon} "
            f"unauthenticated. Broken object-level authorization confirmed.",
            detail={"object_url": object_url, "attacker": attacker_principal,
                    "victim_owner": owner, "anon_status": code_anon},
        )


# ── Out-of-band callback listener (for SSRF / blind injection) ─────
class OOBListener:
    """
    Minimal interactsh-style local callback catcher. Start it, embed the unique
    URL in a payload, and a hit proves the server made the request.
    """

    def __init__(self, host="127.0.0.1", port=0):
        self.token = uuid.uuid4().hex
        self.hits  = []
        handler_hits = self.hits
        token = self.token

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if token in self.path:
                    handler_hits.append({"path": self.path,
                                         "at": time.time(),
                                         "from": self.client_address[0]})
                self.send_response(200); self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):  # silence
                pass

        self._srv = socketserver.TCPServer((host, port), H)
        self.host, self.port = self._srv.server_address
        self._t = threading.Thread(target=self._srv.serve_forever, daemon=True)

    @property
    def callback_url(self) -> str:
        return f"http://{self.host}:{self.port}/{self.token}"

    def __enter__(self):
        self._t.start(); return self

    def __exit__(self, *a):
        self._srv.shutdown()

    def got_hit(self, wait=3.0) -> bool:
        deadline = time.time() + wait
        while time.time() < deadline:
            if self.hits:
                return True
            time.sleep(0.1)
        return bool(self.hits)


class SSRFValidator:
    """
    CONFIRMED only if injecting the OOB callback URL into `param` causes the
    target server to fetch it (a hit lands on the listener).
    inject(url, param, callback_url) -> performs the request; caller supplies it.
    """

    def validate(self, inject: Callable[[str], None]) -> Verdict:
        with OOBListener() as oob:
            try:
                inject(oob.callback_url)
            except Exception as e:
                return Verdict(ERROR, "ssrf", f"Injection failed: {e}")
            if oob.got_hit(wait=5.0):
                return Verdict(CONFIRMED, "ssrf",
                               f"Server fetched the out-of-band URL "
                               f"({oob.callback_url}) — SSRF confirmed.",
                               detail={"hits": oob.hits})
            return Verdict(UNCONFIRMED, "ssrf",
                           "No callback received within 5s — not confirmed.")


class XSSValidator:
    """
    CONFIRMED only if a headless browser proves the payload EXECUTED (a unique
    marker set by injected JS), not merely reflected in the HTML. Requires
    Playwright; degrades to ERROR (never a false CONFIRMED) if unavailable.
    """

    def validate(self, page_url: str) -> Verdict:
        marker = "amon_" + uuid.uuid4().hex[:12]
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return Verdict(ERROR, "xss",
                           "Playwright unavailable — cannot confirm execution.")
        fired = {"v": False}
        try:
            with sync_playwright() as p:
                b = p.chromium.launch(headless=True, args=["--no-sandbox"])
                pg = b.new_page()
                # Any dialog opening with our marker = script executed
                pg.on("dialog", lambda d: (fired.__setitem__("v", marker in (d.message or "")),
                                           d.dismiss()))
                pg.on("console", lambda m: fired.__setitem__("v", fired["v"] or marker in m.text))
                pg.goto(page_url.replace("__MARKER__", marker),
                        wait_until="networkidle", timeout=15000)
                pg.wait_for_timeout(1500)
                b.close()
        except Exception as e:
            return Verdict(ERROR, "xss", f"Headless run failed: {e}")
        if fired["v"]:
            return Verdict(CONFIRMED, "xss",
                           f"Injected JS executed in a real browser "
                           f"(marker {marker} fired). Reflected/DOM XSS confirmed.")
        return Verdict(UNCONFIRMED, "xss",
                       "Payload did not execute in a headless browser.")


# ── Gate ───────────────────────────────────────────────────────────
def gate(finding: dict, verdict: Verdict) -> dict:
    """
    Attach a verdict to a finding and mark reportability. Only CONFIRMED
    findings are allowed downstream to the report generator.
    """
    finding = dict(finding)
    finding["validated"]    = verdict.confirmed
    finding["verdict"]      = verdict.status
    finding["proof"]        = verdict.evidence
    finding["reportable"]   = verdict.confirmed
    if verdict.confirmed and verdict.evidence:
        # fold deterministic proof into the evidence the report will show
        finding["evidence"] = (finding.get("evidence", "") +
                               "\n\n[VALIDATOR PROOF] " + verdict.evidence).strip()
    return finding


if __name__ == "__main__":
    # Self-contained proof the differential IDOR validator distinguishes a
    # real access-control bug from public data and from own-object access —
    # no external target needed.
    import re

    def make_server(vulnerable: bool, requires_auth: bool):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                # /obj/<id> ; token via Authorization: Bearer <principal>
                m = re.match(r"/obj/(\d+)", self.path)
                if not m:
                    self.send_response(404); self.end_headers(); return
                oid  = int(m.group(1))
                auth = self.headers.get("Authorization", "")
                principal = auth.replace("Bearer ", "") if auth else None
                if requires_auth and not principal:
                    self.send_response(401); self.end_headers(); return
                # owner of object N is principal N
                if not vulnerable and str(principal) != str(oid):
                    self.send_response(403); self.end_headers(); return
                self.send_response(200)
                self.send_header("Content-Type", "application/json"); self.end_headers()
                self.wfile.write(json.dumps({"id": oid, "ownerId": oid,
                                             "secret": f"data-of-user-{oid}"}).encode())
            def log_message(self, *a): pass
        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, srv.server_address[1]

    owner_of = lambda body: (json.loads(body).get("ownerId")
                             if body.strip().startswith("{") else None)
    v = IDORValidator(owner_of)

    print("=== IDOR validator self-test ===")
    # Case A: genuinely vulnerable + auth-gated  -> CONFIRMED
    s, port = make_server(vulnerable=True, requires_auth=True)
    r = v.validate(f"http://127.0.0.1:{port}/obj/2",
                   attacker_token="1", attacker_principal="1")
    print("A vulnerable+authed :", r); assert r.confirmed, "should confirm"
    s.shutdown()

    # Case B: proper access control -> UNCONFIRMED (attacker gets 403)
    s, port = make_server(vulnerable=False, requires_auth=True)
    r = v.validate(f"http://127.0.0.1:{port}/obj/2",
                   attacker_token="1", attacker_principal="1")
    print("B access-controlled :", r); assert not r.confirmed, "should not confirm"
    s.shutdown()

    # Case C: public data (no auth required) -> UNCONFIRMED (rules out FP)
    s, port = make_server(vulnerable=True, requires_auth=False)
    r = v.validate(f"http://127.0.0.1:{port}/obj/2",
                   attacker_token="1", attacker_principal="1")
    print("C public data       :", r); assert not r.confirmed, "public != IDOR"
    s.shutdown()

    print("\nAll IDOR validator cases passed — CONFIRMED only for the real bug.")
