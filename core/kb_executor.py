#!/usr/bin/env python3
"""
AmonStrike — KB-Augmented Executor

The executor wraps any Claude API call with retrieved knowledge context.
At scan time:
  1. Identify the vuln class being tested (idor, xss, ssrf, jwt, oauth, ...)
  2. Query the KB for relevant methodology chunks
  3. Inject as system context before the LLM reasoning step
  4. LLM proposes candidate test vectors
  5. Deterministic validators (core/validators.py) confirm/deny

This is the Planner→Executor→Verifier architecture from the survey
(PentestGPT PTT, XBOW, CAI ReAct).
"""

from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from knowledge.build_kb import query as kb_query, format_context

# ── Vuln-class → KB tag mapping ────────────────────────────────────────────
VULN_TAG_MAP = {
    "idor":           ["idor", "bola", "authorization", "access-control"],
    "bola":           ["idor", "bola", "authorization"],
    "xss":            ["xss", "injection"],
    "sqli":           ["sqli", "injection"],
    "ssrf":           ["ssrf", "injection"],
    "jwt":            ["jwt", "authentication"],
    "oauth":          ["oauth", "authorization", "authentication"],
    "business_logic": ["business-logic", "logic-flaw"],
    "graphql":        ["graphql", "api"],
    "race":           ["race-condition", "logic-flaw"],
    "nosqli":         ["nosql", "injection"],
    "auth_bypass":    ["authorization", "bypass", "authentication"],
    "api":            ["api"],
}

# ── System prompt template ─────────────────────────────────────────────────
SYSTEM_PROMPT = """\
You are AmonStrike's exploitation planner. You propose test vectors for a
specific vulnerability class against a real bug-bounty target.

RULES:
- Only propose requests within the program's stated scope.
- Do not guess at impact — output only verifiable test steps.
- Every proposed test must be confirmable by a deterministic validator.
- Output JSON: {"vectors": [{"method":"GET","path":"/...","params":{...},"rationale":"..."}]}

KNOWLEDGE BASE CONTEXT (open-licensed OWASP/PATT methodology):
{kb_context}
"""

USER_PROMPT_TEMPLATE = """\
Target: {target_url}
Scope: {scope_description}
Vuln class: {vuln_class}
Endpoint under test: {endpoint}
Auth context: {auth_context}

Propose 3-5 concrete test vectors for this vuln class on this endpoint.
"""


def get_kb_context(vuln_class: str, top_k: int = 4) -> str:
    """Retrieve relevant KB chunks for a vuln class."""
    tags = VULN_TAG_MAP.get(vuln_class.lower(), [vuln_class.lower()])
    # Primary query: class name
    results = kb_query(vuln_class, top_k=top_k, tag_filter=tags)
    if not results:
        return f"[No KB context found for {vuln_class}]"
    return format_context(results)


def build_system_prompt(vuln_class: str) -> str:
    ctx = get_kb_context(vuln_class)
    return SYSTEM_PROMPT.format(kb_context=ctx)


def build_user_prompt(target_url: str, scope_description: str,
                      vuln_class: str, endpoint: str,
                      auth_context: str = "authenticated user token") -> str:
    return USER_PROMPT_TEMPLATE.format(
        target_url=target_url,
        scope_description=scope_description,
        vuln_class=vuln_class,
        endpoint=endpoint,
        auth_context=auth_context,
    )


# ── Demo: show KB context for key vuln classes ─────────────────────────────
if __name__ == "__main__":
    from knowledge.build_kb import INDEX_FILE
    if not INDEX_FILE.exists():
        print("[!] KB not built yet. Run: python3 knowledge/build_kb.py --build")
        sys.exit(1)

    for vuln in ["idor", "jwt", "oauth", "ssrf"]:
        ctx = get_kb_context(vuln, top_k=2)
        print(f"\n{'='*60}")
        print(f"  KB context for: {vuln}")
        print(f"{'='*60}")
        print(ctx[:600])
        print("...")
