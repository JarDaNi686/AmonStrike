#!/usr/bin/env python3
"""
AmonStrike — Knowledge Base Builder (Open-Licensed Sources Only)

Sources used:
  - OWASP Testing Guide v4.2 (CC BY-SA 3.0) — owasp.org
  - HackTricks (MIT-like, free to use) — book.hacktricks.xyz
  - PayloadsAllTheThings (MIT) — swisskyrepo/PayloadsAllTheThings on GitHub
  - PortSwigger Web Academy (free, research use) — portswigger.net/web-security
  - OWASP WSTG on GitHub (CC BY-SA) — raw markdown

These cover the same attack surface as PEN-200/PEN-300 web chapters.
No OffSec copyrighted material is indexed.

Usage:
  python3 knowledge/build_kb.py              # build / refresh
  python3 knowledge/build_kb.py --query "IDOR bypass techniques"
"""

import json, os, sys, re, time, hashlib, argparse
import urllib.request, urllib.error
from pathlib import Path

KB_DIR = Path(__file__).parent / "db"
KB_DIR.mkdir(exist_ok=True)
INDEX_FILE = KB_DIR / "index.json"

# ── Open-licensed content sources ─────────────────────────────────────────
SOURCES = [
    # OWASP WSTG raw markdown (CC BY-SA 3.0)
    {
        "id": "wstg_idor",
        "title": "WSTG: Testing for Insecure Direct Object References",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md",
        "tags": ["idor", "bola", "authorization", "access-control"],
    },
    {
        "id": "wstg_auth_bypass",
        "title": "WSTG: Testing for Bypassing Authorization Schema",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.md",
        "tags": ["authorization", "bypass", "access-control"],
    },
    {
        "id": "wstg_broken_auth",
        "title": "WSTG: Testing for Bypassing Authentication Schema",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md",
        "tags": ["authentication", "bypass", "session"],
    },
    {
        "id": "wstg_sqli",
        "title": "WSTG: Testing for SQL Injection",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md",
        "tags": ["sqli", "injection", "database"],
    },
    {
        "id": "wstg_xss_reflected",
        "title": "WSTG: Testing for Reflected Cross Site Scripting",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md",
        "tags": ["xss", "reflected", "injection"],
    },
    {
        "id": "wstg_xss_stored",
        "title": "WSTG: Testing for Stored Cross Site Scripting",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md",
        "tags": ["xss", "stored", "injection"],
    },
    {
        "id": "wstg_ssrf",
        "title": "WSTG: Testing for Server-Side Request Forgery",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.md",
        "tags": ["ssrf", "injection"],
    },
    {
        "id": "wstg_jwt",
        "title": "WSTG: Testing JSON Web Tokens",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens.md",
        "tags": ["jwt", "authentication", "session"],
    },
    {
        "id": "wstg_oauth",
        "title": "WSTG: Testing for OAuth Weaknesses",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses.md",
        "tags": ["oauth", "authorization", "authentication"],
    },
    {
        "id": "wstg_business_logic",
        "title": "WSTG: Testing Business Logic",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/10-Business_Logic_Testing/00-Introduction_to_Business_Logic.md",
        "tags": ["business-logic", "logic-flaw"],
    },
    {
        "id": "wstg_api",
        "title": "WSTG: Testing GraphQL",
        "url": "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL.md",
        "tags": ["api", "graphql"],
    },
    # PayloadsAllTheThings (MIT license) — raw GitHub
    {
        "id": "patt_idor",
        "title": "PayloadsAllTheThings: IDOR",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Insecure%20Direct%20Object%20References/README.md",
        "tags": ["idor", "bola", "payloads"],
    },
    {
        "id": "patt_sqli",
        "title": "PayloadsAllTheThings: SQL Injection",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/README.md",
        "tags": ["sqli", "injection", "payloads"],
    },
    {
        "id": "patt_xss",
        "title": "PayloadsAllTheThings: XSS",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/README.md",
        "tags": ["xss", "injection", "payloads"],
    },
    {
        "id": "patt_ssrf",
        "title": "PayloadsAllTheThings: SSRF",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md",
        "tags": ["ssrf", "injection", "payloads"],
    },
    {
        "id": "patt_jwt",
        "title": "PayloadsAllTheThings: JWT",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/JSON%20Web%20Token/README.md",
        "tags": ["jwt", "authentication", "payloads"],
    },
    {
        "id": "patt_oauth",
        "title": "PayloadsAllTheThings: OAuth",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/OAuth/README.md",
        "tags": ["oauth", "authorization", "payloads"],
    },
    {
        "id": "patt_business_logic",
        "title": "PayloadsAllTheThings: Business Logic",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Business%20Logic%20Errors/README.md",
        "tags": ["business-logic", "logic-flaw", "payloads"],
    },
    {
        "id": "patt_graphql",
        "title": "PayloadsAllTheThings: GraphQL",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/GraphQL%20Injection/README.md",
        "tags": ["graphql", "api", "injection", "payloads"],
    },
    {
        "id": "patt_race",
        "title": "PayloadsAllTheThings: Race Condition",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Race%20Condition/README.md",
        "tags": ["race-condition", "logic-flaw", "payloads"],
    },
    {
        "id": "patt_nosqli",
        "title": "PayloadsAllTheThings: NoSQL Injection",
        "url": "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/NoSQL%20Injection/README.md",
        "tags": ["nosql", "injection", "payloads"],
    },
    # OWASP API Security Top 10 (CC BY-SA)
    {
        "id": "owasp_api_top10",
        "title": "OWASP API Security Top 10 2023",
        "url": "https://raw.githubusercontent.com/OWASP/API-Security/master/editions/2023/en/0xa1-broken-object-level-authorization.md",
        "tags": ["api", "idor", "bola", "authorization"],
    },
]


def _fetch(url: str, timeout=20) -> str | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AmonStrike-KB/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  [FETCH ERROR] {url}: {e}")
        return None


def _chunk(text: str, max_chars=2000) -> list[str]:
    """Split markdown text into overlapping chunks."""
    # Split on H2/H3 headers first, then by size
    sections = re.split(r'\n(?=#{1,3} )', text)
    chunks = []
    for sec in sections:
        while len(sec) > max_chars:
            chunks.append(sec[:max_chars])
            sec = sec[max_chars - 200:]  # 200-char overlap
        if sec.strip():
            chunks.append(sec.strip())
    return chunks


def _embed_tfidf(text: str) -> dict[str, float]:
    """Minimal TF-IDF-like word frequency vector (no external deps)."""
    words = re.findall(r'\b[a-z]{3,}\b', text.lower())
    freq = {}
    for w in words:
        freq[w] = freq.get(w, 0) + 1
    total = max(len(words), 1)
    return {w: c / total for w, c in freq.items()}


def _cosine(a: dict, b: dict) -> float:
    keys = set(a) & set(b)
    if not keys:
        return 0.0
    dot = sum(a[k] * b[k] for k in keys)
    mag_a = sum(v * v for v in a.values()) ** 0.5
    mag_b = sum(v * v for v in b.values()) ** 0.5
    return dot / (mag_a * mag_b + 1e-9)


def build(force=False):
    """Fetch all sources, chunk them, build the index."""
    index = []
    existing_ids = set()

    if INDEX_FILE.exists() and not force:
        existing = json.loads(INDEX_FILE.read_text())
        existing_ids = {e["source_id"] for e in existing}
        index = existing
        print(f"[KB] Loaded {len(index)} existing chunks. Updating...")

    for src in SOURCES:
        if src["id"] in existing_ids and not force:
            print(f"  [SKIP] {src['id']} already indexed")
            continue

        print(f"  [FETCH] {src['id']} — {src['title']}")
        text = _fetch(src["url"])
        if not text:
            print(f"  [WARN] Could not fetch {src['id']}")
            continue

        # Remove existing chunks from this source
        index = [e for e in index if e["source_id"] != src["id"]]

        chunks = _chunk(text)
        for i, chunk in enumerate(chunks):
            entry = {
                "source_id": src["id"],
                "title": src["title"],
                "tags": src["tags"],
                "chunk_id": f"{src['id']}_{i}",
                "text": chunk,
                "vec": _embed_tfidf(chunk),
                "hash": hashlib.md5(chunk.encode()).hexdigest()[:8],
            }
            index.append(entry)

        existing_ids.add(src["id"])
        print(f"    → {len(chunks)} chunks")
        time.sleep(0.3)  # polite crawl rate

    INDEX_FILE.write_text(json.dumps(index, indent=2))
    print(f"\n[KB] Done. Total chunks: {len(index)}")
    print(f"[KB] Index: {INDEX_FILE}")


def query(q: str, top_k=5, tag_filter: list[str] = None) -> list[dict]:
    """Return top-k most relevant chunks for the query."""
    if not INDEX_FILE.exists():
        print("[KB] No index found. Run: python3 knowledge/build_kb.py")
        return []

    index = json.loads(INDEX_FILE.read_text())
    q_vec = _embed_tfidf(q)

    scored = []
    for entry in index:
        # Tag boost: multiply score by 2 if tag matches query terms
        score = _cosine(q_vec, entry["vec"])
        if tag_filter:
            if any(t in entry["tags"] for t in tag_filter):
                score *= 1.5
        scored.append((score, entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:top_k]]


def format_context(chunks: list[dict]) -> str:
    """Format retrieved chunks as LLM context."""
    parts = []
    for i, c in enumerate(chunks, 1):
        parts.append(
            f"### Source {i}: {c['title']} [{', '.join(c['tags'])}]\n\n{c['text']}"
        )
    return "\n\n---\n\n".join(parts)


# ── CLI ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--build",  action="store_true", help="Build/refresh KB")
    ap.add_argument("--force",  action="store_true", help="Force re-fetch all")
    ap.add_argument("--query",  type=str, help="Query the KB")
    ap.add_argument("--tags",   type=str, help="Comma-separated tag filter")
    ap.add_argument("--top",    type=int, default=3, help="Top-k results")
    ap.add_argument("--stats",  action="store_true", help="Show index stats")
    args = ap.parse_args()

    if args.build or args.force:
        build(force=args.force)

    if args.query:
        tag_filter = args.tags.split(",") if args.tags else None
        results = query(args.query, top_k=args.top, tag_filter=tag_filter)
        if not results:
            print("[KB] No results.")
        else:
            for i, r in enumerate(results, 1):
                print(f"\n{'='*60}")
                print(f"[{i}] {r['title']} | tags: {r['tags']}")
                print(f"{'='*60}")
                print(r["text"][:800])
                print("...")

    if args.stats:
        if INDEX_FILE.exists():
            idx = json.loads(INDEX_FILE.read_text())
            from collections import Counter
            tag_counts = Counter(t for e in idx for t in e["tags"])
            src_counts = Counter(e["source_id"] for e in idx)
            print(f"\n[KB Stats]")
            print(f"  Total chunks: {len(idx)}")
            print(f"  Sources: {len(src_counts)}")
            print(f"  Top tags: {tag_counts.most_common(10)}")
        else:
            print("[KB] No index found.")
