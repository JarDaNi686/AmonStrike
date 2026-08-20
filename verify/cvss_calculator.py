"""
AmonStrike — CVSS v3.1 Calculator
Full implementation of the Common Vulnerability Scoring System v3.1.

Every finding gets a proper CVSS score for professional reporting.
CVSS is required for HackerOne, Bugcrowd, and CVE submissions.

Reference: https://www.first.org/cvss/v3.1/specification-document
"""

import math
from dataclasses import dataclass
from typing import Optional


# ── CVSS v3.1 Metric Values ───────────────────────────────────

ATTACK_VECTOR = {
    "N": ("Network",          0.85),
    "A": ("Adjacent Network", 0.62),
    "L": ("Local",            0.55),
    "P": ("Physical",         0.20),
}

ATTACK_COMPLEXITY = {
    "L": ("Low",  0.77),
    "H": ("High", 0.44),
}

PRIVILEGES_REQUIRED = {
    "N": {"changed": 0.85, "unchanged": 0.85},
    "L": {"changed": 0.50, "unchanged": 0.62},
    "H": {"changed": 0.50, "unchanged": 0.27},
}

USER_INTERACTION = {
    "N": ("None",     0.85),
    "R": ("Required", 0.62),
}

SCOPE = {
    "U": "Unchanged",
    "C": "Changed",
}

IMPACT = {
    "N": ("None",     0.00),
    "L": ("Low",      0.22),
    "H": ("High",     0.56),
}

# Severity thresholds
SEVERITY_RATINGS = [
    (0.0,  "None"),
    (0.1,  "Low"),
    (4.0,  "Medium"),
    (7.0,  "High"),
    (9.0,  "Critical"),
]


@dataclass
class CVSSVector:
    """CVSS v3.1 vector components."""
    attack_vector:       str = "N"   # N/A/L/P
    attack_complexity:   str = "L"   # L/H
    privileges_required: str = "N"   # N/L/H
    user_interaction:    str = "N"   # N/R
    scope:               str = "U"   # U/C
    confidentiality:     str = "N"   # N/L/H
    integrity:           str = "N"   # N/L/H
    availability:        str = "N"   # N/L/H

    def to_string(self) -> str:
        return (f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
                f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
                f"/S:{self.scope}/C:{self.confidentiality}"
                f"/I:{self.integrity}/A:{self.availability}")

    @classmethod
    def from_string(cls, vector: str) -> "CVSSVector":
        """Parse CVSS vector string."""
        parts = {}
        for part in vector.split("/"):
            if ":" in part:
                k, v = part.split(":", 1)
                parts[k] = v
        return cls(
            attack_vector=       parts.get("AV","N"),
            attack_complexity=   parts.get("AC","L"),
            privileges_required= parts.get("PR","N"),
            user_interaction=    parts.get("UI","N"),
            scope=               parts.get("S","U"),
            confidentiality=     parts.get("C","N"),
            integrity=           parts.get("I","N"),
            availability=        parts.get("A","N"),
        )


class CVSSCalculator:
    """
    CVSS v3.1 Base Score Calculator.
    Implements the full FIRST specification.
    """

    def calculate(self, vector: CVSSVector) -> dict:
        """Calculate CVSS v3.1 base score from vector."""
        scope_changed = vector.scope == "C"

        # Impact sub-scores
        isc_conf = IMPACT.get(vector.confidentiality, ("None",0.0))[1]
        isc_int  = IMPACT.get(vector.integrity,        ("None",0.0))[1]
        isc_avail= IMPACT.get(vector.availability,     ("None",0.0))[1]

        # ISCBase
        isc_base = 1.0 - ((1 - isc_conf) * (1 - isc_int) * (1 - isc_avail))

        # Impact score
        if scope_changed:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)
        else:
            impact = 6.42 * isc_base

        # Exploitability score
        av  = ATTACK_VECTOR.get(vector.attack_vector, ("N",0.85))[1]
        ac  = ATTACK_COMPLEXITY.get(vector.attack_complexity, ("L",0.77))[1]
        pr_map = PRIVILEGES_REQUIRED.get(vector.privileges_required, {"changed":0.85,"unchanged":0.85})
        pr  = pr_map["changed"] if scope_changed else pr_map["unchanged"]
        ui  = USER_INTERACTION.get(vector.user_interaction, ("N",0.85))[1]

        exploitability = 8.22 * av * ac * pr * ui

        # Base score
        if impact <= 0:
            base_score = 0.0
        elif scope_changed:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)

        # Round up to 1 decimal
        base_score = self._round_up(base_score)

        severity = self._severity(base_score)

        return {
            "score":         base_score,
            "severity":      severity,
            "vector":        vector.to_string(),
            "impact":        round(impact, 2),
            "exploitability":round(exploitability, 2),
            "detail": {
                "av":  ATTACK_VECTOR.get(vector.attack_vector,("N","Network"))[0],
                "ac":  ATTACK_COMPLEXITY.get(vector.attack_complexity,("L","Low"))[0],
                "pr":  {k:PRIVILEGES_REQUIRED.get(k,{}) for k in ["N","L","H"]}.get(vector.privileges_required,{}).get("unchanged","None"),
                "ui":  USER_INTERACTION.get(vector.user_interaction,("N","None"))[0],
                "scope": SCOPE.get(vector.scope,"Unchanged"),
                "conf": IMPACT.get(vector.confidentiality,("None","None"))[0],
                "int":  IMPACT.get(vector.integrity,("None","None"))[0],
                "avail":IMPACT.get(vector.availability,("None","None"))[0],
            }
        }

    def score_finding(self, finding: dict) -> dict:
        """Auto-score a finding based on its type and severity."""
        vector = self._finding_to_vector(finding)
        result = self.calculate(vector)
        return result

    def _finding_to_vector(self, finding: dict) -> CVSSVector:
        """Map a finding to a CVSS vector based on vuln type and severity."""
        title  = finding.get("title","").lower()
        module = finding.get("module","").lower()
        sev    = finding.get("severity","MEDIUM")

        # Pre-defined vectors for common vulnerability types
        vuln_vectors = {
            "sql injection":         CVSSVector("N","L","N","N","C","H","H","H"),
            "sqli":                  CVSSVector("N","L","N","N","C","H","H","H"),
            "rce":                   CVSSVector("N","L","N","N","C","H","H","H"),
            "remote code execution": CVSSVector("N","L","N","N","C","H","H","H"),
            "xxe":                   CVSSVector("N","L","N","N","U","H","L","N"),
            "ssrf":                  CVSSVector("N","L","N","N","C","H","L","N"),
            "xss":                   CVSSVector("N","L","N","R","C","L","L","N"),
            "csrf":                  CVSSVector("N","L","N","R","U","N","L","N"),
            "idor":                  CVSSVector("N","L","L","N","U","H","H","N"),
            "auth":                  CVSSVector("N","L","N","N","U","H","H","N"),
            "lfi":                   CVSSVector("N","L","N","N","U","H","N","N"),
            "cors":                  CVSSVector("N","L","N","R","U","L","N","N"),
            "takeover":              CVSSVector("N","L","N","N","U","H","H","N"),
            "default credentials":   CVSSVector("N","L","N","N","C","H","H","H"),
            "http request smuggling":CVSSVector("N","H","N","N","C","H","H","H"),
            "cache poison":          CVSSVector("N","H","N","N","C","H","L","N"),
            "jwt":                   CVSSVector("N","L","N","N","U","H","H","N"),
            "oauth":                 CVSSVector("N","L","N","R","C","H","H","N"),
        }

        # Match by title keywords
        for keyword, vector in vuln_vectors.items():
            if keyword in title or keyword in module:
                return vector

        # Default vectors by severity
        defaults = {
            "CRITICAL": CVSSVector("N","L","N","N","C","H","H","H"),
            "HIGH":     CVSSVector("N","L","N","N","U","H","H","N"),
            "MEDIUM":   CVSSVector("N","L","L","N","U","L","L","N"),
            "LOW":      CVSSVector("L","L","L","N","U","L","N","N"),
            "INFO":     CVSSVector("N","H","N","R","U","N","N","N"),
        }
        return defaults.get(sev, defaults["MEDIUM"])

    def _round_up(self, score: float) -> float:
        """CVSS round-up function (ceiling to 1 decimal)."""
        return math.ceil(score * 10) / 10

    def _severity(self, score: float) -> str:
        """Map score to severity rating."""
        rating = "None"
        for threshold, name in SEVERITY_RATINGS:
            if score >= threshold:
                rating = name
        return rating

    def format_report(self, result: dict) -> str:
        """Format CVSS result for inclusion in reports."""
        return (
            f"CVSS v3.1 Score: {result['score']} ({result['severity']})\n"
            f"Vector: {result['vector']}\n"
            f"Impact: {result['impact']} | Exploitability: {result['exploitability']}\n"
            f"AV:{result['detail']['av']} / "
            f"AC:{result['detail']['ac']} / "
            f"PR:{result['detail']['pr']} / "
            f"UI:{result['detail']['ui']} / "
            f"S:{result['detail']['scope']} / "
            f"C:{result['detail']['conf']} / "
            f"I:{result['detail']['int']} / "
            f"A:{result['detail']['avail']}"
        )


# ── Common vulnerability CVSS scores (reference) ─────────────

COMMON_SCORES = {
    "SQL Injection (auth bypass)":    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "SQL Injection (data read)":      ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "Stored XSS":                     ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",  5.4),
    "Reflected XSS":                  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  6.1),
    "RCE (unauthenticated)":          ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "SSRF (internal network access)": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",  9.3),
    "IDOR (data access)":             ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",  8.1),
    "XXE (file read)":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",  8.2),
    "Path Traversal":                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  7.5),
    "Open Redirect":                  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",  6.1),
    "CSRF":                           ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",  4.3),
    "Missing HTTPS":                  ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",  4.8),
    "Default Credentials":            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    "Subdomain Takeover":             ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  9.1),
    "HTTP Request Smuggling":         ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",  9.0),
}


# ── Tests ─────────────────────────────────────────────────────

def run_regression_tests():
    print("\n=== CVSS CALCULATOR REGRESSION TESTS ===")
    passed = failed = 0
    calc = CVSSCalculator()

    tests = [
        # Known CVSS scores
        ("Critical RCE = 10.0",
         lambda: calc.calculate(CVSSVector("N","L","N","N","C","H","H","H"))["score"] == 10.0),

        ("High SQLi >= 8.0",
         lambda: calc.calculate(CVSSVector("N","L","N","N","U","H","H","H"))["score"] >= 8.0),

        ("Medium XSS ~ 6.1",
         lambda: 5.0 <= calc.calculate(CVSSVector("N","L","N","R","C","L","L","N"))["score"] <= 7.0),

        ("Low CSRF ~ 4.3",
         lambda: 3.5 <= calc.calculate(CVSSVector("N","L","N","R","U","N","L","N"))["score"] <= 5.0),

        ("Zero impact = 0.0",
         lambda: calc.calculate(CVSSVector("N","L","N","N","U","N","N","N"))["score"] == 0.0),

        # Severity labels
        ("Score 10.0 = Critical",
         lambda: calc.calculate(CVSSVector("N","L","N","N","C","H","H","H"))["severity"] == "Critical"),

        ("Score 0.0 = None",
         lambda: calc.calculate(CVSSVector("N","L","N","N","U","N","N","N"))["severity"] == "None"),

        # Vector string
        ("Vector string format correct",
         lambda: "CVSS:3.1/AV:N/AC:L" in CVSSVector("N","L","N","N","U","H","N","N").to_string()),

        # From string
        ("Parse vector string",
         lambda: (
             v := CVSSVector.from_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
             v.attack_vector == "N" and v.confidentiality == "H"
         )[1]),

        # Auto-score finding
        ("SQL injection auto-score is Critical",
         lambda: calc.score_finding({
             "title":"SQL Injection","module":"sqli","severity":"CRITICAL"
         })["score"] >= 9.0),

        ("XSS auto-score is Medium/High",
         lambda: calc.score_finding({
             "title":"Reflected XSS","module":"xss","severity":"MEDIUM"
         })["score"] >= 4.0),

        # Format report
        ("Format report contains score",
         lambda: "CVSS v3.1" in calc.format_report(
             calc.calculate(CVSSVector("N","L","N","N","U","H","N","N"))
         )),

        # Round-up function
        ("Round up works correctly",
         lambda: calc._round_up(7.123) == 7.2),

        # Common scores reference
        ("Common scores reference populated",
         lambda: len(COMMON_SCORES) >= 10),
    ]

    for name, fn in tests:
        try:
            if fn():
                passed += 1
                print(f"  ✓ {name}")
            else:
                failed += 1
                print(f"  ✗ {name}")
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} — {e}")

    print(f"\n  Passed: {passed}  Failed: {failed}")
    return passed, failed


if __name__ == "__main__":
    import sys
    calc = CVSSCalculator()

    # Demo
    print("\nCVSS v3.1 Calculator Demo")
    print("="*50)
    for name, (vector_str, expected) in COMMON_SCORES.items():
        v = CVSSVector.from_string(vector_str)
        r = calc.calculate(v)
        print(f"  {name[:40]:<40} {r['score']:>5} ({r['severity']})")

    rp, rf = run_regression_tests()
    sys.exit(0 if rf == 0 else 1)
