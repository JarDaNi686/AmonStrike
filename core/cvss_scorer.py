#!/usr/bin/env python3
"""
AmonStrike — CVSS v3.1 Auto-Scorer
Calculates numeric CVSS score from finding metadata.
Fixes submission_engine MIN_CVSS_SCORE filter.
"""

# CVSS v3.1 base metric weights
AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}  # Attack Vector
AC  = {"L": 0.77, "H": 0.44}                           # Attack Complexity
PR  = {"N": 0.85, "L": 0.62, "H": 0.27}               # Privileges Required
UI  = {"N": 0.85, "R": 0.62}                           # User Interaction
SC  = {"C": 0.50, "I": 0.40, "N": 0.00}               # Scope (simplified)
CI  = {"H": 0.56, "L": 0.22, "N": 0.00}               # Confidentiality
II  = {"H": 0.56, "L": 0.22, "N": 0.00}               # Integrity
AI  = {"H": 0.56, "L": 0.22, "N": 0.00}               # Availability

# Severity → default CVSS profile
SEVERITY_PROFILES = {
    "CRITICAL": {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"H"},
    "HIGH":     {"AV":"N","AC":"L","PR":"L","UI":"N","C":"H","I":"H","A":"N"},
    "MEDIUM":   {"AV":"N","AC":"L","PR":"L","UI":"R","C":"L","I":"L","A":"N"},
    "LOW":      {"AV":"L","AC":"H","PR":"L","UI":"R","C":"L","I":"N","A":"N"},
    "INFO":     {"AV":"L","AC":"H","PR":"H","UI":"R","C":"N","I":"N","A":"N"},
}

# Vuln-class overrides
VULN_PROFILES = {
    "rce":              {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"H"},
    "sqli":             {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"L"},
    "ssrf":             {"AV":"N","AC":"L","PR":"L","UI":"N","C":"H","I":"L","A":"N"},
    "idor":             {"AV":"N","AC":"L","PR":"L","UI":"N","C":"H","I":"L","A":"N"},
    "xss":              {"AV":"N","AC":"L","PR":"N","UI":"R","C":"L","I":"L","A":"N"},
    "xxe":              {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"L","A":"L"},
    "ssti":             {"AV":"N","AC":"L","PR":"L","UI":"N","C":"H","I":"H","A":"H"},
    "command_injection":{"AV":"N","AC":"L","PR":"L","UI":"N","C":"H","I":"H","A":"H"},
    "csrf":             {"AV":"N","AC":"L","PR":"N","UI":"R","C":"L","I":"L","A":"N"},
    "lfi":              {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"N","A":"N"},
    "account_takeover": {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"N"},
    "auth":             {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"N"},
    "jwt_deep":         {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"H","A":"N"},
    "credentials":      {"AV":"N","AC":"L","PR":"N","UI":"N","C":"H","I":"N","A":"N"},
    "race_condition":   {"AV":"N","AC":"H","PR":"L","UI":"N","C":"L","I":"H","A":"N"},
    "cors":             {"AV":"N","AC":"L","PR":"N","UI":"R","C":"H","I":"L","A":"N"},
    "open_redirect":    {"AV":"N","AC":"L","PR":"N","UI":"R","C":"L","I":"L","A":"N"},
    "file_upload":      {"AV":"N","AC":"L","PR":"L","UI":"N","C":"H","I":"H","A":"H"},
    "http_smuggling":   {"AV":"N","AC":"H","PR":"N","UI":"N","C":"H","I":"H","A":"N"},
    "prototype_pollution":{"AV":"N","AC":"L","PR":"N","UI":"R","C":"L","I":"L","A":"N"},
}


def calculate(finding: dict) -> dict:
    """
    Returns {"score": float, "vector": str, "severity": str}
    """
    module   = finding.get("module", "").lower()
    severity = finding.get("severity", "MEDIUM").upper()

    profile = VULN_PROFILES.get(module) or SEVERITY_PROFILES.get(severity, SEVERITY_PROFILES["MEDIUM"])

    av_val = AV.get(profile["AV"], 0.85)
    ac_val = AC.get(profile["AC"], 0.77)
    pr_val = PR.get(profile["PR"], 0.85)
    ui_val = UI.get(profile["UI"], 0.85)
    c_val  = CI.get(profile["C"],  0.56)
    i_val  = II.get(profile["I"],  0.56)
    a_val  = AI.get(profile["A"],  0.00)

    # CVSS v3.1 ISS
    iss = 1 - (1 - c_val) * (1 - i_val) * (1 - a_val)

    # Impact sub-score
    impact = 6.42 * iss

    # Exploitability
    exploit = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        base = 0.0
    else:
        base = min(impact + exploit, 10.0)
        # Round up to 1 decimal
        import math
        base = math.ceil(base * 10) / 10

    sev = (
        "CRITICAL" if base >= 9.0 else
        "HIGH"     if base >= 7.0 else
        "MEDIUM"   if base >= 4.0 else
        "LOW"      if base >= 0.1 else
        "INFO"
    )

    vector = (
        f"CVSS:3.1/AV:{profile['AV']}/AC:{profile['AC']}"
        f"/PR:{profile['PR']}/UI:{profile['UI']}/S:U"
        f"/C:{profile['C']}/I:{profile['I']}/A:{profile['A']}"
    )

    return {"score": base, "vector": vector, "severity": sev}


def score_findings(findings: list) -> list:
    """Add cvss_score and cvss_vector to every finding in place."""
    for f in findings:
        result = calculate(f)
        f["cvss_score"]  = result["score"]
        f["cvss_vector"] = result["vector"]
        # Upgrade severity if CVSS disagrees upward
        sev_order = ["INFO","LOW","MEDIUM","HIGH","CRITICAL"]
        current = f.get("severity","MEDIUM").upper()
        cvss_sev = result["severity"]
        if sev_order.index(cvss_sev) > sev_order.index(current):
            f["severity"] = cvss_sev
    return findings
