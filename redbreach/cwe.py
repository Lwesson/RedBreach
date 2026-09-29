"""CWE classification for findings, with MITRE CWE Top 25 (2023) coverage.

Pure data + functions so both persistence (db) and reporting can use it without
a circular import. Maps redbreach's finding categories to a primary CWE id, and
tracks which map into the CWE Top 25 (directly or via a Top-25 parent, e.g. IDOR's
CWE-639 rolls up to CWE-862 Missing Authorization).
"""
from __future__ import annotations

# MITRE CWE Top 25 Most Dangerous Software Weaknesses (2023).
CWE_TOP_25_2023: set[str] = {
    "CWE-787", "CWE-79", "CWE-89", "CWE-416", "CWE-78", "CWE-20", "CWE-125",
    "CWE-22", "CWE-352", "CWE-434", "CWE-862", "CWE-476", "CWE-287", "CWE-190",
    "CWE-502", "CWE-77", "CWE-119", "CWE-798", "CWE-918", "CWE-306", "CWE-362",
    "CWE-269", "CWE-94", "CWE-863", "CWE-276",
}

CWE_NAMES: dict[str, str] = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-601": "Open Redirect",
    "CWE-942": "Permissive Cross-domain Policy (CORS)",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-284": "Improper Access Control",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-614": "Sensitive Cookie Without Secure/HttpOnly",
    "CWE-916": "Use of Password Hash With Insufficient Effort",
    "CWE-1427": "Improper Neutralization of Input Used for LLM Prompt",
    "CWE-1336": "Server-Side Template Injection",
    "CWE-94": "Improper Control of Generation of Code (Code Injection)",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-926": "Improper Export of Android Application Components",
    "CWE-489": "Active Debug Code",
    "CWE-530": "Exposure of Backup File to Unauthorized Control Sphere",
}

# category / template_id -> (primary_cwe, related_top25_parent_or_None)
CATEGORY_CWE: dict[str, tuple[str, str | None]] = {
    "sqli": ("CWE-89", None),
    "xss": ("CWE-79", None),
    "ssrf": ("CWE-918", None),
    "ssti": ("CWE-1336", "CWE-94"),  # template injection -> Top-25 code injection
    "csrf": ("CWE-352", None),
    "auth": ("CWE-287", None),
    "auth_bypass": ("CWE-306", None),
    "idor": ("CWE-639", "CWE-862"),        # rolls up to Top-25 Missing Authorization
    "secret_in_js": ("CWE-798", None),
    "hardcoded_secret": ("CWE-798", None),
    "cleartext_traffic": ("CWE-319", None),
    "exported_component": ("CWE-926", "CWE-862"),
    "debuggable": ("CWE-489", None),
    "backup_allowed": ("CWE-530", None),
    "open_redirect": ("CWE-601", None),
    "redirect": ("CWE-601", None),
    "cors": ("CWE-942", None),
    "graphql": ("CWE-200", None),
    "headers": ("CWE-693", None),
    "sensitive_file": ("CWE-200", None),
    "admin_panel": ("CWE-284", None),
    "subdomain_takeover": ("CWE-284", None),
    "tls": ("CWE-326", None),
    "ftp": ("CWE-319", None),
    "prompt_injection": ("CWE-1427", None),
    # scan-phase template_ids used as category
    "sqlmap-detected": ("CWE-89", None),
    "redbreach-ssrf": ("CWE-918", None),
    "cors-credentialed-reflection": ("CWE-942", None),
    "csp-unsafe-inline": ("CWE-693", None),
    "cookie-flags": ("CWE-614", None),
    "redbreach-digest-crack": ("CWE-916", None),
}


def classify_cwe(category: str | None) -> dict | None:
    """Map a finding category to CWE info, or None if unmapped."""
    if not category:
        return None
    entry = CATEGORY_CWE.get(category.strip().lower())
    if not entry:
        return None
    cwe, related = entry
    return {
        "cwe": cwe,
        "cwe_name": CWE_NAMES.get(cwe, ""),
        "in_top25": cwe in CWE_TOP_25_2023,
        "related_top25": related if related in CWE_TOP_25_2023 else None,
    }


def cwe_for_category(category: str | None) -> str | None:
    """Just the primary CWE id (for storing on a finding), or None."""
    info = classify_cwe(category)
    return info["cwe"] if info else None


def top25_coverage(categories: list[str]) -> set[str]:
    """Which CWE Top 25 ids are covered by these finding categories (direct or via parent)."""
    covered: set[str] = set()
    for c in categories:
        info = classify_cwe(c)
        if not info:
            continue
        if info["in_top25"]:
            covered.add(info["cwe"])
        elif info["related_top25"]:
            covered.add(info["related_top25"])
    return covered
