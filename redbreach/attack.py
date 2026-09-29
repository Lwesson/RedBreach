"""MITRE ATT&CK (and ATLAS for AI) technique mapping for findings.

Same shape as redbreach.cwe: pure data + functions, auto-applied on finding
creation and surfaced in reports. Web/API bug -> technique is necessarily
approximate (ATT&CK models adversary TTPs, not webapp CWEs); mappings pick the
closest technique an attacker would use the bug to achieve. AI categories map to
MITRE ATLAS, mobile categories to the ATT&CK Mobile matrix.
"""
from __future__ import annotations

# technique id -> (name, tactic)
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access / Privilege Escalation"),
    "T1059.007": ("Command and Scripting Interpreter: JavaScript", "Execution"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1539": ("Steal Web Session Cookie", "Credential Access"),
    "T1213": ("Data from Information Repositories", "Collection"),
    "T1133": ("External Remote Services", "Initial Access / Persistence"),
    "T1584.001": ("Compromise Infrastructure: Domains", "Resource Development"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access / Collection"),
    "T1210": ("Exploitation of Remote Services", "Lateral Movement"),
    # ATT&CK Mobile
    "T1416": ("Android Intent Hijacking", "Mobile: Privilege Escalation"),
    "T1439": ("Eavesdrop on Insecure Network Communication", "Mobile: Collection"),
    # MITRE ATLAS (AI/ML)
    "AML.T0051": ("LLM Prompt Injection", "ATLAS: ML Attack Staging"),
}

CATEGORY_ATTACK: dict[str, str] = {
    "sqli": "T1190",
    "ssrf": "T1190",
    "ssti": "T1190",
    "idor": "T1190",
    "auth_bypass": "T1190",
    "auth": "T1078",
    "ftp": "T1078",
    "xss": "T1059.007",
    "secret_in_js": "T1552.001",
    "hardcoded_secret": "T1552.001",
    "cors": "T1539",
    "graphql": "T1213",
    "sensitive_file": "T1213",
    "admin_panel": "T1133",
    "subdomain_takeover": "T1584.001",
    "tls": "T1557",
    "network_vuln": "T1210",
    "prompt_injection": "AML.T0051",
    "cleartext_traffic": "T1439",
    "exported_component": "T1416",
    # scan-phase template_ids used as category
    "sqlmap-detected": "T1190",
    "redbreach-ssrf": "T1190",
    "cors-credentialed-reflection": "T1539",
}


def classify_attack(category: str | None) -> dict | None:
    """Map a finding category to ATT&CK/ATLAS technique info, or None if unmapped."""
    if not category:
        return None
    tid = CATEGORY_ATTACK.get(category.strip().lower())
    if not tid:
        return None
    name, tactic = ATTACK_TECHNIQUES.get(tid, ("", ""))
    return {"technique": tid, "technique_name": name, "tactic": tactic}


def attack_for_category(category: str | None) -> str | None:
    """Just the technique id (for storing on a finding), or None."""
    info = classify_attack(category)
    return info["technique"] if info else None


def tactic_coverage(categories: list[str]) -> dict[str, list[str]]:
    """Map covered tactics -> the technique ids seen, from a list of finding categories."""
    coverage: dict[str, list[str]] = {}
    for c in categories:
        info = classify_attack(c)
        if not info:
            continue
        coverage.setdefault(info["tactic"], [])
        if info["technique"] not in coverage[info["tactic"]]:
            coverage[info["tactic"]].append(info["technique"])
    return coverage
