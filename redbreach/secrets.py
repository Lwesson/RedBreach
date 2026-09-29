"""Shared hardcoded-secret detection used by web (JS) and mobile (APK) analysis.

Central home for the credential regexes so web_enum and the mobile module do not
drift. Matches are redacted before storage (minimum-demonstration, red line 1).
"""
from __future__ import annotations

import re

SECRET_PATTERNS: dict[str, "re.Pattern"] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "gcp_service_account": re.compile(r'"type":\s*"service_account"'),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "stripe_key": re.compile(r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
    "firebase_url": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
}


def redact(secret: str, keep: int = 4) -> str:
    """Show only the first/last few chars so the finding proves existence, not the value."""
    s = secret.strip()
    if len(s) <= keep * 2:
        return s[0] + "***" if s else ""
    return f"{s[:keep]}...{s[-keep:]}"


def scan_secrets(text: str, source: str = "", severity: str = "high") -> list[dict]:
    """Return finding dicts for every hardcoded secret pattern matched in *text*."""
    findings: list[dict] = []
    if not text:
        return findings
    for name, pattern in SECRET_PATTERNS.items():
        seen: set[str] = set()
        for m in pattern.finditer(text):
            value = m.group(0)
            if value in seen:
                continue
            seen.add(value)
            findings.append({
                "type": "finding",
                "title": f"Hardcoded secret ({name})",
                "severity": severity,
                "category": "hardcoded_secret",
                "host": source,
                "matched_at": source,
                "template_id": f"secret-{name}",
                "extracted_results": f"{name}={redact(value)}",
                "description": f"Potential {name} hardcoded in {source or 'source'}.",
            })
    return findings
