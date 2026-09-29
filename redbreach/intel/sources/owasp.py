"""OWASP WSTG static checklist source."""

from __future__ import annotations

import logging
from typing import Any

from redbreach.db import Database

logger = logging.getLogger(__name__)

# OWASP Web Security Testing Guide categories and tests
OWASP_CATEGORIES: list[dict[str, Any]] = [
    {
        "id": "WSTG-INFO",
        "name": "Information Gathering",
        "tests": [
            "WSTG-INFO-01: Conduct Search Engine Discovery Reconnaissance",
            "WSTG-INFO-02: Fingerprint Web Server",
            "WSTG-INFO-03: Review Webserver Metafiles for Information Leakage",
            "WSTG-INFO-04: Enumerate Applications on Webserver",
            "WSTG-INFO-05: Review Webpage Content for Information Leakage",
            "WSTG-INFO-06: Identify Application Entry Points",
            "WSTG-INFO-07: Map Execution Paths Through Application",
            "WSTG-INFO-08: Fingerprint Web Application Framework",
            "WSTG-INFO-09: Fingerprint Web Application",
            "WSTG-INFO-10: Map Application Architecture",
        ],
    },
    {
        "id": "WSTG-CONF",
        "name": "Configuration and Deployment Management Testing",
        "tests": [
            "WSTG-CONF-01: Test Network Infrastructure Configuration",
            "WSTG-CONF-02: Test Application Platform Configuration",
            "WSTG-CONF-03: Test File Extensions Handling for Sensitive Information",
            "WSTG-CONF-04: Review Old Backup and Unreferenced Files",
            "WSTG-CONF-05: Enumerate Infrastructure and Application Admin Interfaces",
            "WSTG-CONF-06: Test HTTP Methods",
            "WSTG-CONF-07: Test HTTP Strict Transport Security",
            "WSTG-CONF-08: Test RIA Cross Domain Policy",
            "WSTG-CONF-09: Test File Permission",
            "WSTG-CONF-10: Test for Subdomain Takeover",
            "WSTG-CONF-11: Test Cloud Storage",
        ],
    },
    {
        "id": "WSTG-IDNT",
        "name": "Identity Management Testing",
        "tests": [
            "WSTG-IDNT-01: Test Role Definitions",
            "WSTG-IDNT-02: Test User Registration Process",
            "WSTG-IDNT-03: Test Account Provisioning Process",
            "WSTG-IDNT-04: Testing for Account Enumeration and Guessable User Account",
            "WSTG-IDNT-05: Testing for Weak or Unenforced Username Policy",
        ],
    },
    {
        "id": "WSTG-ATHN",
        "name": "Authentication Testing",
        "tests": [
            "WSTG-ATHN-01: Testing for Credentials Transported over an Encrypted Channel",
            "WSTG-ATHN-02: Testing for Default Credentials",
            "WSTG-ATHN-03: Testing for Weak Lock Out Mechanism",
            "WSTG-ATHN-04: Testing for Bypassing Authentication Schema",
            "WSTG-ATHN-05: Testing for Vulnerable Remember Password",
            "WSTG-ATHN-06: Testing for Browser Cache Weaknesses",
            "WSTG-ATHN-07: Testing for Weak Password Policy",
            "WSTG-ATHN-08: Testing for Weak Security Question Answer",
            "WSTG-ATHN-09: Testing for Weak Password Change or Reset Functionalities",
            "WSTG-ATHN-10: Testing for Weaker Authentication in Alternative Channel",
        ],
    },
    {
        "id": "WSTG-ATHZ",
        "name": "Authorization Testing",
        "tests": [
            "WSTG-ATHZ-01: Testing Directory Traversal File Include",
            "WSTG-ATHZ-02: Testing for Bypassing Authorization Schema",
            "WSTG-ATHZ-03: Testing for Privilege Escalation",
            "WSTG-ATHZ-04: Testing for Insecure Direct Object References",
        ],
    },
    {
        "id": "WSTG-SESS",
        "name": "Session Management Testing",
        "tests": [
            "WSTG-SESS-01: Testing for Session Management Schema",
            "WSTG-SESS-02: Testing for Cookies Attributes",
            "WSTG-SESS-03: Testing for Session Fixation",
            "WSTG-SESS-04: Testing for Exposed Session Variables",
            "WSTG-SESS-05: Testing for Cross Site Request Forgery",
            "WSTG-SESS-06: Testing for Logout Functionality",
            "WSTG-SESS-07: Testing Session Timeout",
            "WSTG-SESS-08: Testing for Session Puzzling",
            "WSTG-SESS-09: Testing for Session Hijacking",
        ],
    },
    {
        "id": "WSTG-INPV",
        "name": "Input Validation Testing",
        "tests": [
            "WSTG-INPV-01: Testing for Reflected Cross Site Scripting",
            "WSTG-INPV-02: Testing for Stored Cross Site Scripting",
            "WSTG-INPV-03: Testing for HTTP Verb Tampering",
            "WSTG-INPV-04: Testing for HTTP Parameter Pollution",
            "WSTG-INPV-05: Testing for SQL Injection",
            "WSTG-INPV-06: Testing for LDAP Injection",
            "WSTG-INPV-07: Testing for XML Injection",
            "WSTG-INPV-08: Testing for SSI Injection",
            "WSTG-INPV-09: Testing for XPath Injection",
            "WSTG-INPV-10: Testing for IMAP SMTP Injection",
            "WSTG-INPV-11: Testing for Code Injection",
            "WSTG-INPV-12: Testing for Command Injection",
            "WSTG-INPV-13: Testing for Format String Injection",
            "WSTG-INPV-14: Testing for Incubated Vulnerability",
            "WSTG-INPV-15: Testing for HTTP Splitting Smuggling",
            "WSTG-INPV-16: Testing for HTTP Incoming Requests",
            "WSTG-INPV-17: Testing for Host Header Injection",
            "WSTG-INPV-18: Testing for Server-Side Template Injection",
            "WSTG-INPV-19: Testing for Server-Side Request Forgery",
        ],
    },
    {
        "id": "WSTG-BUSL",
        "name": "Business Logic Testing",
        "tests": [
            "WSTG-BUSL-01: Test Business Logic Data Validation",
            "WSTG-BUSL-02: Test Ability to Forge Requests",
            "WSTG-BUSL-03: Test Integrity Checks",
            "WSTG-BUSL-04: Test for Process Timing",
            "WSTG-BUSL-05: Test Number of Times a Function Can Be Used",
            "WSTG-BUSL-06: Testing for the Circumvention of Work Flows",
            "WSTG-BUSL-07: Test Defenses Against Application Misuse",
            "WSTG-BUSL-08: Test Upload of Unexpected File Types",
            "WSTG-BUSL-09: Test Upload of Malicious Files",
        ],
    },
]

# Mapping of tech/asset keywords to relevant OWASP categories
_TECH_RELEVANCE: dict[str, list[str]] = {
    "api": ["WSTG-ATHN", "WSTG-ATHZ", "WSTG-INPV", "WSTG-INFO"],
    "web": ["WSTG-INFO", "WSTG-CONF", "WSTG-SESS", "WSTG-INPV", "WSTG-BUSL"],
    "mobile": ["WSTG-ATHN", "WSTG-ATHZ", "WSTG-SESS", "WSTG-INPV"],
    "auth": ["WSTG-IDNT", "WSTG-ATHN", "WSTG-SESS"],
    "upload": ["WSTG-BUSL", "WSTG-INPV"],
    "ecommerce": ["WSTG-BUSL", "WSTG-ATHZ", "WSTG-INPV", "WSTG-SESS"],
}


class OWASPSource:
    """Static OWASP WSTG checklist, no external fetching required."""

    name = "owasp"

    def get_categories(self) -> list[dict[str, Any]]:
        """Return all OWASP WSTG categories."""
        return OWASP_CATEGORIES

    def get_tests_for_category(self, category_id: str) -> list[str]:
        """Return test list for a specific category ID."""
        for cat in OWASP_CATEGORIES:
            if cat["id"] == category_id:
                return cat["tests"]
        return []

    def get_relevant_tests(
        self,
        tech_stack: list[str] | None = None,
        asset_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return categories relevant to the given tech stack / asset type."""
        if not tech_stack and not asset_type:
            return OWASP_CATEGORIES

        relevant_ids: set[str] = set()
        keywords = [k.lower() for k in (tech_stack or [])]
        if asset_type:
            keywords.append(asset_type.lower())

        for keyword in keywords:
            for tech_key, cat_ids in _TECH_RELEVANCE.items():
                if tech_key in keyword or keyword in tech_key:
                    relevant_ids.update(cat_ids)

        if not relevant_ids:
            return OWASP_CATEGORIES

        return [cat for cat in OWASP_CATEGORIES if cat["id"] in relevant_ids]

    async def sync(self, db: Database) -> int:
        """No-op sync, data is static. Returns category count."""
        logger.info("owasp: %d static categories loaded", len(OWASP_CATEGORIES))
        return len(OWASP_CATEGORIES)
