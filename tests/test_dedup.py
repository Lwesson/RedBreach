import pytest
from redbreach.ops.dedup import deduplicate_findings, similarity_score

def test_exact_duplicates_removed():
    findings = [
        {"title": "XSS in /search", "severity": "medium", "category": "xss", "matched_at": "https://example.com/search"},
        {"title": "XSS in /search", "severity": "medium", "category": "xss", "matched_at": "https://example.com/search"},
        {"title": "SQLi in /login", "severity": "high", "category": "sqli", "matched_at": "https://example.com/login"},
    ]
    assert len(deduplicate_findings(findings)) == 2

def test_similar_findings_merged():
    findings = [
        {"title": "XSS in /search?q=", "severity": "medium", "category": "xss", "matched_at": "https://example.com/search?q=1"},
        {"title": "XSS in /search?q=", "severity": "medium", "category": "xss", "matched_at": "https://example.com/search?q=2"},
    ]
    assert len(deduplicate_findings(findings, threshold=0.9)) == 1

def test_different_findings_preserved():
    findings = [
        {"title": "XSS in /search", "severity": "medium", "category": "xss"},
        {"title": "SQLi in /login", "severity": "high", "category": "sqli"},
        {"title": "SSRF in /proxy", "severity": "critical", "category": "ssrf"},
    ]
    assert len(deduplicate_findings(findings)) == 3

def test_similarity_score_identical():
    a = {"title": "XSS", "severity": "medium", "category": "xss"}
    assert similarity_score(a, a) == 1.0

def test_similarity_score_different():
    a = {"title": "XSS in search", "severity": "medium", "category": "xss"}
    b = {"title": "SQLi in login", "severity": "high", "category": "sqli"}
    assert similarity_score(a, b) < 0.5

def test_empty_input():
    assert deduplicate_findings([]) == []

def test_keeps_highest_severity():
    findings = [
        {"title": "XSS in /search", "severity": "medium", "category": "xss"},
        {"title": "XSS in /search", "severity": "high", "category": "xss"},
    ]
    deduped = deduplicate_findings(findings)
    assert len(deduped) == 1
    assert deduped[0]["severity"] == "high"


def test_same_finding_on_different_endpoints_not_merged():
    # IDOR on /users and /orders are DISTINCT findings, must not collapse to one.
    findings = [
        {"title": "IDOR", "severity": "high", "category": "idor", "matched_at": "https://x.com/api/users/1"},
        {"title": "IDOR", "severity": "high", "category": "idor", "matched_at": "https://x.com/api/orders/1"},
    ]
    assert len(deduplicate_findings(findings)) == 2


def test_query_value_difference_still_merges():
    findings = [
        {"title": "SQLi", "severity": "high", "category": "sqli", "matched_at": "https://x.com/s?id=1"},
        {"title": "SQLi", "severity": "high", "category": "sqli", "matched_at": "https://x.com/s?id=2"},
    ]
    assert len(deduplicate_findings(findings)) == 1


def test_hygiene_finding_merges_across_hosts():
    # Missing header site-wide is reported once, so it may merge across hosts.
    findings = [
        {"title": "Missing X-Frame-Options header", "severity": "info", "category": "headers", "matched_at": "https://a.example.com/"},
        {"title": "Missing X-Frame-Options header", "severity": "info", "category": "headers", "matched_at": "https://b.example.com/"},
    ]
    assert len(deduplicate_findings(findings)) == 1
