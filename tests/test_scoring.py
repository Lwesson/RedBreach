import pytest

from redbreach.reporting.scoring import (
    build_vector,
    calculate_cvss,
    estimate_epss,
    score_finding,
    severity_from_cvss,
)


def test_build_vector_full():
    v = build_vector(
        attack_vector="network", attack_complexity="low", privileges_required="none",
        user_interaction="none", scope="unchanged",
        confidentiality="high", integrity="high", availability="high",
    )
    assert v == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_build_vector_defaults_when_missing():
    # missing metrics fall back to the calculator's implicit defaults
    assert build_vector() == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"


def test_score_finding_bundles_score_vector_severity_epss():
    r = score_finding(
        attack_vector="network", attack_complexity="low", privileges_required="none",
        user_interaction="none", scope="unchanged",
        confidentiality="high", integrity="high", availability="high",
    )
    assert r["cvss_score"] == 9.8
    assert r["severity"] == "critical"
    assert r["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert 0.0 <= r["epss_score"] <= 1.0


def test_score_finding_vector_matches_score_with_partial_input():
    # partial spec still yields a consistent score + vector (no crash)
    r = score_finding(confidentiality="high")
    assert r["cvss_vector"].startswith("CVSS:3.1/")
    assert r["cvss_score"] == calculate_cvss(
        attack_vector="network", attack_complexity="low", privileges_required="none",
        user_interaction="none", scope="unchanged",
        confidentiality="high", integrity="none", availability="none",
    )


def test_cvss_xss_reflected():
    """Reflected XSS scores around 6.1 (medium)."""
    score = calculate_cvss(
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="required",
        scope="changed",
        confidentiality="low",
        integrity="low",
        availability="none",
    )
    assert 5.0 <= score <= 7.0


def test_cvss_rce():
    """RCE with no auth scores 9.8+ (critical)."""
    score = calculate_cvss(
        attack_vector="network",
        attack_complexity="low",
        privileges_required="none",
        user_interaction="none",
        scope="unchanged",
        confidentiality="high",
        integrity="high",
        availability="high",
    )
    assert score >= 9.0


def test_cvss_info():
    """Info-level finding scores 0."""
    score = calculate_cvss(
        attack_vector="local",
        attack_complexity="high",
        privileges_required="high",
        user_interaction="required",
        scope="unchanged",
        confidentiality="none",
        integrity="none",
        availability="none",
    )
    assert score == 0.0


def test_severity_from_cvss():
    assert severity_from_cvss(0.0) == "info"
    assert severity_from_cvss(3.5) == "low"
    assert severity_from_cvss(5.5) == "medium"
    assert severity_from_cvss(8.0) == "high"
    assert severity_from_cvss(9.5) == "critical"


def test_estimate_epss():
    """EPSS returns a probability between 0 and 1."""
    prob = estimate_epss(cvss_score=9.8, has_public_exploit=True, age_days=30)
    assert 0.0 <= prob <= 1.0
    # Critical + public exploit should be high probability
    assert prob > 0.5


def test_epss_low_severity():
    prob = estimate_epss(cvss_score=2.0, has_public_exploit=False, age_days=365)
    assert prob < 0.3
