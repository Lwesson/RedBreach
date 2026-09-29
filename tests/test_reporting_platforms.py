import pytest

from redbreach.reporting.generator import ReportGenerator


@pytest.fixture
def generator():
    # Uses the bundled package templates by default.
    return ReportGenerator()


@pytest.fixture
def finding():
    return {
        "title": "[High] IDOR on /api/users",
        "category": "idor",
        "severity": "high",
        "cvss_score": 7.5,
        "description": "IDOR allows accessing other users' data.",
        "steps_to_reproduce": "1. Login\n2. GET /api/users/999",
        "poc_text": "curl -H 'Auth: token' https://api.example.com/api/users/999",
        "impact": "Any user can read any other user's PII.",
        "recommended_fix": "Add server-side authorization.",
        "target": "example.com",
    }


@pytest.mark.parametrize("platform", [
    "hackerone", "bugcrowd", "intigriti", "yeswehack", "synack", "immunefi", "client",
])
def test_generate_all_platforms(generator, finding, platform):
    """Each platform generates a report without error."""
    report = generator.generate(platform, finding)
    assert "IDOR" in report
    assert "HIGH" in report


def test_bugcrowd_has_vrt(generator, finding):
    report = generator.generate("bugcrowd", finding)
    assert "VRT Category" in report


def test_intigriti_has_attack_scenario(generator, finding):
    report = generator.generate("intigriti", finding)
    assert "Attack Scenario" in report


def test_synack_has_executive_summary(generator, finding):
    report = generator.generate("synack", finding)
    assert "Executive Summary" in report


def test_immunefi_has_funds_at_risk_section(generator):
    finding = {
        "title": "Reentrancy", "severity": "critical",
        "description": "Reentrancy in withdraw()", "impact": "Drain funds",
        "steps_to_reproduce": "1. Call withdraw", "funds_at_risk": "$2.5M TVL",
    }
    report = generator.generate("immunefi", finding)
    assert "$2.5M" in report


def test_client_has_table_format(generator, finding):
    report = generator.generate("client", finding)
    assert "Security Assessment Report" in report
    assert "| Severity |" in report
