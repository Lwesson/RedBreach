import pytest

from redbreach.reporting.generator import ReportGenerator


@pytest.fixture
def generator():
    # Uses the bundled package templates by default.
    return ReportGenerator()


@pytest.fixture
def sample_finding():
    return {
        "title": "[High] XSS in Search Parameter",
        "category": "xss",
        "severity": "high",
        "cvss_score": 7.5,
        "description": "Reflected XSS in the search parameter on /search endpoint.",
        "steps_to_reproduce": "1. Navigate to /search?q=<script>alert(1)</script>\n2. Observe alert fires",
        "poc_text": "curl 'https://example.com/search?q=<script>alert(document.cookie)</script>'",
        "impact": "Attacker can steal session cookies of any authenticated user.",
        "recommended_fix": "Sanitize user input in the search parameter using HTML entity encoding.",
    }


def test_generate_hackerone_report(generator, sample_finding):
    """Generate a HackerOne-format report from a finding."""
    report = generator.generate("hackerone", sample_finding)
    assert "[High] XSS in Search Parameter" in report
    assert "Reflected XSS" in report
    assert "Steps to Reproduce" in report
    assert "curl" in report
    assert "HIGH" in report


def test_generate_report_missing_optional_fields(generator):
    """Report generates cleanly with missing optional fields."""
    finding = {
        "title": "Info Disclosure",
        "category": "info-disclosure",
        "severity": "low",
        "description": "Server version exposed in headers.",
        "steps_to_reproduce": "1. Send GET / and check headers",
        "impact": "Attacker learns server version.",
    }
    report = generator.generate("hackerone", finding)
    assert "Info Disclosure" in report
    assert "No PoC attached" in report


def test_generate_unknown_platform_raises(generator):
    """Unknown platform raises ValueError."""
    with pytest.raises(ValueError, match="Unknown platform"):
        generator.generate("unknown_platform", {"title": "test"})


def test_report_includes_version(generator, sample_finding):
    """Report includes redbreach version."""
    report = generator.generate("hackerone", sample_finding)
    assert "RedBreach" in report


def test_save_report(generator, sample_finding, tmp_path):
    """save() writes report to file."""
    output = tmp_path / "report.md"
    generator.save("hackerone", sample_finding, output)
    assert output.exists()
    content = output.read_text()
    assert "[High] XSS in Search Parameter" in content
