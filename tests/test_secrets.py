from redbreach.secrets import redact, scan_secrets


def test_detects_aws_key_and_redacts():
    findings = scan_secrets("cfg AKIAIOSFODNN7EXAMPLE end", source="app.js")
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "hardcoded_secret"
    assert "AKIA" in f["extracted_results"]
    assert "IOSFODNN7EXAMPLE" not in f["extracted_results"]  # redacted


def test_detects_multiple_distinct_secret_types():
    text = "ghp_" + "a" * 36 + " and -----BEGIN RSA PRIVATE KEY-----"
    names = {f["title"] for f in scan_secrets(text)}
    assert any("github_token" in n for n in names)
    assert any("private_key" in n for n in names)


def test_clean_text_returns_no_findings():
    assert scan_secrets("just some ordinary text with no secrets") == []
    assert scan_secrets("") == []


def test_duplicate_secret_reported_once():
    key = "AKIAIOSFODNN7EXAMPLE"
    assert len(scan_secrets(f"{key} {key} {key}")) == 1


def test_redact_shows_ends_only():
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AKIA...MPLE"
    assert redact("short") == "s***"
