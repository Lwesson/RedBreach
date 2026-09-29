import pytest

from redbreach.core.verify import VerificationResult, Confidence, generate_poc_script


def test_verification_result_is_reviewable():
    result = VerificationResult(
        finding_id=1, confidence=Confidence.VERIFIED, replay_status_code=200,
        replay_evidence="Payload reflected in body",
        poc_command="curl -s 'https://example.com/vuln'",
        poc_script="import httpx\nresp = httpx.get('https://example.com/vuln')",
        ai_assessment="Confirmed XSS.",
    )
    assert result.finding_id is not None
    assert result.confidence is not None
    assert result.replay_evidence is not None
    assert result.poc_command is not None
    assert result.poc_script is not None
    assert result.ai_assessment is not None


def test_poc_script_is_executable():
    poc = generate_poc_script(method="GET", url="https://example.com/test",
                               headers={"Authorization": "Bearer token"})
    compile(poc["python"], "<poc>", "exec")


def test_poc_post_with_body():
    poc = generate_poc_script(method="POST", url="https://example.com/api/login",
                               headers={"Content-Type": "application/json"},
                               body='{"user":"admin","pass":"test"}')
    assert "POST" in poc["curl"]
    assert "httpx" in poc["python"]
    compile(poc["python"], "<poc>", "exec")


def test_confidence_filter_verified_only():
    results = [
        VerificationResult(finding_id=1, confidence=Confidence.VERIFIED),
        VerificationResult(finding_id=2, confidence=Confidence.FALSE_POSITIVE),
        VerificationResult(finding_id=3, confidence=Confidence.LIKELY),
        VerificationResult(finding_id=4, confidence=Confidence.UNCONFIRMED),
    ]
    reportable = [r for r in results if r.confidence in (Confidence.VERIFIED, Confidence.LIKELY)]
    assert len(reportable) == 2
    assert all(r.confidence in ("verified", "likely") for r in reportable)
