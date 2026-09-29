import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from redbreach.core.verify import VerificationEngine, VerificationResult, Confidence, generate_poc_script


def test_confidence_levels():
    assert Confidence.VERIFIED == "verified"
    assert Confidence.LIKELY == "likely"
    assert Confidence.UNCONFIRMED == "unconfirmed"
    assert Confidence.FALSE_POSITIVE == "false_positive"


def test_verification_result_structure():
    result = VerificationResult(
        finding_id=1, confidence=Confidence.VERIFIED, replay_status_code=200,
        replay_evidence="<script>alert(1)</script> reflected",
        poc_command="curl -s 'https://example.com/search?q=<script>alert(1)</script>'",
        poc_script="import httpx\nresp = httpx.get('...')",
        ai_assessment="Confirmed reflected XSS.",
    )
    assert result.confidence == "verified"
    assert result.finding_id == 1


@pytest.mark.asyncio
async def test_verify_xss_finding():
    finding = {
        "id": 1, "title": "Reflected XSS in /search", "severity": "medium",
        "category": "xss", "matched_at": "https://example.com/search?q=test",
        "poc_text": "GET /search?q=<script>alert(1)</script>",
    }
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = '<html><script>alert(1)</script></html>'
    mock_response.headers = {"content-type": "text/html"}

    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=MagicMock(
        text=json.dumps({"confidence": "verified", "reasoning": "Payload reflected.", "impact": "Cookie theft."})
    ))

    engine = VerificationEngine(ai_client=mock_ai)
    with patch("redbreach.core.verify.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        result = await engine.verify(finding)

    assert result.confidence in ("verified", "likely")
    assert result.replay_status_code == 200
    assert result.poc_command is not None


@pytest.mark.asyncio
async def test_verify_parses_fenced_json_verdict():
    # AI wraps its JSON in a ```json fence, the verdict must still be read, not lost.
    finding = {"id": 9, "title": "XSS", "matched_at": "https://example.com/s?q=1", "poc_text": "GET /s?q=1"}
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "<script>alert(1)</script>"
    mock_response.headers = {}
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=MagicMock(
        text='```json\n{"confidence": "verified", "reasoning": "Reflected.", "impact": "XSS."}\n```'
    ))
    engine = VerificationEngine(ai_client=mock_ai)
    with patch("redbreach.core.verify.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        result = await engine.verify(finding)
    assert result.confidence == "verified"  # not degraded to unconfirmed by the fences


@pytest.mark.asyncio
async def test_verify_rejects_out_of_vocab_confidence():
    finding = {"id": 10, "title": "X", "matched_at": "https://example.com/a", "poc_text": "GET /a"}
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "ok"
    mock_response.headers = {}
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=MagicMock(
        text='{"confidence": "super-duper-sure", "reasoning": "x", "impact": "y"}'
    ))
    engine = VerificationEngine(ai_client=mock_ai)
    with patch("redbreach.core.verify.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        result = await engine.verify(finding)
    assert result.confidence == Confidence.UNCONFIRMED  # invalid value guarded


@pytest.mark.asyncio
async def test_verify_handles_connection_error():
    finding = {"id": 2, "title": "SQLi", "matched_at": "https://unreachable.example.com/login", "poc_text": "POST /login"}
    engine = VerificationEngine(ai_client=AsyncMock())
    with patch("redbreach.core.verify.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=Exception("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        result = await engine.verify(finding)
    assert result.confidence == Confidence.UNCONFIRMED


@pytest.mark.asyncio
async def test_verify_batch():
    findings = [
        {"id": 1, "title": "XSS", "matched_at": "https://example.com/a", "poc_text": "GET /a"},
        {"id": 2, "title": "SQLi", "matched_at": "https://example.com/b", "poc_text": "GET /b"},
    ]
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.text = "response"
    mock_response.headers = {}

    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=MagicMock(
        text=json.dumps({"confidence": "likely", "reasoning": "Possible.", "impact": "TBD"})
    ))

    engine = VerificationEngine(ai_client=mock_ai)
    with patch("redbreach.core.verify.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client
        results = await engine.verify_batch(findings)
    assert len(results) == 2


def test_generate_poc_curl():
    poc = generate_poc_script(method="GET", url="https://example.com/test", headers={"Cookie": "session=abc"})
    assert "curl" in poc["curl"]
    assert "httpx" in poc["python"]


def test_generate_poc_post():
    poc = generate_poc_script(method="POST", url="https://example.com/login",
                               headers={"Content-Type": "application/json"}, body='{"user":"admin"}')
    assert "-X POST" in poc["curl"] or "-d" in poc["curl"]
    compile(poc["python"], "<poc>", "exec")
