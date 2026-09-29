import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from redbreach.reporting.writer import ReportWriter


@pytest.fixture
def mock_ai():
    ai = AsyncMock()
    ai.analyze = AsyncMock(return_value=MagicMock(
        text=json.dumps({
            "title": "Reflected Cross-Site Scripting (XSS) in Search Functionality",
            "summary": "A reflected XSS vulnerability exists in the search endpoint.",
            "description": "The /search endpoint fails to sanitize the q parameter before reflecting it.",
            "impact": "An attacker can steal session cookies or perform actions on behalf of the victim.",
            "steps_to_reproduce": "1. Navigate to /search?q=test\n2. Replace q with <script>alert(1)</script>\n3. Observe execution",
            "recommended_fix": "Implement output encoding for all user-supplied input.",
        })
    ))
    return ai


@pytest.mark.asyncio
async def test_write_report(mock_ai):
    writer = ReportWriter(ai_client=mock_ai)
    finding = {"title": "XSS in /search", "severity": "medium", "category": "xss",
               "description": "XSS via q param", "poc_text": "GET /search?q=<script>alert(1)</script>"}
    verification = {"confidence": "verified", "replay_evidence": "reflected",
                     "poc_command": "curl 'https://example.com/search?q=<script>'", "ai_assessment": "Confirmed."}
    report = await writer.write(finding, verification, platform="hackerone")
    assert "title" in report
    assert "summary" in report
    assert "steps_to_reproduce" in report
    assert len(report["description"]) > 20


@pytest.mark.asyncio
async def test_write_report_includes_poc(mock_ai):
    writer = ReportWriter(ai_client=mock_ai)
    finding = {"title": "SQLi", "severity": "high", "category": "sqli", "description": "SQL injection"}
    verification = {"confidence": "verified", "poc_command": "curl 'https://example.com/login'"}
    report = await writer.write(finding, verification, platform="bugcrowd")
    assert report is not None


@pytest.mark.asyncio
async def test_write_handles_ai_failure():
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(side_effect=RuntimeError("budget"))
    writer = ReportWriter(ai_client=mock_ai)
    finding = {"title": "XSS", "severity": "medium", "description": "test"}
    report = await writer.write(finding, {}, platform="hackerone")
    assert report["title"] == "XSS"


@pytest.mark.asyncio
async def test_platform_specific_fields(mock_ai):
    writer = ReportWriter(ai_client=mock_ai)
    finding = {"title": "Reentrancy", "severity": "critical", "category": "smart_contract"}
    verification = {"confidence": "verified"}
    report = await writer.write(finding, verification, platform="immunefi")
    mock_ai.analyze.assert_called_once()
    call_args = mock_ai.analyze.call_args
    prompt = call_args.kwargs.get("prompt", "") or (call_args[1].get("prompt", "") if len(call_args) > 1 else "")
    assert "immunefi" in prompt.lower() or "Immunefi" in prompt


@pytest.mark.asyncio
async def test_write_report_parses_fenced_json():
    # AI wraps JSON in a ```json fence -> must still use the AI report, not the raw fallback.
    body = json.dumps({
        "title": "AI Written Title", "summary": "s", "description": "d" * 30,
        "impact": "i", "steps_to_reproduce": "1. do", "recommended_fix": "fix",
    })
    ai = AsyncMock()
    ai.analyze = AsyncMock(return_value=MagicMock(text="```json\n" + body + "\n```"))
    writer = ReportWriter(ai_client=ai)
    report = await writer.write({"title": "RAW FALLBACK", "severity": "low"}, {}, "hackerone")
    assert report["title"] == "AI Written Title"  # not "RAW FALLBACK"
