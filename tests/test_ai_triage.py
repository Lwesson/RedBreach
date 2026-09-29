import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from redbreach.ai.triage import TriageEngine, TriageResult
from redbreach.ai.client import AIResponse


def test_triage_result_structure():
    result = TriageResult(
        finding_index=0, is_false_positive=False,
        confidence=0.85, reasoning="SQL error confirms injection.", priority=1,
    )
    assert result.is_false_positive is False
    assert result.confidence == 0.85


@pytest.mark.asyncio
async def test_triage_findings():
    mock_ai = AsyncMock()
    ai_response_text = json.dumps({
        "results": [
            {"finding_index": 0, "is_false_positive": False, "confidence": 0.9, "reasoning": "SQL error confirms real injection.", "priority": 1},
            {"finding_index": 1, "is_false_positive": False, "confidence": 0.5, "reasoning": "Admin panel is informational.", "priority": 3},
        ]
    })
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=ai_response_text, input_tokens=500, output_tokens=200
    ))

    engine = TriageEngine(ai_client=mock_ai)
    results = await engine.triage(
        findings=[
            {"title": "SQL Injection", "severity": "high", "matched_at": "https://api.example.com/users?id=1"},
            {"title": "Admin Panel", "severity": "info", "matched_at": "https://dev.example.com/admin"},
        ],
        engagement_context="Bug bounty on example.com, web application",
    )

    assert len(results) == 2
    assert results[0].is_false_positive is False
    assert results[0].priority == 1
    mock_ai.analyze.assert_called_once()


@pytest.mark.asyncio
async def test_triage_handles_ai_error():
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(side_effect=RuntimeError("budget exhausted"))

    engine = TriageEngine(ai_client=mock_ai)
    results = await engine.triage(
        findings=[{"title": "Test", "severity": "low"}],
        engagement_context="test",
    )
    assert results == []


@pytest.mark.asyncio
async def test_triage_handles_malformed_response():
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text="This is not JSON", input_tokens=100, output_tokens=50
    ))

    engine = TriageEngine(ai_client=mock_ai)
    results = await engine.triage(
        findings=[{"title": "Test", "severity": "low"}],
        engagement_context="test",
    )
    assert results == []


@pytest.mark.asyncio
async def test_triage_batches_large_lists():
    mock_ai = AsyncMock()
    batch_response = json.dumps({
        "results": [{"finding_index": i, "is_false_positive": False, "confidence": 0.8, "reasoning": "ok", "priority": 2} for i in range(20)]
    })
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=batch_response, input_tokens=500, output_tokens=200
    ))

    engine = TriageEngine(ai_client=mock_ai, batch_size=20)
    findings = [{"title": f"Finding {i}", "severity": "medium"} for i in range(25)]
    results = await engine.triage(findings=findings, engagement_context="test")

    assert mock_ai.analyze.call_count == 2


@pytest.mark.asyncio
async def test_triage_prompt_includes_evidence():
    # The model is told to weigh evidence strength, so the prompt must carry it.
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=json.dumps({"results": []}), input_tokens=1, output_tokens=1,
    ))
    engine = TriageEngine(ai_client=mock_ai)
    await engine.triage(
        findings=[{
            "title": "SQL Injection", "severity": "high",
            "matched_at": "https://api.example.com/u?id=1",
            "extracted_results": "You have an error in your SQL syntax near '1''",
        }],
        engagement_context="web app",
    )
    prompt = mock_ai.analyze.call_args.kwargs["prompt"]
    assert "error in your SQL syntax" in prompt
    assert "api.example.com" in prompt
