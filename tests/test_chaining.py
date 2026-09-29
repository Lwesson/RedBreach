import json
import pytest
from unittest.mock import AsyncMock

from redbreach.ai.chaining import ChainingEngine, VulnChain
from redbreach.ai.client import AIResponse, DEFAULT_MODEL


def test_chain_structure():
    chain = VulnChain(
        finding_ids=[1, 3, 5],
        combined_severity="critical",
        attack_path="SSRF → Internal API → RCE",
        business_impact="Full server compromise via chained low-severity bugs.",
        cvss_override=9.8,
    )
    assert len(chain.finding_ids) == 3
    assert chain.combined_severity == "critical"


@pytest.mark.asyncio
async def test_identify_chains():
    mock_ai = AsyncMock()
    response_text = json.dumps({
        "chains": [
            {
                "finding_ids": [0, 2],
                "combined_severity": "critical",
                "attack_path": "XSS → Session Hijack → Admin Access",
                "business_impact": "Attacker gains admin via reflected XSS + weak session.",
                "cvss_override": 9.1,
            }
        ]
    })
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=response_text,
        input_tokens=400,
        output_tokens=200,
        model=DEFAULT_MODEL,
    ))

    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(
        findings=[
            {"id": 1, "title": "Reflected XSS", "severity": "medium"},
            {"id": 2, "title": "Info Disclosure", "severity": "low"},
            {"id": 3, "title": "Weak Session", "severity": "medium"},
        ],
        engagement_context="Web app bounty",
    )

    assert len(chains) == 1
    assert chains[0].combined_severity == "critical"
    mock_ai.analyze.assert_called_once()


@pytest.mark.asyncio
async def test_chaining_handles_ai_error():
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(side_effect=RuntimeError("budget"))

    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(
        findings=[
            {"id": 1, "title": "Test A", "severity": "low"},
            {"id": 2, "title": "Test B", "severity": "low"},
        ],
        engagement_context="test",
    )
    assert chains == []


@pytest.mark.asyncio
async def test_chaining_no_findings():
    mock_ai = AsyncMock()
    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(findings=[], engagement_context="test")
    assert chains == []
    mock_ai.analyze.assert_not_called()


@pytest.mark.asyncio
async def test_chaining_single_finding_skips_ai():
    mock_ai = AsyncMock()
    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(
        findings=[{"id": 1, "title": "Solo bug", "severity": "high"}],
        engagement_context="test",
    )
    assert chains == []
    mock_ai.analyze.assert_not_called()


@pytest.mark.asyncio
async def test_chaining_bad_json_returns_empty():
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text="not valid json at all",
        input_tokens=100,
        output_tokens=50,
        model=DEFAULT_MODEL,
    ))

    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(
        findings=[
            {"id": 1, "title": "Bug A", "severity": "medium"},
            {"id": 2, "title": "Bug B", "severity": "low"},
        ],
        engagement_context="test",
    )
    assert chains == []


@pytest.mark.asyncio
async def test_chaining_no_chains_in_response():
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=json.dumps({"chains": []}),
        input_tokens=100,
        output_tokens=20,
        model=DEFAULT_MODEL,
    ))

    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(
        findings=[
            {"id": 1, "title": "Bug A", "severity": "low"},
            {"id": 2, "title": "Bug B", "severity": "low"},
        ],
        engagement_context="test",
    )
    assert chains == []


@pytest.mark.asyncio
async def test_chaining_optional_cvss_override():
    mock_ai = AsyncMock()
    response_text = json.dumps({
        "chains": [
            {
                "finding_ids": [0, 1],
                "combined_severity": "high",
                "attack_path": "SQLi → Data Exfil",
                "business_impact": "Database dump of PII.",
                # no cvss_override
            }
        ]
    })
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=response_text,
        input_tokens=200,
        output_tokens=100,
        model=DEFAULT_MODEL,
    ))

    engine = ChainingEngine(ai_client=mock_ai)
    chains = await engine.identify_chains(
        findings=[
            {"id": 1, "title": "SQL Injection", "severity": "high"},
            {"id": 2, "title": "Verbose Errors", "severity": "low"},
        ],
        engagement_context="API pentest",
    )
    assert len(chains) == 1
    assert chains[0].cvss_override is None
    assert chains[0].combined_severity == "high"


@pytest.mark.asyncio
async def test_chaining_prompt_includes_endpoint_and_detail():
    # Chaining needs endpoints/detail to connect findings into a real path.
    mock_ai = AsyncMock()
    mock_ai.analyze = AsyncMock(return_value=AIResponse(
        text=json.dumps({"chains": []}), input_tokens=1, output_tokens=1, model=DEFAULT_MODEL,
    ))
    engine = ChainingEngine(ai_client=mock_ai)
    await engine.identify_chains(
        findings=[
            {"title": "SSRF", "severity": "medium", "category": "ssrf",
             "matched_at": "https://app.example.com/webhook", "description": "URL param fetches internal metadata"},
            {"title": "Open S3", "severity": "low", "matched_at": "https://s3.example.com/bucket"},
        ],
        engagement_context="cloud",
    )
    prompt = mock_ai.analyze.call_args.kwargs["prompt"]
    assert "app.example.com/webhook" in prompt
    assert "internal metadata" in prompt
