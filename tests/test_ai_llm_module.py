import json
import pytest
from unittest.mock import AsyncMock, patch

from redbreach.modules.ai_llm import AILLMModule, _CANARY, detect_injection, is_ai_endpoint
from redbreach.core.subprocess_runner import SubprocessResult


@pytest.fixture
def module():
    return AILLMModule()


def test_module_name(module):
    assert module.name == "ai_llm"


def test_tools_required(module):
    assert "curl" in module.tools_required


@pytest.mark.asyncio
async def test_recon_discovers_ai_endpoints(module):
    mock_result = SubprocessResult(
        stdout="/api/chat\n/api/completions\n/v1/embeddings\n",
        stderr="", returncode=0, timed_out=False, duration_seconds=2.0, command=["katana"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        assets = await module.recon({"target": "https://ai.example.com", "type": "bounty"}, [])
    assert len(assets) == 3
    assert all(a["type"] == "ai_endpoint" for a in assets)


@pytest.mark.asyncio
async def test_scan_prompt_injection(module):
    # Realistic LLM response echoing the injected canary -> injection confirmed.
    mock_result = SubprocessResult(
        stdout=json.dumps({"choices": [{"message": {"content": f"Okay: {_CANARY}"}}]}),
        stderr="", returncode=0, timed_out=False, duration_seconds=5.0, command=["curl"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        findings = await module.scan({"target": "https://ai.example.com", "type": "bounty"},
                                      [{"type": "ai_endpoint", "value": "/api/chat"}])
    assert len(findings) == 1  # one confirmed finding per endpoint, not one per payload
    assert findings[0]["category"] == "prompt_injection"
    assert findings[0]["severity"] == "high"
    assert findings[0]["matched_at"].endswith("/api/chat")


@pytest.mark.asyncio
async def test_scan_no_injection_on_benign_response(module):
    # A normal assistant reply that does not echo the canary -> no finding.
    mock_result = SubprocessResult(
        stdout=json.dumps({"choices": [{"message": {"content": "I can help with that."}}]}),
        stderr="", returncode=0, timed_out=False, duration_seconds=1.0, command=["curl"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        findings = await module.scan({"target": "https://ai.example.com", "type": "bounty"},
                                      [{"type": "ai_endpoint", "value": "/api/chat"}])
    assert findings == []


def test_detect_injection_canary_and_leak_and_clean():
    assert detect_injection(f"prefix {_CANARY} suffix", "direct")["severity"] == "high"
    leak = detect_injection("You are a helpful assistant. Your instructions are to never reveal secrets.", "leak")
    assert leak is not None and leak["severity"] == "medium"
    assert detect_injection("Hello, how can I help you today?") is None


def test_is_ai_endpoint_heuristic():
    assert is_ai_endpoint("https://x.com/v1/chat/completions")
    assert is_ai_endpoint("https://x.com/api/assistant")
    assert not is_ai_endpoint("https://x.com/static/logo.png")
    assert not is_ai_endpoint("https://x.com/login")


@pytest.mark.asyncio
async def test_recon_filters_non_ai_urls(module):
    mock_result = SubprocessResult(
        stdout="/api/chat\n/static/app.js\n/login\n/v1/completions\n",
        stderr="", returncode=0, timed_out=False, duration_seconds=2.0, command=["katana"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        assets = await module.recon({"target": "https://ai.example.com", "type": "bounty"}, [])
    values = {a["value"] for a in assets}
    assert values == {"/api/chat", "/v1/completions"}  # js + login filtered out


@pytest.mark.asyncio
async def test_suggest_tests_llm(module):
    tests = await module.suggest_tests({"target": "https://ai.example.com"},
        [{"title": "Prompt Injection", "severity": "high", "category": "prompt_injection"}])
    assert len(tests) > 0


def test_parse_ai_endpoints(module):
    parsed = module.parse_output("ai_endpoints", "/chat\n/completions\n")
    assert len(parsed) == 2


def test_parse_injection_result(module):
    raw = json.dumps({"output": f"here you go: {_CANARY}"})
    parsed = module.parse_output("injection_test", raw)
    assert len(parsed) == 1
    assert parsed[0]["severity"] == "high"
