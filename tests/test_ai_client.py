import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from redbreach.ai.client import AIClient, AIResponse, extract_json


def test_extract_json_plain():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_extract_json_strips_code_fences():
    assert extract_json('```json\n{"confidence": "verified"}\n```') == {"confidence": "verified"}
    assert extract_json('```\n{"x": true}\n```') == {"x": True}


def test_extract_json_ignores_surrounding_prose():
    assert extract_json('Sure, here is my assessment:\n{"confidence": "likely"}\nHope that helps!') == {"confidence": "likely"}


def test_extract_json_array():
    assert extract_json('```json\n[1, 2, 3]\n```') == [1, 2, 3]


def test_extract_json_returns_none_on_garbage():
    assert extract_json("there is no json in this reply") is None
    assert extract_json("") is None
    assert extract_json(None) is None


def test_ai_response_structure():
    resp = AIResponse(text="analysis", input_tokens=100, output_tokens=50)
    assert resp.text == "analysis"
    assert resp.total_tokens == 150
    assert resp.estimated_cost > 0


def test_ai_client_init():
    with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
        client = AIClient(model="claude-sonnet-4-20250514", budget_dollars=5.0)
        assert client.model == "claude-sonnet-4-20250514"
        assert client.budget_remaining == 5.0
        assert client.total_tokens_used == 0


def test_ai_client_no_key_raises():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            AIClient()


@pytest.mark.asyncio
async def test_analyze_returns_response():
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="This is a real vulnerability.")]
    mock_response.usage.input_tokens = 200
    mock_response.usage.output_tokens = 100

    with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
        client = AIClient(budget_dollars=10.0)
        with patch.object(client, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            result = await client.analyze(
                system="You are a security analyst.",
                prompt="Analyze this finding.",
            )
            assert result.text == "This is a real vulnerability."
            assert result.total_tokens == 300


@pytest.mark.asyncio
async def test_budget_tracking():
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="ok")]
    mock_response.usage.input_tokens = 1000000
    mock_response.usage.output_tokens = 500000

    with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):
        client = AIClient(budget_dollars=0.001)
        with patch.object(client, "_client") as mock_client:
            mock_client.messages.create = AsyncMock(return_value=mock_response)
            await client.analyze(system="s", prompt="p")
            assert client.budget_remaining <= 0
            with pytest.raises(RuntimeError, match="budget"):
                await client.analyze(system="s", prompt="p")
