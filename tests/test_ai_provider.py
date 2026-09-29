import os
from pathlib import Path
from unittest.mock import patch

import pytest

import redbreach.ai.client as client_mod
from redbreach.ai.client import AIClient
from redbreach.config import DEFAULT_CONFIG, RedBreachConfig


class _FakeResp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


class _FakeClient:
    """Minimal async context manager standing in for httpx.AsyncClient."""

    def __init__(self, data, capture):
        self._data = data
        self._capture = capture

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, headers=None, json=None):
        self._capture["url"] = url
        self._capture["headers"] = headers
        self._capture["json"] = json
        return _FakeResp(self._data)


def _cfg(raw):
    return RedBreachConfig(data_dir=Path("/tmp/redbreach-test"), raw=raw)


def test_default_provider_is_anthropic():
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}, clear=True):
        c = AIClient()
    assert c.provider == "anthropic"
    assert c.model == "claude-sonnet-4-20250514"


def test_openai_provider_via_arg():
    with patch.dict(os.environ, {}, clear=True):
        c = AIClient(provider="openai", api_key="x", base_url="http://localhost:1234/v1", model="llama3")
    assert c.provider == "openai"
    assert c.base_url == "http://localhost:1234/v1"
    assert c.model == "llama3"


def test_openai_provider_via_env():
    env = {
        "REDBREACH_AI_PROVIDER": "openai",
        "OPENAI_BASE_URL": "http://localhost:11434/v1",
        "OPENAI_API_KEY": "z",
    }
    with patch.dict(os.environ, env, clear=True):
        c = AIClient()  # config default model is a claude id, should fall back
    assert c.provider == "openai"
    assert c.base_url == "http://localhost:11434/v1"
    assert c.model == "gpt-4o-mini"


def test_unknown_provider_raises():
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="Unknown AI provider"):
            AIClient(provider="gemini")


def test_from_config_anthropic(monkeypatch):
    cfg = _cfg(dict(DEFAULT_CONFIG))
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}, clear=True):
        c = AIClient.from_config(cfg)
    assert c.provider == "anthropic"


def test_from_config_anthropic_no_key_raises():
    cfg = _cfg(dict(DEFAULT_CONFIG))
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError):
            AIClient.from_config(cfg)


def test_from_config_openai_block():
    raw = {"ai": {"provider": "openai", "model": "mixtral", "base_url": "http://localhost:11434/v1"}}
    with patch.dict(os.environ, {}, clear=True):
        c = AIClient.from_config(_cfg(raw))
    assert c.provider == "openai"
    assert c.model == "mixtral"
    assert c.base_url == "http://localhost:11434/v1"


@pytest.mark.asyncio
async def test_openai_analyze_posts_and_parses(monkeypatch):
    capture = {}
    data = {
        "choices": [{"message": {"content": "vuln confirmed"}}],
        "usage": {"prompt_tokens": 12, "completion_tokens": 8},
    }
    monkeypatch.setattr(client_mod.httpx, "AsyncClient", lambda *a, **k: _FakeClient(data, capture))

    with patch.dict(os.environ, {}, clear=True):
        c = AIClient(provider="openai", api_key="secret", base_url="http://localhost:1234/v1", model="llama3")
        resp = await c.analyze(system="you are a security analyst", prompt="assess this")

    assert resp.text == "vuln confirmed"
    assert resp.total_tokens == 20
    assert capture["url"] == "http://localhost:1234/v1/chat/completions"
    assert capture["headers"]["Authorization"] == "Bearer secret"
    assert capture["json"]["model"] == "llama3"
    assert capture["json"]["messages"][0]["role"] == "system"
    assert capture["json"]["messages"][1]["role"] == "user"


@pytest.mark.asyncio
async def test_local_model_is_free_and_does_not_consume_budget(monkeypatch):
    data = {
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 1_000_000, "completion_tokens": 1_000_000},
    }
    monkeypatch.setattr(client_mod.httpx, "AsyncClient", lambda *a, **k: _FakeClient(data, {}))

    with patch.dict(os.environ, {}, clear=True):
        c = AIClient(provider="openai", api_key="x", base_url="http://localhost:1234/v1", model="local-llama")
        resp = await c.analyze(system="s", prompt="p")

    assert resp.estimated_cost == 0.0
    assert c.budget_remaining == 10.0  # unknown/local model never charges the budget


@pytest.mark.asyncio
async def test_openai_http_error_becomes_runtime_error(monkeypatch):
    class _BoomClient(_FakeClient):
        async def post(self, url, headers=None, json=None):
            raise client_mod.httpx.ConnectError("connection refused")

    monkeypatch.setattr(client_mod.httpx, "AsyncClient", lambda *a, **k: _BoomClient({}, {}))

    with patch.dict(os.environ, {}, clear=True):
        c = AIClient(provider="openai", api_key="x", base_url="http://localhost:9/v1", model="local")
        with pytest.raises(RuntimeError, match="failed"):
            await c.analyze(system="s", prompt="p")
