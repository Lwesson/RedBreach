import json
import logging
import os
import re
from dataclasses import dataclass

import httpx

logger = logging.getLogger("redbreach.ai")


def extract_json(text: str):
    """Best-effort JSON extraction from model output.

    Models often wrap JSON in ```json fences or add prose despite being told
    "JSON only"; a bare json.loads then throws and a real verdict is lost. This
    strips fences, tries a direct parse, then falls back to the first balanced
    object/array in the text. Returns the parsed value or None.
    """
    if not text:
        return None
    s = text.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z0-9]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s).strip()
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        pass
    for open_ch, close_ch in (("{", "}"), ("[", "]")):
        start, end = s.find(open_ch), s.rfind(close_ch)
        if 0 <= start < end:
            try:
                return json.loads(s[start:end + 1])
            except (json.JSONDecodeError, TypeError):
                continue
    return None


# Prices are per million tokens and are used only to estimate spend against the
# local budget. Models not listed here (including most local/self-hosted models)
# are treated as free so the budget guard never blocks them.
PRICING = {
    "claude-sonnet-4-20250514": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
}
DEFAULT_MODEL = "claude-sonnet-4-20250514"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"


@dataclass
class AIResponse:
    text: str
    input_tokens: int
    output_tokens: int
    model: str = DEFAULT_MODEL

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def estimated_cost(self) -> float:
        pricing = PRICING.get(self.model)
        if not pricing:
            return 0.0
        return (
            (self.input_tokens / 1_000_000) * pricing["input"]
            + (self.output_tokens / 1_000_000) * pricing["output"]
        )


class AIClient:
    """Provider-agnostic async client for the AI features.

    Two providers are supported:

    - ``anthropic`` (default): the native Anthropic Messages API.
    - ``openai``: any OpenAI-compatible ``/chat/completions`` endpoint. This one
      switch covers OpenAI itself and, by pointing ``base_url`` at a local
      server, self-hosted and local models (Ollama, LM Studio, vLLM,
      llama.cpp, and OpenAI-compatible aggregators such as OpenRouter).

    Resolution precedence for every setting is: environment variable, then the
    explicit argument (typically from ``config.json``), then a built-in default.

    Environment variables:
        REDBREACH_AI_PROVIDER   anthropic | openai
        REDBREACH_AI_MODEL      model id for the chosen provider
        ANTHROPIC_API_KEY       key for the anthropic provider
        OPENAI_API_KEY          key for the openai provider (any value for a
                                local server that does not check it)
        OPENAI_BASE_URL         OpenAI-compatible base url, e.g.
                                http://localhost:11434/v1 for Ollama
    """

    def __init__(
        self,
        model: str | None = None,
        budget_dollars: float = 10.0,
        max_tokens: int = 4096,
        *,
        provider: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout: float = 120.0,
    ):
        provider = (os.environ.get("REDBREACH_AI_PROVIDER") or provider or "anthropic").lower()
        self.max_tokens = max_tokens
        self._budget_total = budget_dollars
        self._spent = 0.0
        self.total_tokens_used = 0
        self._timeout = timeout

        resolved_model = os.environ.get("REDBREACH_AI_MODEL") or model

        if provider == "anthropic":
            self.provider = "anthropic"
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise ValueError(
                    "ANTHROPIC_API_KEY not set. Add it to your .env file, or set "
                    "REDBREACH_AI_PROVIDER=openai to use OpenAI or a local model."
                )
            self.model = resolved_model or DEFAULT_MODEL
            try:
                import anthropic
            except ImportError as e:
                raise ModuleNotFoundError(
                    "The 'anthropic' package is required for the anthropic provider. "
                    "Install it with 'pip install redbreach[anthropic]', or set "
                    "REDBREACH_AI_PROVIDER=openai to use OpenAI or a local model."
                ) from e
            self._client = anthropic.AsyncAnthropic(api_key=key)
        elif provider in ("openai", "openai-compatible", "local"):
            self.provider = "openai"
            self.base_url = (
                base_url
                or os.environ.get("OPENAI_BASE_URL")
                or os.environ.get("REDBREACH_AI_BASE_URL")
                or DEFAULT_OPENAI_BASE_URL
            ).rstrip("/")
            key = (
                api_key
                or os.environ.get("OPENAI_API_KEY")
                or os.environ.get("REDBREACH_AI_API_KEY")
                or "not-needed"
            )
            # config.json ships a claude default; fall back to an OpenAI model
            # unless the user actually chose a non-claude one.
            if not resolved_model or resolved_model.startswith("claude"):
                resolved_model = DEFAULT_OPENAI_MODEL
            self.model = resolved_model
            self._headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
            self._client = None
        else:
            raise ValueError(
                f"Unknown AI provider '{provider}'. Use 'anthropic' or 'openai' "
                "(OpenAI-compatible, including local servers)."
            )

    @classmethod
    def from_config(cls, cfg=None, **overrides) -> "AIClient":
        """Build a client from a RedBreachConfig's ``ai`` block plus environment.

        Raises ValueError when the selected provider has no usable credentials
        (for anthropic, no key), so callers can fall back to running without AI.
        """
        ai: dict = {}
        if cfg is not None:
            raw = getattr(cfg, "raw", None) or {}
            ai = raw.get("ai", {}) or {}
        return cls(
            model=overrides.get("model", ai.get("model")),
            budget_dollars=overrides.get("budget_dollars", ai.get("budget_dollars", 10.0)),
            max_tokens=overrides.get("max_tokens", ai.get("max_tokens", 4096)),
            provider=overrides.get("provider", ai.get("provider")),
            base_url=overrides.get("base_url", ai.get("base_url")),
        )

    @property
    def budget_remaining(self) -> float:
        return self._budget_total - self._spent

    async def _analyze_anthropic(self, system: str, prompt: str):
        response = await self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text, response.usage.input_tokens, response.usage.output_tokens

    async def _analyze_openai(self, system: str, prompt: str):
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions", headers=self._headers, json=payload
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as e:
            raise RuntimeError(f"AI request to {self.base_url} failed: {e}") from e

        try:
            text = data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as e:
            raise RuntimeError(f"Unexpected AI response from {self.base_url}: {e}") from e

        usage = data.get("usage") or {}
        input_tokens = usage.get("prompt_tokens", 0) or 0
        output_tokens = usage.get("completion_tokens", 0) or 0
        return text, input_tokens, output_tokens

    async def analyze(self, system: str, prompt: str) -> AIResponse:
        if self.budget_remaining <= 0:
            raise RuntimeError(
                f"AI budget exhausted (${self._spent:.4f} spent of ${self._budget_total:.2f}). "
                "Increase budget or skip AI features."
            )

        if self.provider == "anthropic":
            text, input_tokens, output_tokens = await self._analyze_anthropic(system, prompt)
        else:
            text, input_tokens, output_tokens = await self._analyze_openai(system, prompt)

        ai_response = AIResponse(
            text=text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=self.model,
        )

        self._spent += ai_response.estimated_cost
        self.total_tokens_used += ai_response.total_tokens
        logger.info(
            "AI call (%s/%s): %d tokens, ~$%.4f (remaining: $%.4f)",
            self.provider,
            self.model,
            ai_response.total_tokens,
            ai_response.estimated_cost,
            self.budget_remaining,
        )

        return ai_response
