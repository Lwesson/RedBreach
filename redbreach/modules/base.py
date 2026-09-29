from abc import ABC, abstractmethod

from redbreach.core.subprocess_runner import run_tool, SubprocessResult
from redbreach.core.throttle import ThrottledRunner


class ModuleBase(ABC):
    """Abstract base class for all attack surface modules."""

    name: str
    tools_required: list[str]

    def __init__(self, throttled_runner: ThrottledRunner | None = None) -> None:
        self._runner = throttled_runner

    @abstractmethod
    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 2: Discover new assets relevant to this module."""

    @abstractmethod
    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 3: Enrich assets with tech stack, endpoints, parameters."""

    @abstractmethod
    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 4: Automated scanning, returns raw findings."""

    @abstractmethod
    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        """Phase 5: Generate manual test case suggestions for this surface."""

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        """Parse raw subprocess output into structured data.
        Default splits by newline. Override per tool for JSON/custom formats.
        """
        lines = [line for line in raw_output.strip().split("\n") if line.strip()]
        return [{"raw": line, "tool": tool} for line in lines]

    async def run_tool(self, cmd: list[str], timeout: int = 300, domain: str | None = None) -> SubprocessResult:
        """Execute external tool with timeout, output capture, and rate limiting."""
        if self._runner:
            return await self._runner.run(cmd, timeout=timeout, domain=domain)
        return await run_tool(cmd, timeout=timeout)
