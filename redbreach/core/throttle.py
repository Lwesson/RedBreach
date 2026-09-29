"""Rate limiting for redbreach tool execution and HTTP requests.

Token-bucket algorithm with per-domain tracking, adaptive backoff on
rate-limit detection, and configurable scan profiles (stealth / normal /
aggressive).  Wraps the existing ``run_tool()`` interface so callers can
swap in ``ThrottledRunner`` without changing their call-sites.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from dataclasses import dataclass, field

from redbreach.core.subprocess_runner import SubprocessResult, run_tool

logger = logging.getLogger("redbreach.throttle")

# ── regex used to detect rate-limit signals in tool output ───────────
_RATE_LIMIT_RE = re.compile(
    r"rate.?limit|429|too many requests|blocked",
    re.IGNORECASE,
)

# ── scan profiles ────────────────────────────────────────────────────

@dataclass(frozen=True)
class ScanProfile:
    """Pre-defined throttle configuration."""

    name: str
    requests_per_second: float
    jitter_ms: int          # max random delay in milliseconds
    burst: int              # max tokens that can accumulate


PROFILES: dict[str, ScanProfile] = {
    "stealth": ScanProfile(
        name="stealth",
        requests_per_second=2,
        jitter_ms=500,
        burst=1,
    ),
    "normal": ScanProfile(
        name="normal",
        requests_per_second=10,
        jitter_ms=100,
        burst=5,
    ),
    "aggressive": ScanProfile(
        name="aggressive",
        requests_per_second=50,
        jitter_ms=0,
        burst=20,
    ),
}


# ── token-bucket rate limiter ────────────────────────────────────────

class Throttle:
    """Async token-bucket rate limiter with per-domain tracking.

    Thread-safe across concurrent asyncio tasks (single event-loop).
    Each domain gets its own independent bucket.

    Parameters
    ----------
    requests_per_second:
        Steady-state refill rate.
    burst:
        Maximum tokens the bucket can hold.  Allows short spikes above
        the base RPS.
    """

    def __init__(self, requests_per_second: float, burst: int) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be > 0")
        if burst < 1:
            raise ValueError("burst must be >= 1")

        self._rps = requests_per_second
        self._base_rps = requests_per_second  # ceiling for AIMD recovery
        self._burst = burst

        # per-domain state: (tokens, last_refill_timestamp)
        self._buckets: dict[str, list[float]] = {}  # [tokens, last_ts]
        self._lock = asyncio.Lock()

    # ── properties ───────────────────────────────────────────────────

    @property
    def rps(self) -> float:
        return self._rps

    @rps.setter
    def rps(self, value: float) -> None:
        if value <= 0:
            raise ValueError("rps must be > 0")
        self._rps = value

    # ── core API ─────────────────────────────────────────────────────

    async def acquire(self, domain: str = "__global__") -> None:
        """Block until a token is available for *domain*."""
        while True:
            async with self._lock:
                now = time.monotonic()
                bucket = self._buckets.get(domain)

                if bucket is None:
                    # first request for this domain, full bucket
                    self._buckets[domain] = [self._burst - 1.0, now]
                    return

                tokens, last_ts = bucket
                elapsed = now - last_ts
                tokens = min(self._burst, tokens + elapsed * self._rps)

                if tokens >= 1.0:
                    bucket[0] = tokens - 1.0
                    bucket[1] = now
                    return

                # how long until we'd have a token?
                wait = (1.0 - tokens) / self._rps

            # sleep outside the lock so other domains aren't blocked
            await asyncio.sleep(wait)

    def reduce_rps(self, factor: float = 0.5) -> None:
        """Reduce the refill rate by *factor* (adaptive backoff).

        Clamps to a minimum of 0.5 req/s so we never stall completely.
        """
        old = self._rps
        self._rps = max(0.5, self._rps * factor)
        logger.warning(
            "Throttle RPS reduced: %.1f -> %.1f (factor %.0f%%)",
            old, self._rps, factor * 100,
        )

    def increase_rps(self, step: float = 0.5) -> None:
        """Additively recover the refill rate toward the baseline (AIMD).

        Called after a clean (non-rate-limited) request so a single 429
        does not permanently degrade throughput for the rest of the
        session. Never climbs above the profile's baseline RPS.
        """
        if self._rps >= self._base_rps:
            return
        old = self._rps
        self._rps = min(self._base_rps, self._rps + step)
        if self._rps != old:
            logger.debug(
                "Throttle RPS recovered: %.1f -> %.1f (base %.1f)",
                old, self._rps, self._base_rps,
            )


# ── throttled runner ─────────────────────────────────────────────────

@dataclass
class ThrottledRunner:
    """Rate-limited wrapper around ``run_tool()``.

    Acquires a token from the throttle before every execution, applies
    jitter, and watches tool output for rate-limit signals, backing off
    automatically when detected.

    Parameters
    ----------
    profile:
        A ``ScanProfile`` defining RPS, jitter, and burst.
    domain:
        Default target domain for per-domain tracking.  Can be
        overridden per-call.
    """

    profile: ScanProfile
    domain: str = "__global__"
    throttle: Throttle = field(init=False, repr=False)

    # backoff state per domain: timestamp when backoff expires
    _backoff_until: dict[str, float] = field(
        default_factory=dict, init=False, repr=False,
    )

    _BACKOFF_SECONDS: float = 30.0
    _RPS_REDUCTION: float = 0.5

    def __post_init__(self) -> None:
        self.throttle = Throttle(
            requests_per_second=self.profile.requests_per_second,
            burst=self.profile.burst,
        )

    # ── public API ───────────────────────────────────────────────────

    async def run(
        self,
        cmd: list[str],
        timeout: int = 300,
        cwd: str | None = None,
        domain: str | None = None,
    ) -> SubprocessResult:
        """Execute *cmd* through the throttle, with jitter and backoff.

        Parameters mirror ``run_tool()`` plus an optional *domain*
        override for per-target tracking.

        Returns the same ``SubprocessResult`` as the raw runner.
        """
        target = domain or self.domain

        # honour active backoff
        await self._wait_for_backoff(target)

        # acquire rate-limit token
        await self.throttle.acquire(target)

        # apply jitter
        if self.profile.jitter_ms > 0:
            jitter = random.uniform(0, self.profile.jitter_ms / 1000.0)
            await asyncio.sleep(jitter)

        logger.debug(
            "Throttled exec [%s @ %.1f rps]: %s",
            target, self.throttle.rps, " ".join(cmd),
        )

        result = await run_tool(cmd, timeout=timeout, cwd=cwd)

        # check for rate-limit signals in output
        combined = f"{result.stdout}\n{result.stderr}"
        if _RATE_LIMIT_RE.search(combined):
            logger.warning(
                "Rate-limit detected for domain %s (cmd: %s). "
                "Reducing RPS and backing off %.0fs.",
                target, cmd[0], self._BACKOFF_SECONDS,
            )
            self.throttle.reduce_rps(self._RPS_REDUCTION)
            self._backoff_until[target] = (
                time.monotonic() + self._BACKOFF_SECONDS
            )
        else:
            # Clean run, recover throughput toward baseline so one 429
            # earlier in the session does not throttle us forever.
            self.throttle.increase_rps()

        return result

    # ── internals ────────────────────────────────────────────────────

    async def _wait_for_backoff(self, domain: str) -> None:
        """If a backoff is active for *domain*, sleep until it expires."""
        deadline = self._backoff_until.get(domain)
        if deadline is None:
            return
        remaining = deadline - time.monotonic()
        if remaining > 0:
            logger.info(
                "Backoff active for %s, sleeping %.1fs",
                domain, remaining,
            )
            await asyncio.sleep(remaining)
        # clear expired backoff
        self._backoff_until.pop(domain, None)


# ── factory ──────────────────────────────────────────────────────────

def get_throttled_runner(
    profile: str = "normal",
    domain: str | None = None,
) -> ThrottledRunner:
    """Create a ``ThrottledRunner`` from a named scan profile.

    Parameters
    ----------
    profile:
        One of ``"stealth"``, ``"normal"``, or ``"aggressive"``.
    domain:
        Default target domain for per-domain tracking.  Pass ``None``
        for a global (domain-agnostic) limiter.

    Returns
    -------
    ThrottledRunner
        Ready-to-use throttled tool runner.

    Raises
    ------
    ValueError
        If *profile* is not a recognised scan profile name.
    """
    scan_profile = PROFILES.get(profile)
    if scan_profile is None:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(
            f"Unknown scan profile {profile!r}. Choose from: {valid}"
        )

    runner = ThrottledRunner(
        profile=scan_profile,
        domain=domain or "__global__",
    )

    logger.info(
        "Throttled runner ready: profile=%s rps=%.0f burst=%d jitter=%dms domain=%s",
        scan_profile.name,
        scan_profile.requests_per_second,
        scan_profile.burst,
        scan_profile.jitter_ms,
        runner.domain,
    )

    return runner
