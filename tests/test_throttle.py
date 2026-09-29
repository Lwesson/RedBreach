import pytest

from redbreach.core import throttle as throttle_mod
from redbreach.core.subprocess_runner import SubprocessResult
from redbreach.core.throttle import (
    PROFILES,
    ScanProfile,
    Throttle,
    ThrottledRunner,
    get_throttled_runner,
)


def _result(stdout: str = "", stderr: str = "") -> SubprocessResult:
    return SubprocessResult(
        stdout=stdout,
        stderr=stderr,
        returncode=0,
        timed_out=False,
        duration_seconds=0.01,
        command=["echo"],
    )


# ── Throttle core ────────────────────────────────────────────────────

def test_invalid_construction():
    with pytest.raises(ValueError):
        Throttle(requests_per_second=0, burst=5)
    with pytest.raises(ValueError):
        Throttle(requests_per_second=10, burst=0)


@pytest.mark.asyncio
async def test_acquire_first_request_is_immediate():
    t = Throttle(requests_per_second=1, burst=1)
    await t.acquire("a.com")  # must not hang
    assert "a.com" in t._buckets


@pytest.mark.asyncio
async def test_per_domain_isolation():
    # Draining one domain's bucket must not consume another's.
    t = Throttle(requests_per_second=1000, burst=1)
    await t.acquire("a.com")
    await t.acquire("b.com")
    assert set(t._buckets) == {"a.com", "b.com"}


def test_reduce_rps_halves_and_clamps():
    t = Throttle(requests_per_second=10, burst=5)
    t.reduce_rps(0.5)
    assert t.rps == 5
    for _ in range(20):
        t.reduce_rps(0.5)
    assert t.rps == 0.5  # clamped, never stalls to zero


def test_increase_rps_recovers_but_never_exceeds_base():
    t = Throttle(requests_per_second=10, burst=5)
    t.reduce_rps(0.5)  # 10 -> 5
    t.increase_rps(1.0)  # 5 -> 6
    assert t.rps == 6
    for _ in range(100):
        t.increase_rps(1.0)
    assert t.rps == 10  # capped at baseline, no runaway


def test_increase_rps_noop_at_base():
    t = Throttle(requests_per_second=10, burst=5)
    t.increase_rps(5.0)
    assert t.rps == 10


# ── profiles / factory ───────────────────────────────────────────────

def test_profiles_present():
    assert set(PROFILES) == {"stealth", "normal", "aggressive"}


def test_factory_rejects_unknown_profile():
    with pytest.raises(ValueError):
        get_throttled_runner("ludicrous")


# ── ThrottledRunner behavior ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_runner_backs_off_on_rate_limit_signal(monkeypatch):
    monkeypatch.setattr(throttle_mod, "run_tool",
                        lambda *a, **k: _make_awaitable(_result(stdout="HTTP 429 Too Many Requests")))
    profile = ScanProfile(name="t", requests_per_second=10, jitter_ms=0, burst=5)
    runner = ThrottledRunner(profile=profile, domain="t.com")
    await runner.run(["curl", "t.com"], domain="t.com")
    assert runner.throttle.rps < 10          # reduced
    assert "t.com" in runner._backoff_until   # backoff armed


@pytest.mark.asyncio
async def test_runner_recovers_on_clean_run(monkeypatch):
    monkeypatch.setattr(throttle_mod, "run_tool",
                        lambda *a, **k: _make_awaitable(_result(stdout="all good")))
    profile = ScanProfile(name="t", requests_per_second=10, jitter_ms=0, burst=5)
    runner = ThrottledRunner(profile=profile, domain="t.com")
    runner.throttle.reduce_rps(0.5)  # simulate an earlier 429: 10 -> 5
    await runner.run(["curl", "t.com"], domain="t.com")
    assert runner.throttle.rps > 5   # recovered on the clean run


def _make_awaitable(value):
    async def _coro(*_a, **_k):
        return value
    return _coro()
