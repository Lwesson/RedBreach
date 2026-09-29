import asyncio

import pytest

from redbreach.core.subprocess_runner import run_tool, SubprocessResult


pytestmark = pytest.mark.asyncio


async def test_run_tool_success():
    """run_tool captures stdout from a simple command."""
    result = await run_tool(["echo", "hello world"])
    assert result.returncode == 0
    assert "hello world" in result.stdout
    assert result.stderr == ""
    assert result.timed_out is False


async def test_run_tool_captures_stderr():
    """run_tool captures stderr."""
    result = await run_tool(["python3", "-c", "import sys; sys.stderr.write('err\\n')"])
    assert "err" in result.stderr


async def test_run_tool_timeout():
    """run_tool kills process on timeout."""
    result = await run_tool(["sleep", "60"], timeout=2)
    assert result.timed_out is True
    assert result.returncode != 0


async def test_run_tool_nonzero_exit():
    """run_tool captures non-zero exit codes."""
    result = await run_tool(["python3", "-c", "raise SystemExit(42)"])
    assert result.returncode == 42
    assert result.timed_out is False


async def test_run_tool_command_not_found():
    """run_tool handles missing commands gracefully."""
    result = await run_tool(["nonexistent_tool_xyz_999"])
    assert result.returncode == 127
    assert result.timed_out is False


async def test_run_tool_duration_tracked():
    """run_tool records execution duration."""
    result = await run_tool(["echo", "fast"])
    assert result.duration_seconds >= 0
    assert result.duration_seconds < 5


async def test_timeout_survives_already_exited_process(monkeypatch):
    # If the process exits between the timeout and our terminate(), run_tool must
    # not crash with ProcessLookupError, it should return a timed_out result.
    class _FakeProc:
        returncode = -15
        async def communicate(self):
            await asyncio.sleep(10)
        def terminate(self):
            raise ProcessLookupError()
        def kill(self):
            raise ProcessLookupError()
        async def wait(self):
            return -15

    async def _fake_exec(*a, **k):
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    result = await run_tool(["sleep", "10"], timeout=0.1)
    assert result.timed_out is True
    assert result.command == ["sleep", "10"]
