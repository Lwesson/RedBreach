import pytest
from unittest.mock import AsyncMock, patch

from redbreach.core.tool_health import check_tool, check_tools, ToolStatus, PHASE_A_TOOLS
from redbreach.core.subprocess_runner import SubprocessResult


pytestmark = pytest.mark.asyncio


def _res(stdout="", stderr="", rc=0):
    return SubprocessResult(stdout=stdout, stderr=stderr, returncode=rc,
                            timed_out=False, duration_seconds=0.1, command=["x"])


async def test_check_tool_flags_wrong_httpx_binary():
    # The Python httpx CLI shadowing projectdiscovery httpx must be caught, not
    # reported as healthy (this is what silently broke recon host-probing).
    with patch("redbreach.core.tool_health.run_tool",
               AsyncMock(return_value=_res(stdout="Usage: httpx [OPTIONS] URL"))):
        status = await check_tool("httpx", "-version")
    assert status.installed is True
    assert status.identity_ok is False
    assert "wrong binary" in (status.error or "")


async def test_check_tool_accepts_real_projectdiscovery_httpx():
    with patch("redbreach.core.tool_health.run_tool",
               AsyncMock(return_value=_res(stderr="projectdiscovery.io\nCurrent Version: v1.9.0"))):
        status = await check_tool("httpx", "-version")
    assert status.installed is True
    assert status.identity_ok is True


async def test_check_tool_without_signature_is_identity_ok():
    with patch("redbreach.core.tool_health.run_tool",
               AsyncMock(return_value=_res(stdout="Nmap 7.94"))):
        status = await check_tool("nmap", "-V")
    assert status.identity_ok is True


async def test_check_tool_installed():
    """check_tool returns installed=True for a known command."""
    status = await check_tool("echo", version_flag="--version")
    assert status.name == "echo"
    assert status.installed is True


async def test_check_tool_not_installed():
    """check_tool returns installed=False for a missing command."""
    status = await check_tool("nonexistent_tool_xyz_999")
    assert status.installed is False
    assert status.version is None


async def test_check_tools_returns_all():
    """check_tools returns a status for every requested tool."""
    tools = {"echo": "--version", "ls": "--version"}
    results = await check_tools(tools)
    assert len(results) == 2
    assert all(isinstance(r, ToolStatus) for r in results)


async def test_phase_a_tools_defined():
    """PHASE_A_TOOLS contains the MVP tool requirements."""
    assert "subfinder" in PHASE_A_TOOLS
    assert "httpx" in PHASE_A_TOOLS
    assert "whois" in PHASE_A_TOOLS
