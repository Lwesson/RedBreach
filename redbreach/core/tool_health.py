import asyncio
import logging
from dataclasses import dataclass

from redbreach.core.subprocess_runner import run_tool

logger = logging.getLogger("redbreach.health")

PHASE_A_TOOLS = {
    "subfinder": "-version",
    "httpx": "-version",
    "whois": "--version",
    "curl": "--version",
    "theHarvester": "--help",
    "waybackurls": "-h",
    "dnsx": "-version",
    "wafw00f": "-V",
}

PHASE_B_TOOLS = {
    "nuclei": "-version",
    "katana": "-version",
    "ffuf": "-V",
    "whatweb": "--version",
    "nikto": "-Version",
    "arjun": "--help",
    "wpscan": "--version",
    "gobuster": "version",
}

PHASE_C_TOOLS = {
    "sqlmap": "--version",
    "hydra": "-h",
    "burpsuite": "--help",
}

PHASE_D_TOOLS = {
    "nmap": "-V",
    "masscan": "--version",
    "s3scanner": "--version",
}

ALL_TOOLS = {**PHASE_A_TOOLS, **PHASE_B_TOOLS, **PHASE_C_TOOLS, **PHASE_D_TOOLS}


# Tools whose name commonly collides with a DIFFERENT binary on PATH. The value
# is a substring the REAL tool's version output must contain, so `health` can flag
# a wrong-identity binary instead of reporting it healthy. Only `httpx` collides
# in practice (the Python httpx library ships an `httpx` CLI that shadows the
# projectdiscovery security tool). The other pd tools (subfinder/nuclei/katana/
# dnsx) have no such collision AND print "Current Version"/"Nuclei Engine
# Version" (not "projectdiscovery"), so signature-checking them false-flags the
# correct binary, do NOT add them here.
_EXPECTED_SIGNATURE = {
    "httpx": "projectdiscovery",
}


@dataclass
class ToolStatus:
    """Health status of an external tool."""

    name: str
    installed: bool
    version: str | None = None
    error: str | None = None
    identity_ok: bool = True


async def check_tool(name: str, version_flag: str = "--version") -> ToolStatus:
    """Check if a tool is installed, get its version, and verify its identity."""
    result = await run_tool([name, version_flag], timeout=10)

    if result.returncode == 127:
        return ToolStatus(name=name, installed=False, error="Not found")

    version_text = (result.stdout + result.stderr).strip()
    version_line = version_text.split("\n")[0][:100] if version_text else None

    signature = _EXPECTED_SIGNATURE.get(name)
    if signature and signature.lower() not in version_text.lower():
        return ToolStatus(
            name=name, installed=True, version=version_line, identity_ok=False,
            error=f"wrong binary on PATH (expected the '{signature}' tool)",
        )

    return ToolStatus(name=name, installed=True, version=version_line)


async def check_tools(tools: dict[str, str] | None = None) -> list[ToolStatus]:
    """Check multiple tools in parallel."""
    if tools is None:
        tools = PHASE_A_TOOLS

    tasks = [check_tool(name, flag) for name, flag in tools.items()]
    return await asyncio.gather(*tasks)
