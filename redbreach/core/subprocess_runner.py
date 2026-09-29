import asyncio
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger("redbreach.subprocess")


@dataclass
class SubprocessResult:
    """Result from an external tool execution."""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    duration_seconds: float
    command: list[str]


async def run_tool(
    cmd: list[str],
    timeout: int = 300,
    cwd: str | None = None,
) -> SubprocessResult:
    """Execute an external tool as an async subprocess.

    Args:
        cmd: Command and arguments as list.
        timeout: Max seconds before killing the process (default 300).
        cwd: Working directory for the subprocess.

    Returns:
        SubprocessResult with captured output, exit code, and timing.
    """
    start = time.monotonic()
    timed_out = False

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
    except FileNotFoundError:
        duration = time.monotonic() - start
        logger.error("Command not found: %s", cmd[0])
        return SubprocessResult(
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            returncode=127,
            timed_out=False,
            duration_seconds=duration,
            command=cmd,
        )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        timed_out = True
        # The process may exit on its own between the timeout firing and our
        # signal; terminate()/kill() then raise ProcessLookupError. Guard it so a
        # timeout never crashes the scan phase (run_tool is the core executor).
        try:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
        except ProcessLookupError:
            pass
        stdout_bytes = b""
        stderr_bytes = b"Process timed out"

    duration = time.monotonic() - start
    stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
    stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
    returncode = proc.returncode if proc.returncode is not None else -1

    logger.info(
        "Tool %s finished: exit=%d timeout=%s duration=%.1fs",
        cmd[0], returncode, timed_out, duration,
    )

    return SubprocessResult(
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        timed_out=timed_out,
        duration_seconds=duration,
        command=cmd,
    )
