import pytest
from unittest.mock import AsyncMock, patch

from redbreach.modules.takeover import TakeoverModule
from redbreach.core.subprocess_runner import SubprocessResult


@pytest.fixture
def module():
    return TakeoverModule()


def make_result(stdout="", stderr="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
        timed_out=False, duration_seconds=1.0, command=["test"],
    )


def test_module_name(module):
    assert module.name == "takeover"


def test_tools_required(module):
    assert "nuclei" in module.tools_required
    assert "subzy" in module.tools_required


@pytest.mark.asyncio
async def test_recon_returns_empty_when_no_subdomains(module):
    findings = await module.recon({"target": "example.com"}, [])
    assert findings == []


@pytest.mark.asyncio
async def test_enumerate_returns_empty(module):
    result = await module.enumerate({}, [])
    assert result == []


@pytest.mark.asyncio
async def test_scan_returns_empty(module):
    result = await module.scan({}, [])
    assert result == []


@pytest.mark.asyncio
async def test_suggest_tests_returns_empty(module):
    result = await module.suggest_tests({}, [])
    assert result == []


@pytest.mark.asyncio
async def test_recon_runs_nuclei_and_subzy(module):
    nuclei_jsonl = (
        '{"template-id":"github-takeover","host":"abandoned.example.com",'
        '"info":{"name":"GitHub Pages Takeover","severity":"high"},'
        '"matched-at":"abandoned.example.com"}\n'
    )
    subzy_json = (
        '[{"subdomain":"orphan.example.com","status":"VULNERABLE",'
        '"engine":"AWS/S3","details":"NoSuchBucket"}]'
    )

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "nuclei":
            return make_result(stdout=nuclei_jsonl)
        if cmd[0] == "subzy":
            # subzy writes JSON to the --output file, not stdout.
            with open(cmd[cmd.index("--output") + 1], "w") as f:
                f.write(subzy_json)
            return make_result()
        return make_result()

    assets = [
        {"type": "domain", "value": "abandoned.example.com"},
        {"type": "domain", "value": "orphan.example.com"},
        {"type": "domain", "value": "live.example.com"},
    ]
    with patch.object(module, "run_tool", side_effect=mock_run):
        findings = await module.recon({"target": "example.com"}, assets)

    assert len(findings) == 2
    hosts = {f["host"] for f in findings}
    assert "abandoned.example.com" in hosts
    assert "orphan.example.com" in hosts
    for f in findings:
        assert f["type"] == "finding"
        assert f["severity"] == "high"
        assert f["category"] == "subdomain_takeover"


@pytest.mark.asyncio
async def test_recon_dedupes_overlapping_results(module):
    nuclei_jsonl = (
        '{"template-id":"s3-takeover","host":"dup.example.com",'
        '"info":{"name":"S3 Bucket Takeover","severity":"high"},'
        '"matched-at":"dup.example.com"}\n'
    )
    subzy_json = '[{"subdomain":"dup.example.com","status":"VULNERABLE","engine":"AWS/S3"}]'

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "nuclei":
            return make_result(stdout=nuclei_jsonl)
        if cmd[0] == "subzy":
            # subzy writes JSON to the --output file, not stdout.
            with open(cmd[cmd.index("--output") + 1], "w") as f:
                f.write(subzy_json)
            return make_result()
        return make_result()

    with patch.object(module, "run_tool", side_effect=mock_run):
        findings = await module.recon(
            {"target": "example.com"},
            [{"type": "domain", "value": "dup.example.com"}],
        )

    assert len(findings) == 1
    assert set(findings[0]["sources"]) == {"nuclei", "subzy"}


@pytest.mark.asyncio
async def test_recon_skips_when_tools_missing(module):
    async def mock_run(cmd, **kwargs):
        return make_result(returncode=127)

    with patch.object(module, "run_tool", side_effect=mock_run):
        findings = await module.recon(
            {"target": "example.com"},
            [{"type": "domain", "value": "x.example.com"}],
        )
    assert findings == []


@pytest.mark.asyncio
async def test_subzy_output_is_a_real_file_not_literal_json(module):
    # Regression: --output is a FILENAME; passing "json" wrote to a file named json
    # and left stdout unparsed, silently dropping every subzy takeover.
    captured = {}

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "subzy":
            captured["out"] = cmd[cmd.index("--output") + 1]
        return make_result()

    with patch.object(module, "run_tool", side_effect=mock_run):
        await module.recon({"target": "example.com"}, [{"type": "domain", "value": "x.example.com"}])
    assert captured["out"] != "json"
    assert captured["out"].endswith(".subzy.json")
