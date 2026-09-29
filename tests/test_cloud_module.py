import json
import pytest
from unittest.mock import AsyncMock, patch

from redbreach.modules.cloud import CloudModule
from redbreach.core.subprocess_runner import SubprocessResult


@pytest.fixture
def module():
    return CloudModule()


def test_module_name(module):
    assert module.name == "cloud"


def test_tools_required(module):
    assert "aws" in module.tools_required
    assert "gcloud" in module.tools_required


@pytest.mark.asyncio
async def test_recon_s3_enum(module):
    mock_result = SubprocessResult(
        stdout=(
            '{"bucket":"example-backup","message":"exists"}\n'
            '{"bucket":"example-assets","message":"bucket is open to public"}\n'
        ),
        stderr="", returncode=0, timed_out=False, duration_seconds=2.0, command=["s3scanner"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        assets = await module.recon({"target": "example.com", "type": "bounty"}, [])
    assert len(assets) == 2
    assert all(a["type"] == "cloud_storage" for a in assets)
    open_buckets = {a["value"] for a in assets if a.get("open")}
    assert open_buckets == {"example-assets"}


@pytest.mark.asyncio
async def test_recon_s3_ignores_non_json_noise(module):
    # Human-readable status lines must not be mistaken for bucket names.
    mock_result = SubprocessResult(
        stdout="INFO scanning...\nsome banner text\n",
        stderr="", returncode=0, timed_out=False, duration_seconds=1.0, command=["s3scanner"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        assets = await module.recon({"target": "example.com", "type": "bounty"}, [])
    assert assets == []


@pytest.mark.asyncio
async def test_scan_returns_findings(module):
    mock_result = SubprocessResult(
        stdout=json.dumps([{"rule": "s3-public-read", "severity": "HIGH", "resource": "arn:aws:s3:::example-backup"}]),
        stderr="", returncode=0, timed_out=False, duration_seconds=5.0, command=["cloudsploit"],
    )
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        findings = await module.scan({"target": "example.com", "type": "bounty"},
                                      [{"type": "cloud_storage", "value": "example-backup"}])
    assert len(findings) >= 1
    assert findings[0]["type"] == "finding"


@pytest.mark.asyncio
async def test_suggest_tests(module):
    tests = await module.suggest_tests(
        {"target": "example.com"},
        [{"title": "Public S3", "severity": "high", "category": "cloud_storage"}],
    )
    assert isinstance(tests, list)
    assert len(tests) > 0


def test_parse_s3scanner(module):
    raw = '{"bucket":"bucket1","message":"exists"}\n{"bucket":"bucket2","message":"public read"}'
    parsed = module.parse_output("s3scanner", raw)
    assert len(parsed) == 2
    assert parsed[0]["value"] == "bucket1"


def test_parse_cloudsploit(module):
    raw = json.dumps([
        {"rule": "s3-public-read", "severity": "HIGH", "resource": "bucket1"},
        {"rule": "iam-root-access", "severity": "CRITICAL", "resource": "root"},
    ])
    parsed = module.parse_output("cloudsploit", raw)
    assert len(parsed) == 2
