import json
import pytest
from unittest.mock import AsyncMock, patch

from redbreach.modules.recon import ReconModule
from redbreach.core.subprocess_runner import SubprocessResult


pytestmark = pytest.mark.asyncio


@pytest.fixture
def recon():
    return ReconModule()


@pytest.fixture
def engagement():
    return {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}


def make_result(stdout="", stderr="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
        timed_out=False, duration_seconds=1.0, command=["test"],
    )


async def test_parse_subfinder_output(recon, fixtures_dir):
    raw = (fixtures_dir / "subfinder_output.txt").read_text()
    assets = recon.parse_output("subfinder", raw)
    domains = [a["value"] for a in assets]
    assert "www.example.com" in domains
    assert "api.example.com" in domains
    assert len(assets) == 5
    assert all(a["type"] == "domain" for a in assets)


async def test_parse_httpx_output(recon, fixtures_dir):
    raw = (fixtures_dir / "httpx_output.json").read_text()
    assets = recon.parse_output("httpx", raw)
    assert len(assets) == 3
    assert assets[0]["status_code"] == 200
    assert assets[0]["url"] == "https://www.example.com"


async def test_parse_crtsh_response(recon, fixtures_dir):
    raw = (fixtures_dir / "crtsh_response.json").read_text()
    assets = recon.parse_output("crtsh", raw)
    domains = [a["value"] for a in assets]
    assert "www.example.com" in domains
    assert "cdn.example.com" in domains
    # Wildcards should be excluded
    assert "*.example.com" not in domains


async def test_parse_waybackurls_output(recon, fixtures_dir):
    raw = (fixtures_dir / "waybackurls_output.txt").read_text()
    assets = recon.parse_output("waybackurls", raw)
    urls = [a["value"] for a in assets]
    assert "https://www.example.com/login" in urls
    assert all(a["type"] == "url" for a in assets)


async def test_recon_runs_subfinder(recon, engagement):
    """recon() calls subfinder and returns discovered assets."""
    subfinder_output = "sub1.example.com\nsub2.example.com\n"
    with patch.object(recon, "run_tool", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = make_result(stdout=subfinder_output)
        assets = await recon.recon(engagement, [])
        mock_run.assert_called()
        domains = [a["value"] for a in assets]
        assert "sub1.example.com" in domains


async def test_recon_deduplicates(recon, engagement):
    """recon() deduplicates assets from multiple tools."""
    output = "dupe.example.com\ndupe.example.com\nother.example.com\n"
    with patch.object(recon, "run_tool", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = make_result(stdout=output)
        assets = await recon.recon(engagement, [])
        values = [a["value"] for a in assets]
        assert values.count("dupe.example.com") == 1


async def test_module_properties(recon):
    """ReconModule has correct name and tools."""
    assert recon.name == "recon"
    assert "subfinder" in recon.tools_required


async def test_parse_crtsh_splits_multiline_name_value(recon):
    # crt.sh often packs several SANs into one name_value separated by newlines.
    raw = json.dumps([
        {"name_value": "a.example.com\nb.example.com"},
        {"name_value": "*.example.com\nc.example.com"},
    ])
    domains = [x["value"] for x in recon.parse_output("crtsh", raw)]
    assert "a.example.com" in domains
    assert "b.example.com" in domains
    assert "c.example.com" in domains
    assert "*.example.com" not in domains
    assert not any("\n" in d for d in domains)  # no malformed merged asset


async def test_resolve_dns_removes_tempfile(recon):
    import os
    captured = {}

    async def fake_run(cmd, **kw):
        captured["file"] = cmd[cmd.index("-l") + 1]
        assert os.path.exists(captured["file"])  # present during the dnsx call
        return make_result(stdout="")

    with patch.object(recon, "run_tool", side_effect=fake_run):
        await recon._resolve_dns(["a.example.com", "b.example.com"])
    assert not os.path.exists(captured["file"])  # cleaned up afterward
