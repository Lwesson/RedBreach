"""Tests for Nuclei template index feed source."""

from pathlib import Path

import pytest

from redbreach.intel.sources.nuclei_index import NucleiIndexSource

pytestmark = pytest.mark.asyncio


@pytest.fixture
def source(fixtures_dir):
    return NucleiIndexSource(templates_dir=str(fixtures_dir))


async def test_parse_template(source, fixtures_dir):
    result = source.parse_template(fixtures_dir / "nuclei_sample.yaml")
    assert result is not None
    assert result["cve_id"] == "CVE-2024-12345"
    assert result["name"] == "nginx Buffer Overflow"
    assert "nginx" in result["tags"]
    assert "rce" in result["tags"]


async def test_parse_template_no_cve(source, tmp_path):
    no_cve = tmp_path / "no_cve.yaml"
    no_cve.write_text("id: test\ninfo:\n  name: test\n  classification: {}\n")
    assert source.parse_template(no_cve) is None


async def test_parse_template_invalid_yaml(source, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("{{invalid yaml")
    assert source.parse_template(bad) is None


async def test_sync_indexes_templates(source, db):
    count = await source.sync(db)
    assert count >= 1
    exploits = await db.get_exploits_for_cve("CVE-2024-12345")
    assert len(exploits) == 1
    assert exploits[0]["source"] == "nuclei"


async def test_sync_missing_dir(db):
    source = NucleiIndexSource(templates_dir="/nonexistent/path")
    count = await source.sync(db)
    assert count == 0
