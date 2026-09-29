"""Tests for GitHub Advisories feed source."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from redbreach.intel.sources.github_advisories import GitHubAdvisorySource

pytestmark = pytest.mark.asyncio


@pytest.fixture
def ghsa_data(fixtures_dir):
    return json.loads((fixtures_dir / "github_advisory_sample.json").read_text())


@pytest.fixture
def source():
    return GitHubAdvisorySource(token="test-token")


async def test_parse_count(source, ghsa_data):
    records = source.parse(ghsa_data)
    assert len(records) == 1


async def test_parse_fields(source, ghsa_data):
    records = source.parse(ghsa_data)
    rec = records[0]
    assert rec["cve_id"] == "CVE-2025-22222"
    assert "XSS" in rec["description"]
    assert rec["cvss_score"] == 7.5  # high severity
    assert rec["published_at"] == "2025-01-15T00:00:00Z"
    tags = json.loads(rec["cpe_matches"])
    assert "package-name" in tags


async def test_parse_skips_no_cve(source):
    data = [{"ghsa_id": "GHSA-xxxx", "summary": "no cve"}]
    assert source.parse(data) == []


async def test_sync_upserts(source, ghsa_data, db):
    with patch.object(source, "fetch", new_callable=AsyncMock, return_value=ghsa_data):
        count = await source.sync(db)
    assert count == 1
    cve = await db.get_cve("CVE-2025-22222")
    assert cve is not None
    assert cve["cvss_score"] == 7.5


def _adv(cve="CVE-2025-1", severity="high", cvss=None, cvss_severities=None):
    a = {"cve_id": cve, "summary": "x", "vulnerabilities": [], "severity": severity,
         "html_url": "https://x", "published_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-01T00:00:00Z"}
    if cvss is not None:
        a["cvss"] = cvss
    if cvss_severities is not None:
        a["cvss_severities"] = cvss_severities
    return a


async def test_uses_real_cvss_over_severity_map(source):
    # A "high" advisory with a real 8.9 must store 8.9, not the 7.5 band guess.
    rec = source.parse([_adv(cvss={"score": 8.9, "vector_string": "CVSS:3.1/AV:N"})])[0]
    assert rec["cvss_score"] == 8.9
    assert rec["cvss_vector"] == "CVSS:3.1/AV:N"


async def test_prefers_cvss_severities_v3(source):
    rec = source.parse([_adv(cvss_severities={"cvss_v3": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N"}})])[0]
    assert rec["cvss_score"] == 9.8


async def test_falls_back_to_severity_band_without_cvss(source):
    rec = source.parse([_adv(severity="critical")])[0]
    assert rec["cvss_score"] == 9.5  # critical band
    assert rec["cvss_vector"] is None
