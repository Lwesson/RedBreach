"""Tests for NVD feed source."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from redbreach.intel.sources.nvd import NVDSource

pytestmark = pytest.mark.asyncio


@pytest.fixture
def nvd_data(fixtures_dir):
    return json.loads((fixtures_dir / "nvd_sample.json").read_text())


@pytest.fixture
def source():
    return NVDSource(api_key="test-key")


async def test_parse_cve_count(source, nvd_data):
    cves, mappings = source.parse(nvd_data)
    assert len(cves) == 2


async def test_parse_cve_fields(source, nvd_data):
    cves, _ = source.parse(nvd_data)
    cve = cves[0]
    assert cve["cve_id"] == "CVE-2024-54321"
    assert cve["cvss_score"] == 7.5
    assert "CVSS:3.1" in cve["cvss_vector"]
    assert "nginx" in cve["description"].lower()
    assert cve["published_at"] == "2024-10-15T00:00:00.000"


async def test_parse_cpe_extraction(source):
    assert source.parse_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*") == "nginx"
    assert source.parse_cpe("cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*") == "react"


async def test_parse_cpe_short_string(source):
    assert source.parse_cpe("cpe:2.3:a:vendor") == ""


async def test_parse_tech_mappings(source, nvd_data):
    _, mappings = source.parse(nvd_data)
    assert len(mappings) == 2
    assert mappings[0]["product"] == "nginx"
    assert mappings[0]["version_range"] == "< 1.25.3"


async def test_parse_missing_metrics(source):
    data = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2099-00001",
                "descriptions": [{"lang": "en", "value": "Test"}],
                "metrics": {},
                "configurations": [],
                "references": [],
                "published": "2099-01-01T00:00:00.000",
                "lastModified": "2099-01-01T00:00:00.000",
            }
        }]
    }
    cves, mappings = source.parse(data)
    assert len(cves) == 1
    assert cves[0]["cvss_score"] is None
    assert cves[0]["cvss_vector"] is None
    assert mappings == []


async def test_sync_upserts(source, nvd_data, db):
    with patch.object(source, "fetch", new_callable=AsyncMock, return_value=nvd_data):
        count = await source.sync(db)
    assert count == 2
    cve = await db.get_cve("CVE-2024-54321")
    assert cve is not None
    assert cve["cvss_score"] == 7.5
    # Check tech mapping
    tech_cves = await db.get_cves_for_tech("nginx")
    assert len(tech_cves) == 1


def _cve_with_metrics(cve_id, metrics):
    return {"vulnerabilities": [{"cve": {
        "id": cve_id, "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": metrics, "configurations": [], "references": [],
        "published": "2024-01-01T00:00:00.000", "lastModified": "2024-01-01T00:00:00.000",
    }}]}


async def test_parse_cvss_v30_fallback(source):
    data = _cve_with_metrics("CVE-2024-30", {
        "cvssMetricV30": [{"cvssData": {"baseScore": 8.8, "vectorString": "CVSS:3.0/AV:N/AC:L"}}]})
    cves, _ = source.parse(data)
    assert cves[0]["cvss_score"] == 8.8
    assert "3.0" in cves[0]["cvss_vector"]


async def test_parse_cvss_v2_fallback(source):
    data = _cve_with_metrics("CVE-2024-02", {
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N"}}]})
    cves, _ = source.parse(data)
    assert cves[0]["cvss_score"] == 5.0


async def test_parse_prefers_v31_over_older(source):
    data = _cve_with_metrics("CVE-2024-99", {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "vectorString": "CVSS:3.1/AV:N"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}]})
    cves, _ = source.parse(data)
    assert cves[0]["cvss_score"] == 9.1  # v3.1 wins


async def test_sync_stops_on_empty_page(source, db):
    # Without the progress guard this would loop forever (index never advances).
    empty_page = {"vulnerabilities": [], "totalResults": 100, "resultsPerPage": 0}
    with patch.object(source, "fetch", new_callable=AsyncMock, return_value=empty_page):
        count = await source.sync(db)
    assert count == 0
