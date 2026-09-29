"""Tests for CISA KEV feed source."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from redbreach.intel.sources.cisa_kev import CISAKEVSource

pytestmark = pytest.mark.asyncio


@pytest.fixture
def kev_data(fixtures_dir):
    return json.loads((fixtures_dir / "kev_sample.json").read_text())


@pytest.fixture
def source():
    return CISAKEVSource()


async def test_parse_returns_correct_count(source, kev_data):
    records = source.parse(kev_data)
    assert len(records) == 3


async def test_parse_fields(source, kev_data):
    records = source.parse(kev_data)
    rec = records[0]
    assert rec["cve_id"] == "CVE-2024-12345"
    assert rec["kev_known_exploited"] == 1
    assert rec["kev_due_date"] == "2024-12-01"
    assert rec["kev_added_date"] == "2024-11-01"
    assert "buffer overflow" in rec["description"].lower()


async def test_parse_skips_missing_cve_id(source):
    data = {"vulnerabilities": [{"shortDescription": "no cve id"}]}
    assert source.parse(data) == []


async def test_sync_upserts_all(source, kev_data, db):
    with patch.object(source, "fetch", new_callable=AsyncMock, return_value=kev_data):
        count = await source.sync(db)
    assert count == 3
    cve = await db.get_cve("CVE-2024-12345")
    assert cve is not None
    assert cve["kev_known_exploited"] == 1


async def test_sync_idempotent(source, kev_data, db):
    with patch.object(source, "fetch", new_callable=AsyncMock, return_value=kev_data):
        await source.sync(db)
        count = await source.sync(db)
    assert count == 3
    cve = await db.get_cve("CVE-2024-67890")
    assert cve is not None
