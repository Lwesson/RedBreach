"""Tests for intel-layer tables: cve_cache, exploits, tech_cve_map, engagement_intel."""

import pytest

from redbreach.db import SCHEMA_VERSION

pytestmark = pytest.mark.asyncio


# ------------------------------------------------------------------
# Schema checks
# ------------------------------------------------------------------

async def test_schema_version_is_current(db):
    version = await db.get_meta("schema_version")
    assert version == SCHEMA_VERSION


async def test_new_tables_exist(db):
    tables = await db.list_tables()
    for t in ("cve_cache", "exploits", "tech_cve_map", "engagement_intel"):
        assert t in tables, f"Missing table: {t}"


async def test_cross_findings_view_exists(db):
    """cross_findings view should be queryable."""
    async with db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='view' AND name='cross_findings'"
    ) as cur:
        row = await cur.fetchone()
    assert row is not None


# ------------------------------------------------------------------
# CVE Cache CRUD
# ------------------------------------------------------------------

async def test_upsert_and_get_cve(db):
    await db.upsert_cve(
        cve_id="CVE-2024-1234",
        description="Test vuln",
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        epss_score=0.95,
    )
    row = await db.get_cve("CVE-2024-1234")
    assert row is not None
    assert row["cve_id"] == "CVE-2024-1234"
    assert row["cvss_score"] == 9.8
    assert row["description"] == "Test vuln"
    assert row["epss_score"] == 0.95


async def test_upsert_cve_updates_existing(db):
    await db.upsert_cve(cve_id="CVE-2024-0001", description="Original")
    await db.upsert_cve(cve_id="CVE-2024-0001", description="Updated", cvss_score=7.5)
    row = await db.get_cve("CVE-2024-0001")
    assert row["description"] == "Updated"
    assert row["cvss_score"] == 7.5


async def test_get_cve_returns_none_for_missing(db):
    row = await db.get_cve("CVE-9999-0000")
    assert row is None


async def test_search_cves(db):
    await db.upsert_cve(cve_id="CVE-2024-1000", description="Buffer overflow in nginx")
    await db.upsert_cve(cve_id="CVE-2024-2000", description="SQL injection in app")
    results = await db.search_cves("nginx")
    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2024-1000"


async def test_search_cves_by_id(db):
    await db.upsert_cve(cve_id="CVE-2024-5555", description="Some vuln")
    results = await db.search_cves("5555")
    assert len(results) == 1


async def test_get_kev_cves(db):
    await db.upsert_cve(cve_id="CVE-2024-1111", description="KEV vuln",
                        cvss_score=9.0, kev_known_exploited=1)
    await db.upsert_cve(cve_id="CVE-2024-2222", description="Normal vuln",
                        cvss_score=5.0, kev_known_exploited=0)
    kev = await db.get_kev_cves()
    assert len(kev) == 1
    assert kev[0]["cve_id"] == "CVE-2024-1111"


# ------------------------------------------------------------------
# Exploits CRUD
# ------------------------------------------------------------------

async def test_upsert_and_get_exploit(db):
    await db.upsert_exploit(
        source="exploitdb",
        source_id="12345",
        title="Nginx RCE",
        cve_id="CVE-2024-1234",
        poc_url="https://exploit-db.com/exploits/12345",
    )
    results = await db.get_exploits_for_cve("CVE-2024-1234")
    assert len(results) == 1
    assert results[0]["source"] == "exploitdb"
    assert results[0]["title"] == "Nginx RCE"


async def test_upsert_exploit_no_duplicate(db):
    await db.upsert_exploit(source="github", source_id="abc", title="V1")
    await db.upsert_exploit(source="github", source_id="abc", title="V2")
    # Should have only one record, query all exploits
    async with db._conn.execute("SELECT COUNT(*) as cnt FROM exploits") as cur:
        row = await cur.fetchone()
    assert row["cnt"] == 1


async def test_get_exploits_for_cve_empty(db):
    results = await db.get_exploits_for_cve("CVE-0000-0000")
    assert results == []


# ------------------------------------------------------------------
# Tech-CVE Map CRUD
# ------------------------------------------------------------------

async def test_add_tech_cve_mapping(db):
    await db.upsert_cve(cve_id="CVE-2024-9999", description="Apache vuln", cvss_score=8.0)
    await db.add_tech_cve_mapping("apache", "2.4.0-2.4.50", "CVE-2024-9999")
    cves = await db.get_cves_for_tech("apache")
    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2024-9999"


async def test_tech_cve_mapping_case_insensitive(db):
    await db.upsert_cve(cve_id="CVE-2024-8888", description="Nginx vuln", cvss_score=7.0)
    await db.add_tech_cve_mapping("Nginx", "1.0-1.25", "CVE-2024-8888")
    cves = await db.get_cves_for_tech("nginx")
    assert len(cves) == 1


async def test_tech_cve_mapping_upsert_version(db):
    await db.upsert_cve(cve_id="CVE-2024-7777", description="Test")
    await db.add_tech_cve_mapping("redis", "6.0-6.2", "CVE-2024-7777")
    await db.add_tech_cve_mapping("redis", "6.0-7.0", "CVE-2024-7777")
    # Should update version_range, not create duplicate
    async with db._conn.execute(
        "SELECT COUNT(*) as cnt FROM tech_cve_map WHERE product='redis'"
    ) as cur:
        row = await cur.fetchone()
    assert row["cnt"] == 1


# ------------------------------------------------------------------
# Engagement Intel CRUD
# ------------------------------------------------------------------

async def test_save_and_get_intel_brief(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "target.com", "{}")
    row_id = await db.save_intel_brief(eng_id, '{"summary": "test"}', sync_generation=1)
    assert row_id > 0
    brief = await db.get_intel_brief(eng_id)
    assert brief is not None
    assert brief["brief_json"] == '{"summary": "test"}'
    assert brief["sync_generation"] == 1


async def test_save_intel_brief_replaces_previous(db):
    eng_id = await db.create_engagement("pentest", None, "target.com", "{}")
    await db.save_intel_brief(eng_id, '{"v": 1}', sync_generation=1)
    await db.save_intel_brief(eng_id, '{"v": 2}', sync_generation=2)
    brief = await db.get_intel_brief(eng_id)
    assert brief["brief_json"] == '{"v": 2}'
    # Should only have one row for this engagement
    async with db._conn.execute(
        "SELECT COUNT(*) as cnt FROM engagement_intel WHERE engagement_id = ?",
        (eng_id,),
    ) as cur:
        row = await cur.fetchone()
    assert row["cnt"] == 1


async def test_get_intel_brief_returns_none(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "target.com", "{}")
    brief = await db.get_intel_brief(eng_id)
    assert brief is None


# ------------------------------------------------------------------
# Sync Generation
# ------------------------------------------------------------------

async def test_sync_generation_starts_at_zero(db):
    gen = await db.get_sync_generation()
    assert gen == 0


async def test_increment_sync_generation(db):
    gen1 = await db.increment_sync_generation()
    assert gen1 == 1
    gen2 = await db.increment_sync_generation()
    assert gen2 == 2
    stored = await db.get_sync_generation()
    assert stored == 2


# ------------------------------------------------------------------
# Cross-findings view
# ------------------------------------------------------------------

async def test_cross_findings_view_returns_data(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    asset_id = await db.create_asset(eng_id, "domain", "example.com")
    await db.create_finding(
        engagement_id=eng_id, asset_id=asset_id,
        title="XSS", severity="high", category="xss",
    )
    async with db._conn.execute("SELECT * FROM cross_findings") as cur:
        rows = await cur.fetchall()
    assert len(rows) == 1
    row = dict(rows[0])
    assert row["title"] == "XSS"
    assert row["platform"] == "hackerone"
    assert row["asset_type"] == "domain"


async def test_cross_findings_excludes_false_positive(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    fid = await db.create_finding(
        engagement_id=eng_id, asset_id=None,
        title="FP finding", severity="low",
    )
    # Manually set status to false_positive
    await db._conn.execute(
        "UPDATE findings SET status = 'false_positive' WHERE id = ?", (fid,)
    )
    await db._conn.commit()
    async with db._conn.execute("SELECT * FROM cross_findings") as cur:
        rows = await cur.fetchall()
    assert len(rows) == 0
