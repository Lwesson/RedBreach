"""Tests for the Phase 1 brief generator."""

import json

import pytest

from redbreach.intel.brief import BriefGenerator, _extract_tech_names

pytestmark = pytest.mark.asyncio


async def _seed_engagement_with_nginx(db):
    """Create engagement with nginx asset, CVE with KEV flag, tech mapping, and exploit."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    asset_id = await db.create_asset(
        eng_id, "web", "https://example.com",
        tech_stack_json=json.dumps({"nginx": "1.18.0", "php": "8.1"}),
    )

    # KEV CVE mapped to nginx
    await db.upsert_cve(
        cve_id="CVE-2021-23017",
        description="nginx resolver vulnerability",
        cvss_score=9.4,
        epss_score=0.85,
        kev_known_exploited=1,
    )
    await db.add_tech_cve_mapping("nginx", "<1.21.0", "CVE-2021-23017")

    # Non-KEV CVE with exploit
    await db.upsert_cve(
        cve_id="CVE-2022-41741",
        description="nginx mp4 module vulnerability",
        cvss_score=7.8,
        epss_score=0.4,
    )
    await db.add_tech_cve_mapping("nginx", "<1.23.2", "CVE-2022-41741")
    await db.upsert_exploit(
        source="exploitdb",
        source_id="51234",
        title="nginx mp4 PoC",
        cve_id="CVE-2022-41741",
        poc_url="https://exploit-db.com/exploits/51234",
    )

    return eng_id, asset_id


async def test_generate_brief(db):
    """Brief has kev_hits, high_value, tech_coverage populated."""
    eng_id, _ = await _seed_engagement_with_nginx(db)
    gen = BriefGenerator(db)

    brief = await gen.generate(eng_id)

    assert brief["engagement_id"] == eng_id
    assert brief["target"] == "example.com"
    assert len(brief["kev_hits"]) >= 1
    assert brief["kev_hits"][0]["cve_id"] == "CVE-2021-23017"
    assert len(brief["high_value"]) >= 1
    assert "nginx" in brief["tech_coverage"]
    assert brief["tech_coverage"]["nginx"]["matched"] is True
    assert brief["tech_coverage"]["nginx"]["kev_count"] >= 1
    assert len(brief["priority_stack"]) > 0


async def test_brief_stores_in_db(db):
    """Generate with save=True stores in engagement_intel."""
    eng_id, _ = await _seed_engagement_with_nginx(db)
    gen = BriefGenerator(db)

    await gen.generate(eng_id, save=True)

    stored = await db.get_intel_brief(eng_id)
    assert stored is not None
    assert stored["engagement_id"] == eng_id
    parsed = json.loads(stored["brief_json"])
    assert parsed["target"] == "example.com"


async def test_brief_staleness_detection(db):
    """After incrementing sync_generation, brief is stale."""
    eng_id, _ = await _seed_engagement_with_nginx(db)
    gen = BriefGenerator(db)

    await gen.generate(eng_id, save=True)
    assert await gen.is_stale(eng_id) is False

    await db.increment_sync_generation()
    assert await gen.is_stale(eng_id) is True


async def test_empty_brief_for_no_tech_stack(db):
    """Brief works with bare engagement (no assets/tech)."""
    eng_id = await db.create_engagement("pentest", None, "bare.example.com", "{}")
    gen = BriefGenerator(db)

    brief = await gen.generate(eng_id)

    assert brief["engagement_id"] == eng_id
    assert brief["kev_hits"] == []
    assert brief["high_value"] == []
    assert brief["tech_coverage"] == {}
    assert brief["priority_stack"] == []


def test_extract_tech_names_dict():
    """Extracts tech names from dict-style tech_stack_json."""
    assets = [{"tech_stack_json": json.dumps({"nginx/1.18": True, "PHP 8.1": True})}]
    names = _extract_tech_names(assets)
    assert "nginx" in names
    assert "php" in names


def test_extract_tech_names_empty():
    """Returns empty set for assets with no tech stack."""
    assets = [{"tech_stack_json": "{}"}]
    names = _extract_tech_names(assets)
    assert names == set()


async def test_brief_surfaces_critical_no_poc(db):
    eng_id, _ = await _seed_engagement_with_nginx(db)
    # Critical nginx CVE: not KEV, no public exploit -> a prime MANUAL target that
    # the priority stack (KEV + has-PoC only) would otherwise drop entirely.
    await db.upsert_cve(cve_id="CVE-2099-99999", description="nginx critical RCE", cvss_score=9.8)
    await db.add_tech_cve_mapping("nginx", "<99", "CVE-2099-99999")

    brief = await BriefGenerator(db).generate(eng_id)
    notable_ids = [n["cve_id"] for n in brief["notable_no_poc"]]
    assert "CVE-2099-99999" in notable_ids
    assert "CVE-2099-99999" not in [h["cve_id"] for h in brief["high_value"]]
    assert "CVE-2099-99999" not in [k["cve_id"] for k in brief["kev_hits"]]
