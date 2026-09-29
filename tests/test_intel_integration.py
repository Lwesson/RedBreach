"""End-to-end integration test: sync -> brief -> pipeline."""
import json
import pytest
from unittest.mock import AsyncMock
from redbreach.db import Database
from redbreach.intel.sync import SyncOrchestrator
from redbreach.intel.brief import BriefGenerator

pytestmark = pytest.mark.asyncio


async def test_full_intel_flow(db):
    """Sync feeds -> generate brief -> verify priority ordering."""
    eng_id = await db.create_engagement("bounty", "hackerone", "test.com", "{}")
    await db.create_asset(eng_id, "domain", "test.com",
                          tech_stack_json=json.dumps(["nginx", "react"]))

    orch = SyncOrchestrator(db)
    for source in orch.sources:
        source.sync = AsyncMock(return_value=0)

    await db.upsert_cve(cve_id="CVE-2024-KEV01", description="nginx critical",
                        cvss_score=9.8, epss_score=0.95, kev_known_exploited=1)
    await db.add_tech_cve_mapping("nginx", "<2.0", "CVE-2024-KEV01")
    await db.upsert_exploit(source="exploitdb", source_id="EDB-11111",
                            title="nginx RCE", cve_id="CVE-2024-KEV01")
    await db.upsert_cve(cve_id="CVE-2025-LOW01", description="react info leak",
                        cvss_score=3.0, epss_score=0.1)
    await db.add_tech_cve_mapping("react", "<19.0", "CVE-2025-LOW01")

    gen = BriefGenerator(db)
    brief = await gen.generate(eng_id, save=True)

    assert len(brief["kev_hits"]) == 1
    assert brief["kev_hits"][0]["cve_id"] == "CVE-2024-KEV01"
    assert brief["priority_stack"][0]["cve_id"] == "CVE-2024-KEV01"
    # KEV hit should outscore any deprioritized items
    if brief["deprioritized"]:
        assert brief["priority_stack"][0]["score"] > brief["deprioritized"][-1]["score"]

    stored = await db.get_intel_brief(eng_id)
    assert stored is not None

    await db.increment_sync_generation()
    assert await gen.is_stale(eng_id) is True
