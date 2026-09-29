"""Tests for the sync orchestrator."""

from unittest.mock import AsyncMock, patch

import pytest

from redbreach.intel.sync import SyncOrchestrator

pytestmark = pytest.mark.asyncio


async def test_sync_all_sources(db):
    """All sources run, total is summed, sync_generation increments."""
    orch = SyncOrchestrator(db)
    gen_before = await db.get_sync_generation()

    # Mock every source's sync method to return 5
    for source in orch.sources:
        source.sync = AsyncMock(return_value=5)

    result = await orch.sync_all()

    assert result["total"] == 5 * len(orch.sources)
    assert "synced_at" in result
    for source in orch.sources:
        assert result[source.name] == 5

    gen_after = await db.get_sync_generation()
    assert gen_after == gen_before + 1


async def test_sync_single_source(db):
    """Syncing a single source by name returns its count."""
    orch = SyncOrchestrator(db)
    # Mock only the cisa_kev source
    orch._source_map["cisa_kev"].sync = AsyncMock(return_value=42)

    count = await orch.sync_source("cisa_kev")
    assert count == 42


async def test_sync_tracks_last_sync_at(db):
    """After sync_all, last_sync_at is set in meta."""
    orch = SyncOrchestrator(db)
    for source in orch.sources:
        source.sync = AsyncMock(return_value=0)

    before = await db.get_meta("last_sync_at")
    assert before is None

    await orch.sync_all()

    after = await db.get_meta("last_sync_at")
    assert after is not None


async def test_sync_unknown_source_raises(db):
    """Requesting a nonexistent source raises ValueError."""
    orch = SyncOrchestrator(db)
    with pytest.raises(ValueError, match="Unknown source"):
        await orch.sync_source("not_a_real_source")


async def test_sync_all_handles_source_error(db):
    """A failing source logs error but doesn't stop other sources."""
    orch = SyncOrchestrator(db)
    for source in orch.sources:
        source.sync = AsyncMock(return_value=3)
    # Make one source fail
    orch.sources[0].sync = AsyncMock(side_effect=RuntimeError("boom"))

    result = await orch.sync_all()

    assert "error" in str(result[orch.sources[0].name])
    # Other sources still counted
    assert result["total"] == 3 * (len(orch.sources) - 1)


async def test_get_stats(db):
    """Stats returns counts and sync metadata."""
    orch = SyncOrchestrator(db)
    stats = await orch.get_stats()

    assert stats["cve_count"] == 0
    assert stats["exploit_count"] == 0
    assert stats["tech_mapping_count"] == 0
    assert stats["sync_generation"] == 0
    assert stats["last_sync_at"] is None


async def test_last_sync_not_advanced_when_incremental_source_fails(db):
    # Regression: a transient NVD/GitHub failure must NOT advance last_sync_at,
    # or the window they missed is skipped forever.
    await db._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('last_sync_at', '2020-01-01T00:00:00')")
    await db._conn.commit()
    orch = SyncOrchestrator(db)
    for source in orch.sources:
        source.sync = AsyncMock(return_value=1)
    orch._source_map["nvd"].sync = AsyncMock(side_effect=RuntimeError("403 rate limited"))

    await orch.sync_all()
    assert await db.get_meta("last_sync_at") == "2020-01-01T00:00:00"  # unchanged -> will retry


async def test_last_sync_advances_when_only_noncritical_source_fails(db):
    orch = SyncOrchestrator(db)
    for source in orch.sources:
        source.sync = AsyncMock(return_value=1)
    orch._source_map["cisa_kev"].sync = AsyncMock(side_effect=RuntimeError("boom"))  # non-incremental

    await orch.sync_all()
    assert await db.get_meta("last_sync_at") is not None  # advanced despite cisa_kev failing
