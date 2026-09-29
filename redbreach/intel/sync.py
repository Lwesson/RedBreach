"""Sync orchestrator, coordinates all feed source imports."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from redbreach.db import Database
from redbreach.intel.sources.cisa_kev import CISAKEVSource
from redbreach.intel.sources.nvd import NVDSource
from redbreach.intel.sources.exploitdb import ExploitDBSource
from redbreach.intel.sources.nuclei_index import NucleiIndexSource
from redbreach.intel.sources.github_advisories import GitHubAdvisorySource
from redbreach.intel.sources.owasp import OWASPSource

logger = logging.getLogger("redbreach.intel.sync")


class SyncOrchestrator:
    """Runs all intel feed sources and tracks sync state."""

    def __init__(self, db: Database, nvd_api_key: str | None = None) -> None:
        self.db = db
        self.sources = [
            CISAKEVSource(),
            NVDSource(api_key=nvd_api_key),
            ExploitDBSource(),
            NucleiIndexSource(),
            GitHubAdvisorySource(),
            OWASPSource(),
        ]
        self._source_map = {s.name: s for s in self.sources}

    async def sync_all(self) -> dict:
        """Run all sources, increment sync_generation, return summary."""
        last_sync_at = await self.db.get_meta("last_sync_at")
        results: dict = {}
        total = 0
        incremental_ok = True  # did the incremental (nvd/github) sources succeed?

        for source in self.sources:
            try:
                if source.name in ("nvd", "github_advisory"):
                    count = await source.sync(self.db, last_sync_at=last_sync_at)
                else:
                    count = await source.sync(self.db)
                results[source.name] = count
                total += count
            except Exception as e:
                logger.error("Source %s failed: %s", source.name, e)
                results[source.name] = f"error: {e}"
                if source.name in ("nvd", "github_advisory"):
                    incremental_ok = False

        now = datetime.now(timezone.utc).isoformat()
        # Only advance the incremental watermark when the incremental sources
        # actually succeeded. Otherwise a transient failure (e.g. NVD 403) would
        # move last_sync_at past the window they missed and never re-fetch it.
        if incremental_ok:
            await self.db._conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
                ("last_sync_at", now),
            )
            await self.db._conn.commit()
        else:
            logger.warning("incremental source failed; keeping last_sync_at to retry its window")
        await self.db.increment_sync_generation()

        results["total"] = total
        results["synced_at"] = now
        return results

    async def sync_source(self, name: str) -> int:
        """Sync a single source by name."""
        source = self._source_map.get(name)
        if not source:
            raise ValueError(
                f"Unknown source: {name}. Available: {list(self._source_map.keys())}"
            )
        last_sync_at = await self.db.get_meta("last_sync_at")
        if name in ("nvd", "github_advisory"):
            return await source.sync(self.db, last_sync_at=last_sync_at)
        return await source.sync(self.db)

    async def get_stats(self) -> dict:
        """Return current intel database statistics."""
        last_sync = await self.db.get_meta("last_sync_at")
        gen = await self.db.get_sync_generation()

        async with self.db._conn.execute(
            "SELECT COUNT(*) as cnt FROM cve_cache"
        ) as cur:
            cve_count = (await cur.fetchone())["cnt"]

        async with self.db._conn.execute(
            "SELECT COUNT(*) as cnt FROM exploits"
        ) as cur:
            exploit_count = (await cur.fetchone())["cnt"]

        async with self.db._conn.execute(
            "SELECT COUNT(*) as cnt FROM tech_cve_map"
        ) as cur:
            mapping_count = (await cur.fetchone())["cnt"]

        return {
            "last_sync_at": last_sync,
            "sync_generation": gen,
            "cve_count": cve_count,
            "exploit_count": exploit_count,
            "tech_mapping_count": mapping_count,
        }
