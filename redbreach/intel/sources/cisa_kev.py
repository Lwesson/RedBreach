"""CISA Known Exploited Vulnerabilities (KEV) catalog feed source."""

from __future__ import annotations

import json
import logging
from typing import Any

import aiohttp

from redbreach.db import Database

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CISAKEVSource:
    """Imports CISA KEV catalog into the CVE cache."""

    name = "cisa_kev"

    async def fetch(self) -> dict[str, Any]:
        """Download the full KEV JSON catalog."""
        async with aiohttp.ClientSession() as session:
            async with session.get(KEV_URL) as resp:
                resp.raise_for_status()
                return await resp.json(content_type=None)

    def parse(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert KEV vulnerabilities to CVE upsert records."""
        records = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue
            records.append({
                "cve_id": cve_id,
                "description": vuln.get("shortDescription"),
                "kev_known_exploited": 1,
                "kev_due_date": vuln.get("dueDate"),
                "kev_added_date": vuln.get("dateAdded"),
                "published_at": vuln.get("dateAdded"),
            })
        return records

    async def sync(self, db: Database) -> int:
        """Fetch, parse, and upsert all KEV entries. Returns count."""
        data = await self.fetch()
        records = self.parse(data)
        for rec in records:
            await db.upsert_cve(**rec)
        logger.info("cisa_kev: synced %d CVEs", len(records))
        return len(records)
