"""NVD (National Vulnerability Database) CVE feed source."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from redbreach.db import Database

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDSource:
    """Imports CVEs from the NVD REST API 2.0."""

    name = "nvd"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        # Rate limit: 0.6s with key, 6s without
        self.delay = 0.6 if self.api_key else 6.0

    async def fetch(
        self,
        last_modified_since: str | None = None,
        start_index: int = 0,
    ) -> dict[str, Any]:
        """Fetch a page of CVEs from the NVD API."""
        params: dict[str, Any] = {"startIndex": start_index, "resultsPerPage": 2000}
        if last_modified_since:
            params["lastModStartDate"] = last_modified_since
            params["lastModEndDate"] = "2099-12-31T00:00:00.000"

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        async with aiohttp.ClientSession() as session:
            async with session.get(NVD_API_URL, params=params, headers=headers) as resp:
                if resp.status == 403:
                    logger.warning("NVD rate limited (403), backing off")
                    raise aiohttp.ClientResponseError(
                        resp.request_info, resp.history,
                        status=403, message="Rate limited",
                    )
                resp.raise_for_status()
                return await resp.json(content_type=None)

    @staticmethod
    def parse_cpe(criteria: str, version_end: str | None = None) -> str:
        """Extract product name from CPE 2.3 string (index 4)."""
        parts = criteria.split(":")
        if len(parts) > 4:
            return parts[4]
        return ""

    def parse(self, data: dict[str, Any]) -> tuple[list[dict], list[dict]]:
        """Parse NVD response into (cve_records, tech_cve_mappings)."""
        cves = []
        mappings = []

        for item in data.get("vulnerabilities", []):
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id")
            if not cve_id:
                continue

            # English description
            description = None
            for desc in cve_data.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value")
                    break

            # CVSS: prefer v3.1, fall back to v3.0, then v2, so CVEs scored only
            # under an older metric still get a score (the brief ranks by it).
            cvss_score = None
            cvss_vector = None
            metrics = cve_data.get("metrics", {})
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(metric_key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break

            # References
            refs = [r.get("url") for r in cve_data.get("references", []) if r.get("url")]

            # CPE matches → tech mappings
            for config in cve_data.get("configurations", []):
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable"):
                            continue
                        criteria = match.get("criteria", "")
                        version_end = match.get("versionEndExcluding")
                        product = self.parse_cpe(criteria, version_end)
                        if product:
                            version_range = f"< {version_end}" if version_end else "*"
                            mappings.append({
                                "product": product,
                                "version_range": version_range,
                                "cve_id": cve_id,
                            })

            cves.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "references": json.dumps(refs),
                "published_at": cve_data.get("published"),
                "modified_at": cve_data.get("lastModified"),
            })

        return cves, mappings

    async def sync(self, db: Database, last_sync_at: str | None = None) -> int:
        """Paginated fetch + upsert loop. Returns total CVEs synced."""
        import asyncio

        total = 0
        start_index = 0

        while True:
            data = await self.fetch(last_modified_since=last_sync_at, start_index=start_index)
            cves, mappings = self.parse(data)

            for rec in cves:
                await db.upsert_cve(**rec)
            for m in mappings:
                await db.add_tech_cve_mapping(**m)

            total += len(cves)
            total_results = data.get("totalResults", 0)
            # Advance by the page size; guard against a 0-length page that would
            # otherwise never advance start_index (infinite loop).
            advanced = data.get("resultsPerPage") or len(data.get("vulnerabilities", []))
            if advanced <= 0:
                logger.warning("nvd: page returned no results, stopping at index %d", start_index)
                break
            start_index += advanced

            logger.info("nvd: synced %d/%d CVEs", total, total_results)

            if start_index >= total_results:
                break

            await asyncio.sleep(self.delay)

        return total
