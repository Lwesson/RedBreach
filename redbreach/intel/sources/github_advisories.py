"""GitHub Security Advisories feed source."""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import aiohttp

from redbreach.db import Database

logger = logging.getLogger(__name__)

GHSA_API_URL = "https://api.github.com/advisories"


class GitHubAdvisorySource:
    """Imports GitHub Security Advisories into CVE cache."""

    name = "github_advisory"

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.environ.get("GITHUB_TOKEN")

    async def fetch(self, updated_since: str | None = None) -> list[dict[str, Any]]:
        """Fetch advisories from GitHub API."""
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        params: dict[str, str] = {"per_page": "100", "type": "reviewed"}
        if updated_since:
            params["updated"] = updated_since

        async with aiohttp.ClientSession() as session:
            async with session.get(GHSA_API_URL, headers=headers, params=params) as resp:
                if resp.status == 403:
                    logger.warning("GitHub API rate limited (403)")
                    raise aiohttp.ClientResponseError(
                        resp.request_info, resp.history,
                        status=403, message="Rate limited",
                    )
                resp.raise_for_status()
                return await resp.json(content_type=None)

    def parse(self, data: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Parse GitHub advisories into CVE upsert records."""
        records = []
        for adv in data:
            cve_id = adv.get("cve_id")
            if not cve_id:
                continue

            # Build tags from package names
            tags = []
            for vuln in adv.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                name = pkg.get("name")
                if name:
                    tags.append(name)

            # Use the advisory's REAL CVSS when present (v4, then v3, then the
            # legacy cvss object); only approximate from the severity band as a
            # last resort. The old code always used the coarse approximation,
            # understating scores and skewing the intel brief's ranking.
            cvss_score = None
            cvss_vector = None
            severities = adv.get("cvss_severities") or {}
            for sev_key in ("cvss_v4", "cvss_v3"):
                entry = severities.get(sev_key) or {}
                if entry.get("score") is not None:
                    cvss_score = entry.get("score")
                    cvss_vector = entry.get("vector_string")
                    break
            if cvss_score is None:
                cvss_obj = adv.get("cvss") or {}
                if cvss_obj.get("score") is not None:
                    cvss_score = cvss_obj.get("score")
                    cvss_vector = cvss_obj.get("vector_string")
            if cvss_score is None:
                severity_map = {"low": 3.0, "medium": 5.5, "high": 7.5, "critical": 9.5}
                cvss_score = severity_map.get(adv.get("severity", ""))

            records.append({
                "cve_id": cve_id,
                "description": adv.get("summary") or adv.get("description"),
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "references": json.dumps([adv.get("html_url", "")]),
                "published_at": adv.get("published_at"),
                "modified_at": adv.get("updated_at"),
                "cpe_matches": json.dumps(tags),
            })
        return records

    async def sync(self, db: Database, last_sync_at: str | None = None) -> int:
        """Fetch, parse, and upsert advisories. Returns count."""
        data = await self.fetch(updated_since=last_sync_at)
        records = self.parse(data)
        for rec in records:
            await db.upsert_cve(**rec)
        logger.info("github_advisory: synced %d CVEs", len(records))
        return len(records)
