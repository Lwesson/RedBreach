"""Cross-engagement pattern matcher."""

from __future__ import annotations

import logging

from redbreach.db import Database

logger = logging.getLogger("redbreach.intel.patterns")


class PatternMatcher:
    """Find patterns from past engagements that match a given tech stack."""

    def __init__(self, db: Database) -> None:
        self.db = db

    async def find_patterns(
        self,
        engagement,
        tech_stack: list[str] | None = None,
        asset_type: str | None = None,
    ) -> list[dict]:
        """Find patterns from OTHER engagements matching tech stack."""
        eng_id = engagement["id"] if isinstance(engagement, dict) else engagement

        async with self.db._conn.execute(
            """SELECT category, severity, title, asset_type, tech_stack_json,
                      target, engagement_id, COUNT(*) as hit_count
               FROM cross_findings WHERE engagement_id != ?
               GROUP BY category, target ORDER BY hit_count DESC""",
            (eng_id,),
        ) as cur:
            rows = await cur.fetchall()

        patterns: list[dict] = []
        for row in rows:
            rd = dict(row)
            if tech_stack:
                tech_str = (rd.get("tech_stack_json") or "{}").lower()
                if not any(t.lower() in tech_str for t in tech_stack):
                    continue
            if asset_type and rd.get("asset_type") != asset_type:
                continue
            patterns.append({
                "category": rd["category"],
                "severity": rd["severity"],
                "example_title": rd["title"],
                "asset_type": rd.get("asset_type"),
                "target": rd["target"],
                "hit_count": rd["hit_count"],
                "engagement_id": rd["engagement_id"],
            })
        return patterns

    async def get_hit_rates(self) -> dict:
        """Return category hit rates across all engagements."""
        async with self.db._conn.execute(
            """SELECT category, COUNT(*) as cnt,
                      COUNT(DISTINCT engagement_id) as eng_count
               FROM cross_findings
               WHERE category IS NOT NULL
               GROUP BY category ORDER BY cnt DESC"""
        ) as cur:
            rows = await cur.fetchall()

        return {
            dict(r)["category"]: {
                "count": dict(r)["cnt"],
                "engagements": dict(r)["eng_count"],
            }
            for r in rows
        }
