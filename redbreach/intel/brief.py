"""Phase 1 brief generator, produces structured intel briefs from local DB."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from redbreach.db import Database
from redbreach.intel.patterns import PatternMatcher
from redbreach.intel.priority import PriorityScorer

logger = logging.getLogger("redbreach.intel.brief")

# Load CPE aliases for tech name -> CPE product fallback
_ALIASES_PATH = Path(__file__).parent / "cpe_aliases.json"
_CPE_ALIASES: dict[str, str] = {}
if _ALIASES_PATH.exists():
    with open(_ALIASES_PATH) as f:
        _CPE_ALIASES = json.load(f)


def _extract_tech_names(assets: list[dict]) -> set[str]:
    """Parse tech_stack_json from each asset, return unique lowercased tech names."""
    names: set[str] = set()
    for asset in assets:
        raw = asset.get("tech_stack_json", "{}")
        try:
            stack = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(stack, dict):
            for key in stack:
                # Strip version info: "nginx/1.18" -> "nginx", "PHP 8.1" -> "php"
                base = re.split(r"[\s/]", key.strip())[0].lower()
                if base:
                    names.add(base)
        elif isinstance(stack, list):
            for item in stack:
                base = re.split(r"[\s/]", str(item).strip())[0].lower()
                if base:
                    names.add(base)
    return names


class BriefGenerator:
    """Generates Phase 1 intel briefs for an engagement."""

    def __init__(self, db: Database) -> None:
        self.db = db
        self.scorer = PriorityScorer()
        self.matcher = PatternMatcher(db)

    async def generate(self, engagement_id: int, save: bool = False) -> dict:
        """Build a full Phase 1 brief for the given engagement.

        Steps:
        1. Get engagement assets, extract tech names
        2. Query tech_cve_map for matching CVEs (with CPE alias fallback)
        3. Separate KEV hits (highest priority)
        4. Find high-value items (non-KEV CVEs with public PoCs)
        5. Build tech coverage stats
        6. Get cross-engagement patterns
        7. Score everything for priority stack
        8. Separate deprioritized items (score <= 10)
        9. Flag unmatched tech names
        10. Optionally save to engagement_intel table
        """
        engagement = await self.db.get_engagement(engagement_id)
        if not engagement:
            raise ValueError(f"Engagement {engagement_id} not found")

        assets = await self.db.get_assets(engagement_id)
        tech_names = _extract_tech_names(assets)

        # Query CVEs for each tech name (with alias fallback)
        all_cves: dict[str, list[dict]] = {}  # tech -> [cve_rows]
        matched_techs: set[str] = set()

        for tech in tech_names:
            cves = await self.db.get_cves_for_tech(tech)
            if not cves and tech in _CPE_ALIASES:
                alias = _CPE_ALIASES[tech].split(":")[-1]
                cves = await self.db.get_cves_for_tech(alias)
            if cves:
                all_cves[tech] = cves
                matched_techs.add(tech)

        unmatched_techs = tech_names - matched_techs

        # Separate KEV hits
        kev_hits: list[dict] = []
        non_kev_cves: list[dict] = []
        seen_cves: set[str] = set()

        for tech, cves in all_cves.items():
            for cve in cves:
                cve_id = cve["cve_id"]
                if cve_id in seen_cves:
                    continue
                seen_cves.add(cve_id)
                entry = {**cve, "_matched_tech": tech}
                if cve.get("kev_known_exploited"):
                    kev_hits.append(entry)
                else:
                    non_kev_cves.append(entry)

        # Find PoCs for non-KEV CVEs
        high_value: list[dict] = []
        for cve in non_kev_cves:
            exploits = await self.db.get_exploits_for_cve(cve["cve_id"])
            if exploits:
                high_value.append({**cve, "_exploits": len(exploits)})

        # Critical CVEs on the target's stack that are NOT KEV and have NO public
        # exploit, prime candidates for MANUAL exploitation (nobody has dropped a
        # PoC yet). The priority stack only holds KEV + has-PoC CVEs, so without
        # this these criticals vanished from the brief entirely.
        high_value_ids = {c["cve_id"] for c in high_value}
        notable_no_poc = sorted(
            (
                {
                    "cve_id": c["cve_id"],
                    "description": c.get("description"),
                    "cvss_score": c.get("cvss_score"),
                    "matched_tech": c.get("_matched_tech"),
                }
                for c in non_kev_cves
                if c["cve_id"] not in high_value_ids and (c.get("cvss_score") or 0) >= 9.0
            ),
            key=lambda x: x["cvss_score"] or 0,
            reverse=True,
        )

        # Tech coverage stats
        tech_coverage: dict[str, dict] = {}
        for tech in tech_names:
            cves = all_cves.get(tech, [])
            kev_count = sum(1 for c in cves if c.get("kev_known_exploited"))
            tech_coverage[tech] = {
                "cve_count": len(cves),
                "kev_count": kev_count,
                "matched": tech in matched_techs,
            }

        # Cross-engagement patterns
        patterns = await self.matcher.find_patterns(
            engagement_id,
            tech_stack=list(tech_names) if tech_names else None,
        )

        # Score everything into priority stack
        priority_stack: list[dict] = []
        deprioritized: list[dict] = []

        for cve in kev_hits + high_value:
            has_poc = cve.get("_exploits", 0) > 0 or cve.get("kev_known_exploited")
            cross_hit = any(
                p["category"] for p in patterns
                if p.get("category")
            )
            score = self.scorer.score_cve(
                cve, has_poc=bool(has_poc), cross_engagement_hit=cross_hit
            )
            entry = {
                "cve_id": cve["cve_id"],
                "description": cve.get("description"),
                "cvss_score": cve.get("cvss_score"),
                "epss_score": cve.get("epss_score"),
                "kev": bool(cve.get("kev_known_exploited")),
                "matched_tech": cve.get("_matched_tech"),
                "score": round(score, 2),
            }
            if score <= 10:
                deprioritized.append(entry)
            else:
                priority_stack.append(entry)

        priority_stack.sort(key=lambda x: x["score"], reverse=True)

        brief = {
            "engagement_id": engagement_id,
            "target": engagement.get("target"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tech_names": sorted(tech_names),
            "kev_hits": [
                {
                    "cve_id": c["cve_id"],
                    "description": c.get("description"),
                    "cvss_score": c.get("cvss_score"),
                    "matched_tech": c.get("_matched_tech"),
                }
                for c in kev_hits
            ],
            "high_value": [
                {
                    "cve_id": c["cve_id"],
                    "description": c.get("description"),
                    "cvss_score": c.get("cvss_score"),
                    "exploits": c.get("_exploits", 0),
                    "matched_tech": c.get("_matched_tech"),
                }
                for c in high_value
            ],
            "tech_coverage": tech_coverage,
            "cross_patterns": patterns,
            "priority_stack": priority_stack,
            "deprioritized": deprioritized,
            "notable_no_poc": notable_no_poc,
            "unmatched_techs": sorted(unmatched_techs),
        }

        if save:
            gen = await self.db.get_sync_generation()
            await self.db.save_intel_brief(
                engagement_id, json.dumps(brief), gen
            )

        return brief

    async def is_stale(self, engagement_id: int) -> bool:
        """Check if stored brief is outdated vs current sync generation."""
        stored = await self.db.get_intel_brief(engagement_id)
        if not stored:
            return True
        current_gen = await self.db.get_sync_generation()
        return stored["sync_generation"] < current_gen
