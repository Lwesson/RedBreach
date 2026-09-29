"""Nuclei template index feed source."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from redbreach.db import Database

logger = logging.getLogger(__name__)


class NucleiIndexSource:
    """Indexes local Nuclei templates for CVE-linked exploits."""

    name = "nuclei"

    def __init__(self, templates_dir: str | None = None) -> None:
        self.templates_dir = Path(templates_dir or Path.home() / "nuclei-templates")

    def parse_template(self, path: Path) -> dict[str, Any] | None:
        """Parse a single Nuclei YAML template. Returns None if no CVE."""
        try:
            data = yaml.safe_load(path.read_text(errors="replace"))
        except Exception:
            return None

        if not isinstance(data, dict):
            return None

        info = data.get("info", {})
        if not isinstance(info, dict):
            return None

        classification = info.get("classification", {})
        if not isinstance(classification, dict):
            return None

        cve_id = classification.get("cve-id")
        if not cve_id:
            return None

        # Normalize tags to list
        tags = info.get("tags", "")
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        return {
            "cve_id": cve_id,
            "name": info.get("name", ""),
            "description": info.get("description", ""),
            "tags": tags,
        }

    async def sync(self, db: Database) -> int:
        """Scan templates dir, parse YAML files, upsert exploits. Returns count."""
        if not self.templates_dir.is_dir():
            logger.warning("Nuclei templates dir not found: %s", self.templates_dir)
            return 0

        count = 0
        for path in self.templates_dir.rglob("*.yaml"):
            parsed = self.parse_template(path)
            if not parsed:
                continue

            await db.upsert_exploit(
                source="nuclei",
                source_id=parsed["cve_id"],
                title=parsed["name"],
                cve_id=parsed["cve_id"],
                description=parsed["description"],
                tags=json.dumps(parsed["tags"]),
            )
            count += 1

        logger.info("nuclei: indexed %d CVE-linked templates", count)
        return count
