"""Async SQLite database layer for RedBreach.

All I/O is async via aiosqlite. Rows are returned as dicts.
Foreign keys are enforced. Schema version is tracked in the meta table.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from redbreach.attack import attack_for_category
from redbreach.cwe import cwe_for_category

logger = logging.getLogger("redbreach.db")

SCHEMA_VERSION = "8"


# ---------------------------------------------------------------------------
# Schema DDL
# ---------------------------------------------------------------------------

_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS engagements (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    type           TEXT NOT NULL CHECK(type IN ('bounty', 'pentest', 'private')),
    platform       TEXT,
    target         TEXT NOT NULL,
    client_name    TEXT,
    contract_notes TEXT,
    scope_json     TEXT NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT 'active',
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_engagements_status ON engagements(status);

CREATE TABLE IF NOT EXISTS assets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    type           TEXT NOT NULL,
    value          TEXT NOT NULL,
    tech_stack_json TEXT NOT NULL DEFAULT '{}',
    notes          TEXT,
    discovered_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assets_engagement ON assets(engagement_id);

CREATE TABLE IF NOT EXISTS findings (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id        INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    asset_id             INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    title                TEXT NOT NULL,
    severity             TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    category             TEXT,
    status               TEXT NOT NULL DEFAULT 'new',
    description          TEXT,
    steps_to_reproduce   TEXT,
    poc_text             TEXT,
    impact               TEXT,
    recommended_fix      TEXT,
    cvss_score           REAL,
    cvss_vector          TEXT,
    epss_score           REAL,
    confidence           REAL,
    triage_priority      INTEGER,
    triage_reasoning     TEXT,
    cwe                  TEXT,
    attack_technique     TEXT,
    chain_parent_id      INTEGER REFERENCES findings(id) ON DELETE SET NULL,
    created_at           TEXT NOT NULL,
    updated_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);

CREATE TABLE IF NOT EXISTS scans (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id  INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    phase          INTEGER NOT NULL,
    tool           TEXT NOT NULL,
    target         TEXT NOT NULL,
    command        TEXT NOT NULL,
    output_path    TEXT,
    status         TEXT NOT NULL DEFAULT 'running',
    findings_count INTEGER NOT NULL DEFAULT 0,
    started_at     TEXT NOT NULL,
    finished_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_engagement ON scans(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scans_status     ON scans(status);

CREATE TABLE IF NOT EXISTS evidence (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id     INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_type  TEXT NOT NULL,
    file_path      TEXT NOT NULL,
    description    TEXT,
    hash_sha256    TEXT,
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);

CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id              TEXT PRIMARY KEY NOT NULL,
    description         TEXT,
    cvss_score          REAL,
    cvss_vector         TEXT,
    epss_score          REAL,
    cpe_matches         TEXT NOT NULL DEFAULT '[]',
    references_json     TEXT NOT NULL DEFAULT '[]',
    kev_known_exploited INTEGER NOT NULL DEFAULT 0,
    kev_due_date        TEXT,
    kev_added_date      TEXT,
    published_at        TEXT,
    modified_at         TEXT,
    synced_at           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_cache(cvss_score);
CREATE INDEX IF NOT EXISTS idx_cve_kev ON cve_cache(kev_known_exploited);

CREATE TABLE IF NOT EXISTS exploits (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id    TEXT,
    source    TEXT NOT NULL,
    source_id TEXT NOT NULL,
    title     TEXT,
    description TEXT,
    poc_url   TEXT,
    tags      TEXT NOT NULL DEFAULT '[]',
    platform  TEXT,
    synced_at TEXT NOT NULL,
    UNIQUE(source, source_id)
);

CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_source ON exploits(source);

CREATE TABLE IF NOT EXISTS tech_cve_map (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    product       TEXT NOT NULL,
    version_range TEXT,
    cve_id        TEXT NOT NULL REFERENCES cve_cache(cve_id) ON DELETE CASCADE,
    UNIQUE(product, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_tech_product ON tech_cve_map(product);

CREATE TABLE IF NOT EXISTS engagement_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    brief_json      TEXT NOT NULL,
    sync_generation INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_intel_engagement ON engagement_intel(engagement_id);

CREATE VIEW IF NOT EXISTS cross_findings AS
SELECT
    f.id AS finding_id,
    f.category,
    f.severity,
    f.title,
    a.type AS asset_type,
    a.tech_stack_json,
    e.id AS engagement_id,
    e.target,
    e.platform,
    f.status,
    f.created_at
FROM findings f
JOIN engagements e ON f.engagement_id = e.id
LEFT JOIN assets a ON f.asset_id = a.id
WHERE f.status NOT IN ('false_positive', 'rejected');
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
    return dict(row)


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------

class Database:
    """Async SQLite wrapper for all RedBreach persistence."""

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open connection, enforce FK pragma, create schema, set version."""
        # Ensure the database's parent directory exists so a fresh checkout
        # works with no manual setup. In-memory DBs have no directory to make.
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_SCHEMA)
        await self._migrate()
        await self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            ("schema_version", SCHEMA_VERSION),
        )
        await self._conn.commit()

    async def _migrate(self) -> None:
        """Additive, idempotent column migrations for pre-existing databases.

        ``CREATE TABLE IF NOT EXISTS`` never alters an existing table, so a
        database created under an older schema will be missing newer columns.
        Add any that are absent (safe to run every startup).
        """
        async with self._conn.execute("PRAGMA table_info(findings)") as cur:
            existing = {row["name"] for row in await cur.fetchall()}
        additions = {
            "confidence": "REAL",
            "triage_priority": "INTEGER",
            "triage_reasoning": "TEXT",
            "cvss_score": "REAL",
            "cvss_vector": "TEXT",
            "epss_score": "REAL",
            "cwe": "TEXT",
            "attack_technique": "TEXT",
        }
        for col, coltype in additions.items():
            if col not in existing:
                await self._conn.execute(f"ALTER TABLE findings ADD COLUMN {col} {coltype}")
                logger.info("Migration: added findings.%s (%s)", col, coltype)
        await self._conn.commit()

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Meta
    # ------------------------------------------------------------------

    async def get_meta(self, key: str) -> str | None:
        async with self._conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ) as cur:
            row = await cur.fetchone()
        return row["value"] if row else None

    async def list_tables(self) -> list[str]:
        async with self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ) as cur:
            rows = await cur.fetchall()
        return [r["name"] for r in rows]

    # ------------------------------------------------------------------
    # Engagements
    # ------------------------------------------------------------------

    async def create_engagement(
        self,
        eng_type: str,
        platform: str | None,
        target: str,
        scope_json: str,
        client_name: str | None = None,
        contract_notes: str | None = None,
    ) -> int:
        now = _now()
        async with self._conn.execute(
            """
            INSERT INTO engagements
                (type, platform, target, client_name, contract_notes,
                 scope_json, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
            """,
            (eng_type, platform, target, client_name, contract_notes,
             scope_json, now, now),
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_engagement(self, eng_id: int) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (eng_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_dict(row) if row else None

    async def list_engagements(self) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM engagements WHERE status != 'deleted' ORDER BY created_at DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    async def delete_engagement(self, eng_id: int) -> None:
        """Soft-delete: sets status to 'deleted'."""
        await self._conn.execute(
            "UPDATE engagements SET status = 'deleted', updated_at = ? WHERE id = ?",
            (_now(), eng_id),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    async def create_asset(
        self,
        engagement_id: int,
        asset_type: str,
        value: str,
        tech_stack_json: str = "{}",
        notes: str | None = None,
    ) -> int:
        async with self._conn.execute(
            """
            INSERT INTO assets
                (engagement_id, type, value, tech_stack_json, notes, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, asset_type, value, tech_stack_json, notes, _now()),
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_assets(self, engagement_id: int) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM assets WHERE engagement_id = ? ORDER BY discovered_at",
            (engagement_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def create_finding(
        self,
        engagement_id: int,
        asset_id: int | None,
        title: str,
        severity: str,
        category: str | None = None,
        description: str | None = None,
        steps_to_reproduce: str | None = None,
        poc_text: str | None = None,
        impact: str | None = None,
        recommended_fix: str | None = None,
    ) -> int:
        now = _now()
        cwe = cwe_for_category(category)  # auto-classify every finding by category
        attack = attack_for_category(category)
        async with self._conn.execute(
            """
            INSERT INTO findings
                (engagement_id, asset_id, title, severity, category, status,
                 description, steps_to_reproduce, poc_text, impact,
                 recommended_fix, cwe, attack_technique, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, asset_id, title, severity, category,
             description, steps_to_reproduce, poc_text, impact,
             recommended_fix, cwe, attack, now, now),
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_findings(self, engagement_id: int) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE engagement_id = ? ORDER BY created_at DESC",
            (engagement_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    async def get_finding(self, finding_id: int) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_dict(row) if row else None

    async def update_finding(self, finding_id: int, **kwargs: Any) -> None:
        """Update arbitrary columns on a finding."""
        allowed = {
            "title", "severity", "category", "status", "description",
            "steps_to_reproduce", "poc_text", "impact", "recommended_fix",
            "confidence", "triage_priority", "triage_reasoning", "chain_parent_id",
            "cvss_score", "cvss_vector", "epss_score", "cwe", "attack_technique",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        updates["updated_at"] = _now()
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        values = list(updates.values()) + [finding_id]
        await self._conn.execute(
            f"UPDATE findings SET {set_clause} WHERE id = ?", values,
        )
        await self._conn.commit()

    async def set_triage_result(
        self,
        finding_id: int,
        is_false_positive: bool,
        confidence: float,
        priority: int,
        reasoning: str,
    ) -> None:
        """Persist an AI triage verdict. Marks status false_positive when flagged;
        otherwise leaves status untouched so existing verified/new state survives."""
        updates: dict[str, Any] = {
            "confidence": confidence,
            "triage_priority": priority,
            "triage_reasoning": reasoning,
        }
        if is_false_positive:
            updates["status"] = "false_positive"
        await self.update_finding(finding_id, **updates)

    async def link_chain(self, parent_id: int, member_ids: list[int]) -> None:
        """Point each member finding at the parent chain finding via chain_parent_id."""
        for mid in member_ids:
            if mid != parent_id:
                await self.update_finding(mid, chain_parent_id=parent_id)

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    async def create_scan(
        self,
        engagement_id: int,
        phase: int,
        tool: str,
        target: str,
        command: str,
        output_path: str | None = None,
    ) -> int:
        async with self._conn.execute(
            """
            INSERT INTO scans
                (engagement_id, phase, tool, target, command, output_path,
                 status, findings_count, started_at)
            VALUES (?, ?, ?, ?, ?, ?, 'running', 0, ?)
            """,
            (engagement_id, phase, tool, target, command, output_path, _now()),
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_scans(self, engagement_id: int) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM scans WHERE engagement_id = ? ORDER BY started_at DESC",
            (engagement_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    async def complete_scan(
        self,
        scan_id: int,
        status: str = "complete",
        findings_count: int = 0,
    ) -> None:
        await self._conn.execute(
            """
            UPDATE scans
            SET status = ?, findings_count = ?, finished_at = ?
            WHERE id = ?
            """,
            (status, findings_count, _now(), scan_id),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    async def create_evidence(
        self, finding_id: int, evidence_type: str, file_path: str,
        description: str | None = None, hash_sha256: str | None = None,
    ) -> int:
        """Store an evidence record."""
        now = datetime.now(timezone.utc).isoformat()
        async with self._conn.execute(
            """INSERT INTO evidence (finding_id, evidence_type, file_path, description, hash_sha256, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (finding_id, evidence_type, file_path, description, hash_sha256, now),
        ) as cursor:
            row_id = cursor.lastrowid
        await self._conn.commit()
        return row_id

    async def get_evidence(self, finding_id: int) -> list[dict]:
        """Get all evidence for a finding."""
        async with self._conn.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY created_at",
            (finding_id,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # CVE Cache
    # ------------------------------------------------------------------

    async def upsert_cve(self, cve_id: str, description: str = None,
                         cvss_score: float = None, cvss_vector: str = None,
                         epss_score: float = None, cpe_matches: str = "[]",
                         references: str = "[]", kev_known_exploited: int = 0,
                         kev_due_date: str = None, kev_added_date: str = None,
                         published_at: str = None, modified_at: str = None) -> None:
        await self._conn.execute(
            """INSERT INTO cve_cache
                (cve_id, description, cvss_score, cvss_vector, epss_score,
                 cpe_matches, references_json, kev_known_exploited,
                 kev_due_date, kev_added_date, published_at, modified_at, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                cvss_vector=excluded.cvss_vector,
                epss_score=excluded.epss_score,
                cpe_matches=excluded.cpe_matches,
                references_json=excluded.references_json,
                kev_known_exploited=excluded.kev_known_exploited,
                kev_due_date=excluded.kev_due_date,
                kev_added_date=excluded.kev_added_date,
                published_at=excluded.published_at,
                modified_at=excluded.modified_at,
                synced_at=excluded.synced_at""",
            (cve_id, description, cvss_score, cvss_vector, epss_score,
             cpe_matches, references, kev_known_exploited, kev_due_date,
             kev_added_date, published_at, modified_at, _now()),
        )
        await self._conn.commit()

    async def get_cve(self, cve_id: str) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM cve_cache WHERE cve_id = ?", (cve_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_dict(row) if row else None

    async def get_kev_cves(self) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM cve_cache WHERE kev_known_exploited = 1 ORDER BY cvss_score DESC"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    async def search_cves(self, keyword: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM cve_cache WHERE description LIKE ? OR cve_id LIKE ? ORDER BY cvss_score DESC",
            (f"%{keyword}%", f"%{keyword}%"),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    async def get_cves_for_tech(self, product: str) -> list[dict]:
        async with self._conn.execute(
            """SELECT c.* FROM cve_cache c
               JOIN tech_cve_map t ON c.cve_id = t.cve_id
               WHERE LOWER(t.product) = LOWER(?)
               ORDER BY c.cvss_score DESC""",
            (product,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Exploits
    # ------------------------------------------------------------------

    async def upsert_exploit(self, source: str, source_id: str,
                             title: str = None, cve_id: str = None,
                             description: str = None, poc_url: str = None,
                             tags: str = "[]", platform: str = None) -> None:
        await self._conn.execute(
            """INSERT INTO exploits
                (cve_id, source, source_id, title, description, poc_url, tags, platform, synced_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source, source_id) DO UPDATE SET
                cve_id=excluded.cve_id, title=excluded.title,
                description=excluded.description, poc_url=excluded.poc_url,
                tags=excluded.tags, platform=excluded.platform,
                synced_at=excluded.synced_at""",
            (cve_id, source, source_id, title, description, poc_url, tags, platform, _now()),
        )
        await self._conn.commit()

    async def get_exploits_for_cve(self, cve_id: str) -> list[dict]:
        async with self._conn.execute(
            "SELECT * FROM exploits WHERE cve_id = ?", (cve_id,)
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Tech-CVE Map
    # ------------------------------------------------------------------

    async def add_tech_cve_mapping(self, product: str, version_range: str, cve_id: str) -> None:
        await self._conn.execute(
            """INSERT INTO tech_cve_map (product, version_range, cve_id)
               VALUES (?, ?, ?)
               ON CONFLICT(product, cve_id) DO UPDATE SET version_range=excluded.version_range""",
            (product, version_range, cve_id),
        )
        await self._conn.commit()

    # ------------------------------------------------------------------
    # Engagement Intel
    # ------------------------------------------------------------------

    async def save_intel_brief(self, engagement_id: int, brief_json: str,
                               sync_generation: int) -> int:
        await self._conn.execute(
            "DELETE FROM engagement_intel WHERE engagement_id = ?", (engagement_id,)
        )
        async with self._conn.execute(
            """INSERT INTO engagement_intel (engagement_id, brief_json, sync_generation, created_at)
               VALUES (?, ?, ?, ?)""",
            (engagement_id, brief_json, sync_generation, _now()),
        ) as cur:
            row_id = cur.lastrowid
        await self._conn.commit()
        return row_id

    async def get_intel_brief(self, engagement_id: int) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM engagement_intel WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 1",
            (engagement_id,),
        ) as cur:
            row = await cur.fetchone()
        return _row_to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Sync Generation
    # ------------------------------------------------------------------

    async def get_sync_generation(self) -> int:
        val = await self.get_meta("sync_generation")
        return int(val) if val else 0

    async def increment_sync_generation(self) -> int:
        gen = await self.get_sync_generation() + 1
        await self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            ("sync_generation", str(gen)),
        )
        await self._conn.commit()
        return gen
