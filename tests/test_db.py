import pytest
import pytest_asyncio

from redbreach.db import Database, SCHEMA_VERSION


pytestmark = pytest.mark.asyncio


async def test_initialize_creates_tables(db):
    """Database.initialize creates all required tables."""
    tables = await db.list_tables()
    assert "engagements" in tables
    assert "assets" in tables
    assert "findings" in tables
    assert "scans" in tables
    assert "meta" in tables


async def test_schema_version_set(db):
    """Schema version is set after initialization."""
    version = await db.get_meta("schema_version")
    assert version == SCHEMA_VERSION


async def test_create_engagement(db):
    """Create and retrieve an engagement."""
    eng_id = await db.create_engagement(
        eng_type="bounty",
        platform="hackerone",
        target="example.com",
        scope_json='{"in_scope": ["*.example.com"]}',
    )
    eng = await db.get_engagement(eng_id)
    assert eng["target"] == "example.com"
    assert eng["type"] == "bounty"
    assert eng["platform"] == "hackerone"
    assert eng["status"] == "active"


async def test_list_engagements(db):
    """List engagements returns all active."""
    await db.create_engagement("bounty", "hackerone", "a.com", "{}")
    await db.create_engagement("pentest", None, "b.com", "{}")
    engagements = await db.list_engagements()
    assert len(engagements) == 2


async def test_create_asset(db):
    """Create and retrieve assets for an engagement."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    asset_id = await db.create_asset(eng_id, "domain", "sub.example.com")
    assets = await db.get_assets(eng_id)
    assert len(assets) == 1
    assert assets[0]["value"] == "sub.example.com"
    assert assets[0]["type"] == "domain"


async def test_create_finding(db):
    """Create and retrieve findings."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    asset_id = await db.create_asset(eng_id, "domain", "example.com")
    finding_id = await db.create_finding(
        engagement_id=eng_id,
        asset_id=asset_id,
        title="XSS in search",
        severity="high",
        category="xss",
        description="Reflected XSS in search parameter",
        steps_to_reproduce="1. Go to /search?q=<script>alert(1)</script>",
        impact="Attacker can steal session cookies",
    )
    findings = await db.get_findings(eng_id)
    assert len(findings) == 1
    assert findings[0]["title"] == "XSS in search"
    assert findings[0]["severity"] == "high"
    assert findings[0]["status"] == "new"


async def test_create_scan(db):
    """Create and retrieve scans."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    scan_id = await db.create_scan(
        engagement_id=eng_id,
        phase=2,
        tool="subfinder",
        target="example.com",
        command="subfinder -d example.com",
    )
    scans = await db.get_scans(eng_id)
    assert len(scans) == 1
    assert scans[0]["tool"] == "subfinder"
    assert scans[0]["status"] == "running"


async def test_update_scan_status(db):
    """Update scan status and findings count."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    scan_id = await db.create_scan(eng_id, 2, "subfinder", "example.com", "subfinder -d example.com")
    await db.complete_scan(scan_id, status="complete", findings_count=15)
    scans = await db.get_scans(eng_id)
    assert scans[0]["status"] == "complete"
    assert scans[0]["findings_count"] == 15


async def test_delete_engagement(db):
    """Delete engagement removes it from list."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    await db.delete_engagement(eng_id)
    engagements = await db.list_engagements()
    assert len(engagements) == 0


async def test_evidence_table_exists(db):
    """Schema v2 includes evidence table."""
    tables = await db.list_tables()
    assert "evidence" in tables


async def test_create_and_get_evidence(db):
    """Can store and retrieve evidence records."""
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    finding_id = await db.create_finding(
        engagement_id=eng_id, asset_id=None, title="XSS", severity="high"
    )
    ev_id = await db.create_evidence(
        finding_id=finding_id,
        evidence_type="screenshot",
        file_path="/evidence/1/screenshot_001.png",
        description="XSS alert fired",
    )
    assert ev_id > 0
    records = await db.get_evidence(finding_id)
    assert len(records) == 1
    assert records[0]["file_path"] == "/evidence/1/screenshot_001.png"
    assert records[0]["evidence_type"] == "screenshot"


async def test_schema_version_current(db):
    """Schema version reflects the current migration level."""
    version = await db.get_meta("schema_version")
    assert version == SCHEMA_VERSION


async def test_findings_have_triage_and_chain_columns(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    fid = await db.create_finding(engagement_id=eng_id, asset_id=None, title="X", severity="low")
    f = await db.get_finding(fid)
    for col in ("confidence", "triage_priority", "triage_reasoning", "chain_parent_id"):
        assert col in f
        assert f[col] is None  # unset by default


async def test_create_finding_auto_classifies_cwe(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    sqli = await db.create_finding(engagement_id=eng_id, asset_id=None,
                                   title="SQLi", severity="high", category="sqli")
    idor = await db.create_finding(engagement_id=eng_id, asset_id=None,
                                   title="IDOR", severity="high", category="idor")
    unknown = await db.create_finding(engagement_id=eng_id, asset_id=None,
                                      title="Misc", severity="low", category="something_odd")
    assert (await db.get_finding(sqli))["cwe"] == "CWE-89"
    assert (await db.get_finding(idor))["cwe"] == "CWE-639"
    assert (await db.get_finding(unknown))["cwe"] is None  # unmapped stays null
    # ATT&CK technique auto-populated from the same category
    assert (await db.get_finding(sqli))["attack_technique"] == "T1190"
    assert (await db.get_finding(unknown))["attack_technique"] is None


async def test_findings_have_cvss_columns_and_persist(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    fid = await db.create_finding(engagement_id=eng_id, asset_id=None, title="X", severity="high")
    f = await db.get_finding(fid)
    for col in ("cvss_score", "cvss_vector", "epss_score"):
        assert col in f and f[col] is None
    await db.update_finding(fid, cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            epss_score=0.42)
    f = await db.get_finding(fid)
    assert f["cvss_score"] == 9.8
    assert f["cvss_vector"].endswith("C:H/I:H/A:H")
    assert f["epss_score"] == 0.42


async def test_set_triage_result_false_positive(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    fid = await db.create_finding(engagement_id=eng_id, asset_id=None, title="X", severity="low")
    await db.set_triage_result(fid, is_false_positive=True, confidence=0.15,
                               priority=3, reasoning="generic banner match")
    f = await db.get_finding(fid)
    assert f["status"] == "false_positive"
    assert f["confidence"] == 0.15
    assert f["triage_priority"] == 3
    assert f["triage_reasoning"] == "generic banner match"


async def test_set_triage_result_keeps_status_when_not_fp(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    fid = await db.create_finding(engagement_id=eng_id, asset_id=None, title="X", severity="high")
    await db.set_triage_result(fid, is_false_positive=False, confidence=0.92,
                               priority=1, reasoning="SQL error in body")
    f = await db.get_finding(fid)
    assert f["status"] == "new"          # unchanged
    assert f["confidence"] == 0.92


async def test_link_chain_sets_parent_and_skips_self(db):
    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    parent = await db.create_finding(engagement_id=eng_id, asset_id=None, title="Chain", severity="critical")
    m1 = await db.create_finding(engagement_id=eng_id, asset_id=None, title="SSRF", severity="medium")
    m2 = await db.create_finding(engagement_id=eng_id, asset_id=None, title="Info leak", severity="low")
    await db.link_chain(parent, [m1, m2, parent])
    assert (await db.get_finding(m1))["chain_parent_id"] == parent
    assert (await db.get_finding(m2))["chain_parent_id"] == parent
    assert (await db.get_finding(parent))["chain_parent_id"] is None  # self skipped


async def test_migration_adds_columns_to_preexisting_db(tmp_path):
    """A DB created under an older schema (no triage columns) gains them on init."""
    import sqlite3
    dbfile = tmp_path / "old.db"
    con = sqlite3.connect(str(dbfile))
    con.executescript(
        """
        CREATE TABLE meta (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            engagement_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    con.commit()
    con.close()

    database = Database(str(dbfile))
    await database.initialize()
    async with database._conn.execute("PRAGMA table_info(findings)") as cur:
        cols = {r["name"] for r in await cur.fetchall()}
    version = await database.get_meta("schema_version")
    await database.close()

    assert {"confidence", "triage_priority", "triage_reasoning"} <= cols
    assert version == SCHEMA_VERSION
