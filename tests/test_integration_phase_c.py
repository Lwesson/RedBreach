import pytest
from unittest.mock import AsyncMock, patch

from redbreach.db import Database
from redbreach.config import load_config
from redbreach.reporting.scoring import calculate_cvss, severity_from_cvss, estimate_epss
from redbreach.reporting.generator import ReportGenerator
from redbreach.core.evidence import EvidenceManager


pytestmark = pytest.mark.asyncio


async def test_scoring_to_report_flow(tmp_path):
    """Score a finding, generate reports for multiple platforms."""
    cvss = calculate_cvss(
        attack_vector="network", attack_complexity="low",
        privileges_required="none", user_interaction="required",
        scope="changed", confidentiality="low", integrity="low", availability="none",
    )
    severity = severity_from_cvss(cvss)
    epss = estimate_epss(cvss, has_public_exploit=True, age_days=10)

    finding = {
        "title": "Reflected XSS", "severity": severity,
        "cvss_score": cvss, "epss_score": epss,
        "category": "xss", "description": "XSS in search",
        "steps_to_reproduce": "1. Visit /search?q=<script>",
        "poc_text": "curl /search?q=<script>alert(1)</script>",
        "impact": "Cookie theft", "target": "example.com",
    }

    gen = ReportGenerator()

    for platform in ["hackerone", "bugcrowd", "synack", "client"]:
        report = gen.generate(platform, finding)
        assert "XSS" in report
        assert severity.upper() in report


async def test_encrypted_evidence_roundtrip(tmp_path):
    """Encrypt evidence, verify it's not plaintext, decrypt it back."""
    mgr = EvidenceManager(tmp_path / "evidence", encryption_key="roundtrip-key-12345678")
    path = mgr.save_tool_output(1, "nuclei", "SENSITIVE FINDING DATA", "")
    assert b"SENSITIVE" not in path.read_bytes()
    decrypted = mgr.decrypt_file(path)
    assert "SENSITIVE FINDING DATA" in decrypted


async def test_db_chain_parent(tmp_path):
    """Findings can reference a chain parent."""
    cfg = load_config(tmp_path)
    db = Database(str(cfg.db_path))
    await db.initialize()

    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", "{}")
    f1 = await db.create_finding(eng_id, None, "XSS", "medium")
    f2 = await db.create_finding(eng_id, None, "Session Hijack", "high")

    # Verify schema has chain_parent_id column
    finding = await db.get_finding(f1)
    assert "chain_parent_id" in finding

    await db.close()
