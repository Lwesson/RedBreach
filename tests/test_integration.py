import pytest
from unittest.mock import AsyncMock, patch

from redbreach.db import Database
from redbreach.config import load_config
from redbreach.core.pipeline import Pipeline
from redbreach.modules.recon import ReconModule
from redbreach.core.subprocess_runner import SubprocessResult
from redbreach.reporting.generator import ReportGenerator


pytestmark = pytest.mark.asyncio


def make_result(stdout="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr="", returncode=returncode,
        timed_out=False, duration_seconds=1.0, command=["test"],
    )


async def test_full_engagement_flow(tmp_path):
    """Full flow: create engagement -> recon -> store findings -> generate report."""
    # Setup
    cfg = load_config(tmp_path)
    db = Database(str(cfg.db_path))
    await db.initialize()

    # Create engagement
    eng_id = await db.create_engagement(
        eng_type="bounty",
        platform="hackerone",
        target="example.com",
        scope_json='{"in_scope": ["*.example.com"]}',
    )
    eng = await db.get_engagement(eng_id)
    assert eng is not None

    # Run recon with mocked tools
    recon = ReconModule()
    subfinder_output = "api.example.com\nwww.example.com\ndev.example.com\n"

    with patch.object(recon, "run_tool", new_callable=AsyncMock) as mock_run, \
         patch.object(recon, "_query_crtsh", new_callable=AsyncMock) as mock_crtsh:
        mock_run.return_value = make_result(stdout=subfinder_output)
        mock_crtsh.return_value = [
            {"type": "domain", "value": "cdn.example.com"},
        ]

        pipe = Pipeline(db=db, modules=[recon])
        assets = await pipe.run_phase(2, eng)

    # Verify assets stored
    stored_assets = await db.get_assets(eng_id)
    assert len(stored_assets) >= 3
    values = [a["value"] for a in stored_assets]
    assert "api.example.com" in values

    # Add a finding manually (simulating Phase 4/5)
    finding_id = await db.create_finding(
        engagement_id=eng_id,
        asset_id=stored_assets[0]["id"],
        title="[High] IDOR on /api/users/{id}",
        severity="high",
        category="idor",
        description="Insecure Direct Object Reference allows accessing other users' data.",
        steps_to_reproduce="1. Login as user A\n2. GET /api/users/999\n3. Observe user B's data returned",
        poc_text="curl -H 'Auth: tokenA' https://api.example.com/api/users/999",
        impact="Any authenticated user can read any other user's PII.",
        recommended_fix="Implement server-side authorization checks on the user ID parameter.",
    )

    # Generate report
    gen = ReportGenerator()
    finding = await db.get_finding(finding_id)
    report = gen.generate("hackerone", finding)

    assert "IDOR" in report
    assert "Steps to Reproduce" in report
    assert "curl" in report
    assert "HIGH" in report

    # Save report
    report_path = tmp_path / "reports" / f"finding_{finding_id}_hackerone.md"
    gen.save("hackerone", finding, report_path)
    assert report_path.exists()

    await db.close()


async def test_engagement_list_and_delete(tmp_path):
    """Create, list, and delete engagements."""
    cfg = load_config(tmp_path)
    db = Database(str(cfg.db_path))
    await db.initialize()

    eng1 = await db.create_engagement("bounty", "hackerone", "a.com", "{}")
    eng2 = await db.create_engagement("pentest", None, "b.com", "{}")

    engagements = await db.list_engagements()
    assert len(engagements) == 2

    await db.delete_engagement(eng1)
    engagements = await db.list_engagements()
    assert len(engagements) == 1
    assert engagements[0]["target"] == "b.com"

    await db.close()
