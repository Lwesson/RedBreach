import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from redbreach.db import Database
from redbreach.config import load_config
from redbreach.core.pipeline import Pipeline
from redbreach.core.scope import ScopeEnforcer
from redbreach.core.evidence import EvidenceManager
from redbreach.modules.web_enum import WebEnumModule
from redbreach.modules.web_scan import WebScanModule
from redbreach.core.subprocess_runner import SubprocessResult
from redbreach.session import SessionManager


pytestmark = pytest.mark.asyncio


def make_result(stdout="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr="", returncode=returncode,
        timed_out=False, duration_seconds=1.0, command=["test"],
    )


async def test_phase_3_4_flow(tmp_path):
    """Full flow: engagement -> enumeration (Phase 3) -> scanning (Phase 4) -> findings stored."""
    cfg = load_config(tmp_path)
    db = Database(str(cfg.db_path))
    await db.initialize()

    eng_id = await db.create_engagement("bounty", "hackerone", "example.com", '{"in_scope": ["*.example.com"]}')
    eng = await db.get_engagement(eng_id)

    await db.create_asset(eng_id, "domain", "www.example.com")
    await db.create_asset(eng_id, "domain", "api.example.com")

    # Phase 3: Enumerate
    web_enum = WebEnumModule()
    httpx_out = '{"input":"www.example.com","url":"https://www.example.com","status_code":200,"title":"T","tech":["nginx"],"content_length":1,"webserver":"nginx","cdn":false,"method":"GET","host":"1.2.3.4","content_type":"text/html","response_time":"1ms"}\n'
    katana_out = "https://www.example.com/login\n"

    async def mock_enum_run(cmd, **kwargs):
        if cmd[0] == "httpx":
            return make_result(stdout=httpx_out)
        elif cmd[0] == "katana":
            return make_result(stdout=katana_out)
        return make_result()

    with patch.object(web_enum, "run_tool", side_effect=mock_enum_run):
        pipe = Pipeline(db=db, modules=[web_enum])
        await pipe.run_phase(3, eng)

    # Phase 4: Scan
    web_scan = WebScanModule()
    nuclei_out = '{"template-id":"cve-test","info":{"name":"Test Vuln","severity":"high","tags":["cve"]},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/login","ip":"1.2.3.4","timestamp":"2026-03-27T10:00:00Z","matcher-name":"body"}\n'

    with patch.object(web_scan, "run_tool", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = make_result(stdout=nuclei_out)
        pipe = Pipeline(db=db, modules=[web_scan])
        await pipe.run_phase(4, eng)

    findings = await db.get_findings(eng_id)
    assert len(findings) >= 1
    assert any("Test Vuln" in f["title"] for f in findings)

    await db.close()


async def test_scope_enforcer_filters_recon(tmp_path):
    scope = json.dumps({"in_scope": ["*.example.com"], "out_of_scope": ["admin.example.com"]})
    enforcer = ScopeEnforcer(scope, mode="bounty")

    targets = ["www.example.com", "evil.com", "admin.example.com", "api.example.com"]
    filtered = enforcer.filter_targets(targets)
    assert "www.example.com" in filtered
    assert "api.example.com" in filtered
    assert "evil.com" not in filtered
    assert "admin.example.com" not in filtered


async def test_session_save_and_resume(tmp_path):
    mgr = SessionManager(tmp_path / "sessions")
    mgr.save(1, {"current_phase": 3, "completed_phases": [1, 2]})
    state = mgr.load(1)
    assert state["current_phase"] == 3


async def test_evidence_captures_tool_output(tmp_path):
    evidence = EvidenceManager(tmp_path / "evidence")
    path = evidence.save_tool_output(1, "nuclei", "CVE-2024-1234 found", "")
    assert path.exists()
    file_hash = evidence.hash_file(path)
    assert len(file_hash) == 64
