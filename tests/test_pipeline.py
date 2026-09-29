import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from redbreach.core.pipeline import Pipeline, _asset_host
from redbreach.core.scope import ScopeEnforcer


pytestmark = pytest.mark.asyncio


def _enforcer(*in_scope, mode="bounty"):
    return ScopeEnforcer(json.dumps({"in_scope": list(in_scope)}), mode=mode)


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.create_asset = AsyncMock(return_value=1)
    db.create_scan = AsyncMock(return_value=1)
    db.complete_scan = AsyncMock()
    db.get_assets = AsyncMock(return_value=[])
    return db


@pytest.fixture
def mock_module():
    mod = AsyncMock()
    mod.name = "recon"
    mod.recon = AsyncMock(return_value=[
        {"type": "domain", "value": "sub.example.com"},
    ])
    mod.enumerate = AsyncMock(return_value=[])
    mod.scan = AsyncMock(return_value=[])
    return mod


async def test_pipeline_runs_recon_phase(mock_db, mock_module):
    """Pipeline phase 2 calls module.recon and stores assets."""
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mock_module])
    assets = await pipe.run_phase(2, engagement)
    mock_module.recon.assert_called_once()
    assert mock_db.create_asset.call_count == 1


async def test_pipeline_runs_enumerate_phase(mock_db, mock_module):
    """Pipeline phase 3 calls module.enumerate."""
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    mock_db.get_assets.return_value = [{"type": "domain", "value": "example.com"}]
    pipe = Pipeline(db=mock_db, modules=[mock_module])
    await pipe.run_phase(3, engagement)
    mock_module.enumerate.assert_called_once()


async def test_pipeline_skips_unknown_phase(mock_db, mock_module):
    """Pipeline handles unknown phases gracefully."""
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mock_module])
    result = await pipe.run_phase(99, engagement)
    assert result == []


async def test_pipeline_aggregates_across_modules(mock_db):
    """Pipeline aggregates results from multiple modules."""
    mod1 = AsyncMock()
    mod1.name = "recon"
    mod1.recon = AsyncMock(return_value=[{"type": "domain", "value": "a.com"}])
    mod2 = AsyncMock()
    mod2.name = "web"
    mod2.recon = AsyncMock(return_value=[{"type": "domain", "value": "b.com"}])

    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod1, mod2])
    assets = await pipe.run_phase(2, engagement)
    assert mock_db.create_asset.call_count == 2


async def test_pipeline_handles_module_error(mock_db):
    """Pipeline continues if one module raises."""
    mod_good = AsyncMock()
    mod_good.name = "recon"
    mod_good.recon = AsyncMock(return_value=[{"type": "domain", "value": "ok.com"}])
    mod_bad = AsyncMock()
    mod_bad.name = "broken"
    mod_bad.recon = AsyncMock(side_effect=RuntimeError("tool crashed"))

    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod_bad, mod_good])
    assets = await pipe.run_phase(2, engagement)
    assert mock_db.create_asset.call_count == 1


async def test_pipeline_stores_findings_in_phase_4(mock_db, mock_module):
    """Pipeline phase 4 stores findings in database."""
    mock_db.create_finding = AsyncMock(return_value=1)

    mod = AsyncMock()
    mod.name = "web_scan"
    mod.scan = AsyncMock(return_value=[
        {"type": "finding", "title": "SQLi", "severity": "high", "matched_at": "https://example.com/vuln"},
    ])

    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod])
    results = await pipe.run_phase(4, engagement)
    assert mock_db.create_finding.call_count == 1


async def test_pipeline_stores_enumerate_assets(mock_db, mock_module):
    """Pipeline phase 3 stores new assets from enumerate."""
    mock_module.enumerate = AsyncMock(return_value=[
        {"type": "api_endpoint", "value": "/api/users", "methods": ["GET"]},
        {"type": "parameters", "value": "/search", "params": ["q"]},
    ])
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mock_module])
    await pipe.run_phase(3, engagement)
    assert mock_db.create_asset.call_count == 2


async def test_pipeline_stores_suggestions(mock_db):
    """Pipeline phase 5 stores suggestions as findings."""
    mock_db.create_finding = AsyncMock(return_value=1)

    mod = AsyncMock()
    mod.name = "web_scan"
    mod.suggest_tests = AsyncMock(return_value=[
        {"type": "suggested_test", "category": "xss", "description": "Test for stored XSS"},
    ])

    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod])
    await pipe.run_phase(5, engagement)
    assert mock_db.create_finding.call_count == 1


async def test_pipeline_default_phases(mock_db, mock_module):
    """Pipeline.run() defaults to phases 1-5."""
    called_phases = []
    pipe = Pipeline(db=mock_db, modules=[mock_module])
    original_run_phase = pipe.run_phase

    async def tracking_run_phase(phase, engagement):
        called_phases.append(phase)
        return await original_run_phase(phase, engagement)

    pipe.run_phase = tracking_run_phase
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    await pipe.run(engagement)
    assert 2 in called_phases
    assert 3 in called_phases
    assert 4 in called_phases
    assert 5 in called_phases


async def test_pipeline_stores_takeover_findings(mock_db):
    """Pipeline phase 2 stores takeover module findings as findings, not assets."""
    mock_db.create_finding = AsyncMock(return_value=1)

    mod = AsyncMock()
    mod.name = "takeover"
    mod.recon = AsyncMock(return_value=[
        {"type": "finding", "title": "Takeover", "severity": "high",
         "category": "subdomain_takeover", "host": "abandoned.example.com"},
    ])

    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod])
    await pipe.run_phase(2, engagement)
    mock_db.create_finding.assert_called_once()


async def test_pipeline_handles_secret_in_js_findings(mock_db):
    """Phase 3 enumerate findings of type=finding flow through to create_finding."""
    mock_db.create_finding = AsyncMock(return_value=1)

    mod = AsyncMock()
    mod.name = "web_enum"
    mod.enumerate = AsyncMock(return_value=[
        {"type": "api_endpoint", "value": "/api/from/js", "source": "js_analysis"},
        {"type": "finding", "title": "Secret in JS, github_token",
         "severity": "high", "category": "secret_in_js", "host": "https://x.com/app.js"},
    ])

    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod])
    results = await pipe.run_phase(3, engagement)

    assert any(r.get("type") == "finding" for r in results)
    assert any(r.get("type") == "api_endpoint" for r in results)
    mock_db.create_finding.assert_called_once()
    mock_db.create_asset.assert_called_once()


# ── scope enforcement ────────────────────────────────────────────────

async def test_asset_host_extraction():
    assert _asset_host({"type": "host", "value": "api.example.com"}) == "api.example.com"
    assert _asset_host({"type": "url", "value": "https://x.example.com/a?b=1"}) == "x.example.com"
    assert _asset_host({"type": "host", "value": "h.example.com:8443/x"}) == "h.example.com"
    # not host-bound → None (never scope-filtered)
    assert _asset_host({"type": "parameters", "value": "/search"}) is None
    assert _asset_host({"type": "host", "value": ""}) is None


async def test_pipeline_blocks_out_of_scope_recon_asset(mock_db):
    mod = AsyncMock()
    mod.name = "recon"
    mod.recon = AsyncMock(return_value=[
        {"type": "domain", "value": "api.example.com"},  # in scope
        {"type": "domain", "value": "evil.com"},          # out of scope
    ])
    engagement = {"id": 1, "target": "example.com", "type": "bounty",
                  "scope_json": json.dumps({"in_scope": ["*.example.com", "example.com"]})}
    pipe = Pipeline(db=mock_db, modules=[mod], scope_enforcer=_enforcer("*.example.com", "example.com"))
    await pipe.run_phase(2, engagement)
    # only the in-scope asset is stored
    assert mock_db.create_asset.call_count == 1
    stored = mock_db.create_asset.call_args.kwargs["value"]
    assert stored == "api.example.com"


async def test_pipeline_filters_preexisting_out_of_scope_assets(mock_db):
    mock_db.get_assets.return_value = [
        {"type": "host", "value": "in.example.com"},
        {"type": "host", "value": "out.evil.com"},
    ]
    mod = AsyncMock()
    mod.name = "web"
    mod.enumerate = AsyncMock(return_value=[])
    engagement = {"id": 1, "target": "example.com", "type": "bounty",
                  "scope_json": json.dumps({"in_scope": ["*.example.com"]})}
    pipe = Pipeline(db=mock_db, modules=[mod], scope_enforcer=_enforcer("*.example.com"))
    await pipe.run_phase(3, engagement)
    # module only ever sees the in-scope asset
    passed_assets = mod.enumerate.call_args.args[1]
    assert [a["value"] for a in passed_assets] == ["in.example.com"]


async def test_pipeline_scope_off_when_unconfigured(mock_db):
    # bounty + empty scope → filtering OFF, out-of-scope-looking asset still stored
    mod = AsyncMock()
    mod.name = "recon"
    mod.recon = AsyncMock(return_value=[{"type": "domain", "value": "anything.com"}])
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod], scope_enforcer=ScopeEnforcer("{}", mode="bounty"))
    await pipe.run_phase(2, engagement)
    assert mock_db.create_asset.call_count == 1


async def test_pipeline_private_mode_allows_all(mock_db):
    mod = AsyncMock()
    mod.name = "recon"
    mod.recon = AsyncMock(return_value=[{"type": "domain", "value": "internal.corp.local"}])
    engagement = {"id": 1, "target": "corp.local", "type": "private", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod], scope_enforcer=ScopeEnforcer("{}", mode="private"))
    await pipe.run_phase(2, engagement)
    assert mock_db.create_asset.call_count == 1


# ── AI triage + chaining wiring ──────────────────────────────────────

def _ai(text):
    from redbreach.ai.client import AIResponse
    ai = AsyncMock()
    ai.analyze = AsyncMock(return_value=AIResponse(text=text, input_tokens=1, output_tokens=1))
    return ai


async def test_triage_runs_after_scan_and_persists(mock_db):
    mock_db.get_findings = AsyncMock(return_value=[
        {"id": 10, "title": "SQLi", "severity": "high"},
        {"id": 11, "title": "Admin panel", "severity": "info"},
    ])
    mock_db.set_triage_result = AsyncMock()
    ai = _ai(json.dumps({"results": [
        {"finding_index": 0, "is_false_positive": False, "confidence": 0.9, "reasoning": "real", "priority": 1},
        {"finding_index": 1, "is_false_positive": True, "confidence": 0.2, "reasoning": "generic", "priority": 3},
    ]}))
    mod = AsyncMock(); mod.name = "web_scan"; mod.scan = AsyncMock(return_value=[])
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod], ai_client=ai)
    await pipe.run_phase(4, engagement)
    assert mock_db.set_triage_result.await_count == 2
    # finding 11 flagged false-positive
    fp_call = [c for c in mock_db.set_triage_result.call_args_list if c.args[0] == 11][0]
    assert fp_call.args[1] is True  # is_false_positive


async def test_triage_skipped_without_ai_client(mock_db):
    mock_db.get_findings = AsyncMock(return_value=[{"id": 10, "title": "X", "severity": "low"}])
    mock_db.set_triage_result = AsyncMock()
    mod = AsyncMock(); mod.name = "web_scan"; mod.scan = AsyncMock(return_value=[])
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod], ai_client=None)
    await pipe.run_phase(4, engagement)
    mock_db.set_triage_result.assert_not_called()


async def test_triage_skips_already_triaged(mock_db):
    # confidence already set → not re-triaged
    mock_db.get_findings = AsyncMock(return_value=[{"id": 10, "title": "X", "severity": "low", "confidence": 0.8}])
    mock_db.set_triage_result = AsyncMock()
    ai = _ai(json.dumps({"results": []}))
    mod = AsyncMock(); mod.name = "web_scan"; mod.scan = AsyncMock(return_value=[])
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[mod], ai_client=ai)
    await pipe.run_phase(4, engagement)
    ai.analyze.assert_not_called()  # nothing untriaged → no AI call


async def test_chaining_creates_parent_and_links(mock_db):
    mock_db.get_findings = AsyncMock(return_value=[
        {"id": 10, "title": "SSRF", "severity": "medium"},
        {"id": 11, "title": "Internal API", "severity": "low"},
        {"id": 12, "title": "Weak auth", "severity": "medium"},
    ])
    mock_db.create_finding = AsyncMock(return_value=99)
    mock_db.link_chain = AsyncMock()
    ai = _ai(json.dumps({"chains": [
        {"finding_ids": [0, 1], "combined_severity": "critical",
         "attack_path": "SSRF -> Internal API -> RCE", "business_impact": "Full compromise", "cvss_override": 9.6},
    ]}))
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[], ai_client=ai)
    created = await pipe._run_chaining(engagement)
    assert created == 1
    assert mock_db.create_finding.await_count == 1
    assert mock_db.create_finding.call_args.kwargs["category"] == "vuln_chain"
    assert mock_db.create_finding.call_args.kwargs["severity"] == "critical"
    mock_db.link_chain.assert_awaited_once_with(99, [10, 11])


async def test_chaining_normalizes_invalid_severity(mock_db):
    mock_db.get_findings = AsyncMock(return_value=[
        {"id": 10, "title": "A", "severity": "low"},
        {"id": 11, "title": "B", "severity": "low"},
    ])
    mock_db.create_finding = AsyncMock(return_value=99)
    mock_db.link_chain = AsyncMock()
    ai = _ai(json.dumps({"chains": [
        {"finding_ids": [0, 1], "combined_severity": "catastrophic",
         "attack_path": "A -> B", "business_impact": "bad"},
    ]}))
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[], ai_client=ai)
    await pipe._run_chaining(engagement)
    assert mock_db.create_finding.call_args.kwargs["severity"] == "high"  # normalized


async def test_chaining_skips_with_fewer_than_two_candidates(mock_db):
    mock_db.get_findings = AsyncMock(return_value=[{"id": 10, "title": "solo", "severity": "high"}])
    mock_db.create_finding = AsyncMock()
    ai = _ai(json.dumps({"chains": []}))
    engagement = {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}
    pipe = Pipeline(db=mock_db, modules=[], ai_client=ai)
    created = await pipe._run_chaining(engagement)
    assert created == 0
    ai.analyze.assert_not_called()
    mock_db.create_finding.assert_not_called()
