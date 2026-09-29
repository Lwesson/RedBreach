import json
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

from redbreach.modules.api import APIModule
from redbreach.core.subprocess_runner import SubprocessResult


@pytest.fixture
def module():
    return APIModule()


def make_result(stdout="", stderr="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
        timed_out=False, duration_seconds=1.0, command=["test"],
    )


def test_module_name(module):
    assert module.name == "api"


def test_tools_required(module):
    assert "nuclei" in module.tools_required
    assert "ffuf" in module.tools_required


@pytest.mark.asyncio
async def test_recon_discovers_endpoints(module):
    mock_result = make_result(stdout="/api/v1/users\n/api/v1/admin\n/api/v1/login\n/api/health\n")
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        assets = await module.recon({"target": "https://api.example.com", "type": "bounty"}, [])
    assert len(assets) == 4
    assert all(a["type"] == "api_endpoint" for a in assets)


@pytest.mark.asyncio
async def test_enumerate_openapi_detection(module):
    """enumerate() detects OpenAPI spec and parses endpoints."""
    spec = json.dumps({
        "openapi": "3.0.0",
        "info": {"title": "Example API", "version": "1.0"},
        "paths": {
            "/api/v1/users": {
                "get": {"summary": "List users", "parameters": [{"name": "page", "in": "query"}]},
                "post": {"summary": "Create user"},
            },
            "/api/v1/users/{id}": {
                "get": {"summary": "Get user", "parameters": [{"name": "id", "in": "path"}]},
                "put": {"summary": "Update user"},
                "delete": {"summary": "Delete user"},
            },
            "/api/v1/orders/{orderId}": {
                "get": {"summary": "Get order"},
            },
        },
    })

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "curl" and "/openapi.json" in cmd[-1]:
            return make_result(stdout=spec)
        return make_result(stdout="", returncode=22)

    with patch.object(module, "run_tool", side_effect=mock_run):
        assets = await module.enumerate(
            {"target": "https://api.example.com", "type": "bounty"},
            [{"type": "api_endpoint", "value": "/api/health"}],
        )

    endpoints = [a for a in assets if a.get("type") == "api_endpoint"]
    values = [e["value"] for e in endpoints]
    assert any("/api/v1/users" in v for v in values)
    assert any("/api/v1/orders" in v for v in values)
    user_endpoint = next(e for e in endpoints if e.get("value") == "/api/v1/users/{id}")
    assert "GET" in user_endpoint.get("methods", [])


@pytest.mark.asyncio
async def test_enumerate_no_spec_returns_assets(module):
    """enumerate() returns original assets when no OpenAPI spec found."""
    async def mock_run(cmd, **kwargs):
        return make_result(stdout="", returncode=22)

    original = [{"type": "api_endpoint", "value": "/api/health"}]
    with patch.object(module, "run_tool", side_effect=mock_run):
        assets = await module.enumerate(
            {"target": "https://api.example.com", "type": "bounty"}, original,
        )
    assert len(assets) >= 1


@pytest.mark.asyncio
async def test_scan_api_endpoints(module):
    nuclei_output = '{"info":{"name":"IDOR","severity":"high"},"matched-at":"https://api.example.com/api/v1/users","template-id":"api-idor"}\n'
    mock_result = make_result(stdout=nuclei_output)
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=mock_result):
        findings = await module.scan({"target": "https://api.example.com", "type": "bounty"},
                                      [{"type": "api_endpoint", "value": "/api/v1/users"}])
    assert len(findings) >= 1
    assert findings[0]["type"] == "finding"


@pytest.mark.asyncio
async def test_scan_graphql_introspection(module):
    """scan() detects GraphQL and tests introspection."""
    introspection = json.dumps({
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query", "fields": [{"name": "user"}, {"name": "orders"}]},
                    {"name": "User", "fields": [{"name": "id"}, {"name": "email"}, {"name": "password_hash"}]},
                    {"name": "Mutation", "fields": [{"name": "updateUser"}, {"name": "deleteUser"}]},
                ]
            }
        }
    })

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "curl":
            body = " ".join(cmd)
            if "__schema" in body:
                return make_result(stdout=introspection)
            return make_result(stdout="{}")
        return make_result(stdout="")

    engagement = {"target": "https://api.example.com", "type": "bounty"}
    assets = [{"type": "api_endpoint", "value": "/graphql"}]

    with patch.object(module, "run_tool", side_effect=mock_run):
        findings = await module.scan(engagement, assets)

    gql_findings = [f for f in findings if "graphql" in f.get("category", "").lower()]
    assert len(gql_findings) >= 1
    assert any("introspection" in f["title"].lower() for f in gql_findings)
    # Should be high severity because password_hash is a sensitive field
    intro_finding = next(f for f in gql_findings if "introspection" in f["title"].lower())
    assert intro_finding["severity"] == "high"


@pytest.mark.asyncio
async def test_scan_no_graphql_endpoints(module):
    """scan() skips GraphQL testing when no GraphQL endpoints exist."""
    async def mock_run(cmd, **kwargs):
        return make_result(stdout="")

    engagement = {"target": "https://api.example.com", "type": "bounty"}
    assets = [{"type": "api_endpoint", "value": "/api/v1/users"}]

    with patch.object(module, "run_tool", side_effect=mock_run):
        findings = await module.scan(engagement, assets)

    gql_findings = [f for f in findings if "graphql" in f.get("category", "").lower()]
    assert len(gql_findings) == 0


@pytest.mark.asyncio
async def test_scan_idor_with_auth_profiles(module):
    """scan() tests for IDOR when auth_session has multiple profiles."""
    from redbreach.core.auth import AuthSession, AuthConfig, AuthType

    auth = AuthSession()
    auth.add_profile("user_a", AuthConfig(auth_type=AuthType.BEARER, token="token-a"))
    auth.add_profile("user_b", AuthConfig(auth_type=AuthType.BEARER, token="token-b"))
    module.auth_session = auth

    engagement = {"target": "https://api.example.com", "type": "bounty"}
    assets = [{"type": "api_endpoint", "value": "/api/v1/users/123", "methods": ["GET"]}]

    # Mock compare_profiles to return identical responses
    mock_compare = AsyncMock(return_value={
        "url": "https://api.example.com/api/v1/users/123",
        "method": "GET",
        "response_a": {"status_code": 200, "body_length": 500, "body_preview": '{"id":123}'},
        "response_b": {"status_code": 200, "body_length": 500, "body_preview": '{"id":123}'},
        "diff": {"same_status": True, "same_body": True, "possible_idor": True,
                 "status_a": 200, "length_a": 500},
    })
    auth.compare_profiles = mock_compare

    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=make_result()):
        findings = await module.scan(engagement, assets)

    idor_findings = [f for f in findings if "idor" in f.get("category", "").lower()]
    assert len(idor_findings) >= 1


@pytest.mark.asyncio
async def test_scan_skips_idor_without_auth(module):
    """scan() skips IDOR testing when no auth_session configured."""
    module.auth_session = None
    engagement = {"target": "https://api.example.com", "type": "bounty"}
    assets = [{"type": "api_endpoint", "value": "/api/v1/users/123", "methods": ["GET"]}]

    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=make_result()):
        findings = await module.scan(engagement, assets)

    idor_findings = [f for f in findings if "idor" in f.get("category", "").lower()]
    assert len(idor_findings) == 0


@pytest.mark.asyncio
async def test_idor_write_method_is_critical_with_evidence(module):
    """A write-method IDOR (DELETE) is rated critical and carries reproducible evidence."""
    from redbreach.core.auth import AuthSession, AuthConfig, AuthType

    auth = AuthSession()
    auth.add_profile("user_a", AuthConfig(auth_type=AuthType.BEARER, token="a"))
    auth.add_profile("user_b", AuthConfig(auth_type=AuthType.BEARER, token="b"))
    module.auth_session = auth

    engagement = {"target": "https://api.example.com", "type": "bounty"}
    assets = [{"type": "api_endpoint", "value": "/api/v1/orders/55", "methods": ["DELETE"]}]

    auth.compare_profiles = AsyncMock(return_value={
        "diff": {"possible_idor": True, "status_b": 200, "length_b": 42, "same_body": True},
    })
    with patch.object(module, "run_tool", new_callable=AsyncMock, return_value=make_result()):
        findings = await module.scan(engagement, assets)

    idor = [f for f in findings if f.get("category") == "idor"]
    assert len(idor) == 1
    assert idor[0]["severity"] == "critical"       # write outranks read
    assert idor[0]["matched_at"].endswith("/api/v1/orders/55")
    assert "status_b=200" in idor[0]["extracted_results"]


@pytest.mark.asyncio
async def test_suggest_tests_context_aware(module):
    """suggest_tests generates specific suggestions based on findings."""
    findings = [
        {"type": "finding", "title": "GraphQL Introspection Enabled", "severity": "high",
         "category": "graphql", "host": "https://api.example.com/graphql"},
        {"type": "finding", "title": "Potential IDOR, GET /api/v1/orders/123", "severity": "high",
         "category": "idor", "host": "https://api.example.com/api/v1/orders/123"},
    ]
    suggestions = await module.suggest_tests({"target": "https://api.example.com"}, findings)
    assert len(suggestions) > 0
    descriptions = " ".join(s["description"] for s in suggestions)
    assert "mutation" in descriptions.lower() or "graphql" in descriptions.lower()
    assert "enumerat" in descriptions.lower() or "idor" in descriptions.lower()


@pytest.mark.asyncio
async def test_suggest_tests_existing(module):
    tests = await module.suggest_tests({"target": "https://api.example.com"},
        [{"title": "IDOR", "severity": "high", "category": "api_auth"}])
    assert len(tests) > 0


def test_parse_endpoints(module):
    parsed = module.parse_output("endpoints", "/api/v1/a\n/api/v1/b\n")
    assert len(parsed) == 2


def test_parse_nuclei_api(module):
    raw = '{"info":{"name":"SQLi","severity":"critical"},"matched-at":"https://x.com/api","template-id":"sqli"}\n'
    parsed = module.parse_output("nuclei", raw)
    assert len(parsed) == 1
    assert parsed[0]["severity"] == "critical"


def test_openapi_params_includes_body_and_path_level(module):
    # Old parser only read operation-level `parameters`; now also path-level params
    # and OpenAPI 3 requestBody body properties (most modern API inputs).
    path_item = {
        "parameters": [{"name": "tenant", "in": "path"}],
        "get": {"parameters": [{"name": "page", "in": "query"}]},
        "post": {"requestBody": {"content": {"application/json": {"schema": {
            "properties": {"email": {}, "role": {}}}}}}},
    }
    params = module._openapi_params(path_item)
    assert "tenant" in params
    assert "page" in params
    assert "email" in params and "role" in params


def test_openapi_params_tolerates_junk(module):
    assert module._openapi_params({"get": "not-a-dict", "parameters": "nope"}) == []
