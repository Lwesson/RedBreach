import json
import pytest
from unittest.mock import AsyncMock, patch

from redbreach.modules.web_enum import WebEnumModule
from redbreach.core.subprocess_runner import SubprocessResult

pytestmark = pytest.mark.asyncio

@pytest.fixture
def web_enum():
    return WebEnumModule()

@pytest.fixture
def engagement():
    return {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}

@pytest.fixture
def assets():
    return [
        {"type": "domain", "value": "www.example.com"},
        {"type": "domain", "value": "api.example.com"},
        {"type": "domain", "value": "dev.example.com"},
    ]

def make_result(stdout="", stderr="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
        timed_out=False, duration_seconds=1.0, command=["test"],
    )

async def test_parse_httpx_probe(web_enum, fixtures_dir):
    raw = (fixtures_dir / "httpx_probe_output.json").read_text()
    results = web_enum.parse_output("httpx", raw)
    assert len(results) == 3
    assert results[0]["tech"] == ["nginx", "jQuery"]
    assert results[0]["status_code"] == 200
    assert results[0]["webserver"] == "nginx/1.24"

async def test_parse_katana_output(web_enum, fixtures_dir):
    raw = (fixtures_dir / "katana_output.txt").read_text()
    results = web_enum.parse_output("katana", raw)
    urls = [r["value"] for r in results]
    assert "https://www.example.com/login" in urls
    assert "https://www.example.com/api/v1/users" in urls
    assert all(r["type"] == "url" for r in results)

async def test_enumerate_probes_domains(web_enum, engagement, assets):
    httpx_output = '{"input":"www.example.com","url":"https://www.example.com","status_code":200,"title":"Test","tech":["nginx"],"content_length":100,"webserver":"nginx","cdn":false,"method":"GET","host":"1.2.3.4","content_type":"text/html","response_time":"50ms"}\n'
    with patch.object(web_enum, "run_tool", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = make_result(stdout=httpx_output)
        enriched = await web_enum.enumerate(engagement, assets)
        mock_run.assert_called()
        assert len(enriched) >= 1

async def test_enumerate_crawls_with_katana(web_enum, engagement, assets):
    httpx_out = '{"input":"www.example.com","url":"https://www.example.com","status_code":200,"title":"T","tech":[],"content_length":1,"webserver":"","cdn":false,"method":"GET","host":"1.2.3.4","content_type":"text/html","response_time":"1ms"}\n'
    katana_out = "https://www.example.com/login\nhttps://www.example.com/api\n"
    call_count = 0

    async def mock_run(cmd, **kwargs):
        nonlocal call_count
        call_count += 1
        if cmd[0] == "httpx":
            return make_result(stdout=httpx_out)
        elif cmd[0] == "katana":
            return make_result(stdout=katana_out)
        return make_result()

    with patch.object(web_enum, "run_tool", side_effect=mock_run):
        results = await web_enum.enumerate(engagement, assets)
        assert call_count >= 2

async def test_module_properties(web_enum):
    assert web_enum.name == "web_enum"
    assert "httpx" in web_enum.tools_required
    assert "katana" in web_enum.tools_required


def test_extract_js_endpoints():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = '''
    var api = "/api/v2/users";
    fetch("/api/v2/orders/list");
    const URL = "https://api.example.com/admin/secrets";
    request("/internal/debug")
    '''
    endpoints = mod._extract_js_endpoints(js)
    assert "/api/v2/users" in endpoints
    assert "/api/v2/orders/list" in endpoints
    assert "https://api.example.com/admin/secrets" in endpoints
    assert "/internal/debug" in endpoints


def test_extract_js_endpoints_dedupes():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = '"/api/v1/x"; "/api/v1/x"; "/api/v1/x";'
    endpoints = mod._extract_js_endpoints(js)
    assert endpoints.count("/api/v1/x") == 1


def test_extract_js_endpoints_ignores_noise():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = 'var x = "hello"; var y = "/"; var z = "//cdn.example.com/lib.js";'
    endpoints = mod._extract_js_endpoints(js)
    assert "hello" not in endpoints
    assert "/" not in endpoints


def test_extract_js_secrets_detects_aws_key():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = 'const k = "AKIAIOSFODNN7EXAMPLE";'
    secrets = mod._extract_js_secrets(js)
    assert any(s["pattern"] == "aws_access_key" for s in secrets)
    assert any("AKIAIOSFODNN7EXAMPLE" in s["match"] for s in secrets)


def test_extract_js_secrets_detects_jwt():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = 'token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
    secrets = mod._extract_js_secrets(js)
    assert any(s["pattern"] == "jwt" for s in secrets)


def test_extract_js_secrets_detects_slack_token():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = 'slack: "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"'
    secrets = mod._extract_js_secrets(js)
    assert any(s["pattern"] == "slack_token" for s in secrets)


def test_extract_js_secrets_detects_github_token():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = 'gh: "ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234"'
    secrets = mod._extract_js_secrets(js)
    assert any(s["pattern"] == "github_token" for s in secrets)


def test_extract_js_secrets_detects_private_key():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = '"-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAA"'
    secrets = mod._extract_js_secrets(js)
    assert any(s["pattern"] == "private_key" for s in secrets)


def test_extract_js_secrets_clean_returns_empty():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    js = 'var x = "hello world"; const y = 42;'
    secrets = mod._extract_js_secrets(js)
    assert secrets == []


@pytest.mark.asyncio
async def test_analyze_javascript_emits_endpoints_and_findings():
    from redbreach.modules.web_enum import WebEnumModule
    from unittest.mock import AsyncMock, patch
    mod = WebEnumModule()

    js_body = '''
    var api = "/api/v2/users";
    var token = "ghp_abcdefghijklmnopqrstuvwxyzABCDEF1234";
    '''

    async def fake_fetch(urls):
        return {urls[0]: js_body}

    with patch.object(mod, "_fetch_js_files", side_effect=fake_fetch):
        results = await mod._analyze_javascript(["https://example.com/app.js"])

    endpoints = [r for r in results if r.get("type") == "api_endpoint"]
    findings = [r for r in results if r.get("type") == "finding"]
    assert any(e["value"] == "/api/v2/users" for e in endpoints)
    assert any(f["category"] == "secret_in_js" for f in findings)
    assert all(e.get("source") == "js_analysis" for e in endpoints)


@pytest.mark.asyncio
async def test_analyze_javascript_handles_empty_url_list():
    from redbreach.modules.web_enum import WebEnumModule
    mod = WebEnumModule()
    results = await mod._analyze_javascript([])
    assert results == []


@pytest.mark.asyncio
async def test_enumerate_calls_js_analysis_for_js_urls():
    from redbreach.modules.web_enum import WebEnumModule
    from unittest.mock import AsyncMock, patch
    mod = WebEnumModule()

    async def mock_probe(domains):
        return [{"type": "domain", "value": "example.com",
                 "url": "https://example.com", "status_code": 200}]

    async def mock_crawl(urls):
        return [
            {"type": "url", "value": "https://example.com/app.js"},
            {"type": "url", "value": "https://example.com/page"},
        ]

    async def mock_params(urls):
        return []

    async def mock_js(urls):
        assert "https://example.com/app.js" in urls
        return [{"type": "api_endpoint", "value": "/from/js", "source": "js_analysis"}]

    with patch.object(mod, "_probe_hosts", side_effect=mock_probe), \
         patch.object(mod, "_crawl_endpoints", side_effect=mock_crawl), \
         patch.object(mod, "_discover_params", side_effect=mock_params), \
         patch.object(mod, "_analyze_javascript", side_effect=mock_js):
        results = await mod.enumerate({"target": "example.com"},
                                      [{"type": "domain", "value": "example.com"}])

    assert any(r.get("source") == "js_analysis" for r in results)


async def test_probe_hosts_removes_tempfile(web_enum):
    # Regression: probe/crawl/discover used delete=False temp files and leaked one each.
    import os
    captured = {}

    async def fake_run(cmd, **kwargs):
        captured["file"] = cmd[cmd.index("-l") + 1]
        assert os.path.exists(captured["file"])
        return make_result(stdout="")

    with patch.object(web_enum, "run_tool", side_effect=fake_run):
        await web_enum._probe_hosts(["a.example.com"])
    assert not os.path.exists(captured["file"])
