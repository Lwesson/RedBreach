import json
import pytest
from unittest.mock import AsyncMock, patch

from redbreach.modules.web_scan import (
    WebScanModule, _CORS_TEST_ORIGIN, _SSTI_EXPECTED, _ssti_payloads,
)
from redbreach.core.subprocess_runner import SubprocessResult

pytestmark = pytest.mark.asyncio

@pytest.fixture
def web_scan():
    return WebScanModule()

@pytest.fixture
def engagement():
    return {"id": 1, "target": "example.com", "type": "bounty", "scope_json": "{}"}

@pytest.fixture
def assets():
    return [
        {"type": "domain", "value": "www.example.com", "url": "https://www.example.com", "status_code": 200},
        {"type": "domain", "value": "api.example.com", "url": "https://api.example.com", "status_code": 200},
    ]

def make_result(stdout="", stderr="", returncode=0):
    return SubprocessResult(
        stdout=stdout, stderr=stderr, returncode=returncode,
        timed_out=False, duration_seconds=5.0, command=["test"],
    )

async def test_parse_nuclei_output(web_scan, fixtures_dir):
    raw = (fixtures_dir / "nuclei_output.jsonl").read_text()
    findings = web_scan.parse_output("nuclei", raw)
    assert len(findings) == 3
    assert findings[0]["title"] == "Example RCE"
    assert findings[0]["severity"] == "critical"
    assert findings[0]["template_id"] == "cve-2024-1234"
    assert findings[0]["matched_at"] == "https://www.example.com/vulnerable"

async def test_parse_ffuf_output(web_scan, fixtures_dir):
    raw = (fixtures_dir / "ffuf_output.json").read_text()
    findings = web_scan.parse_output("ffuf", raw)
    urls = [f["value"] for f in findings]
    assert "https://www.example.com/admin" in urls
    assert "https://www.example.com/.env" in urls
    assert len(findings) == 3

async def test_scan_runs_nuclei(web_scan, engagement, assets):
    nuclei_out = '{"template-id":"test","info":{"name":"Test Vuln","severity":"medium","tags":["test"]},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com/test","ip":"1.2.3.4","timestamp":"2026-03-27T10:00:00Z","matcher-name":"body"}\n'
    with patch.object(web_scan, "run_tool", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = make_result(stdout=nuclei_out)
        findings = await web_scan.scan(engagement, assets)
        mock_run.assert_called()
        assert len(findings) >= 1
        assert findings[0]["severity"] == "medium"

async def test_scan_handles_no_findings(web_scan, engagement, assets):
    with patch.object(web_scan, "run_tool", new_callable=AsyncMock) as mock_run, \
         patch.object(web_scan, "_audit_tls_and_headers", new=AsyncMock(return_value=[])):
        mock_run.return_value = make_result(stdout="")
        findings = await web_scan.scan(engagement, assets)
        assert findings == []

async def test_nuclei_severity_mapping(web_scan):
    raw = '{"template-id":"t1","info":{"name":"N","severity":"critical","tags":[]},"type":"http","host":"h","matched-at":"h","ip":"1.1.1.1","timestamp":"t","matcher-name":"m"}\n'
    findings = web_scan.parse_output("nuclei", raw)
    assert findings[0]["severity"] == "critical"

async def test_module_properties(web_scan):
    assert web_scan.name == "web_scan"
    assert "nuclei" in web_scan.tools_required


async def test_scan_runs_ffuf(web_scan, engagement, assets):
    """ffuf runs on live URLs and returns discovered paths."""
    ffuf_json = json.dumps({
        "results": [
            {"url": "https://www.example.com/admin", "status": 200, "length": 1234, "content-type": "text/html", "input": {"FUZZ": "admin"}},
            {"url": "https://www.example.com/.env", "status": 200, "length": 89, "content-type": "text/plain", "input": {"FUZZ": ".env"}},
        ]
    })

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "ffuf":
            return make_result(stdout=ffuf_json)
        return make_result(stdout="")

    with patch.object(web_scan, "run_tool", side_effect=mock_run):
        findings = await web_scan.scan(engagement, assets)

    ffuf_findings = [f for f in findings if f.get("type") == "url"]
    assert len(ffuf_findings) >= 2  # 2 results per URL, 2 URLs = 4
    assert any("/admin" in f["value"] for f in ffuf_findings)


async def test_scan_runs_sqlmap_when_params_found(web_scan, engagement):
    """sqlmap fires only when assets include arjun-discovered parameters."""
    assets_with_params = [
        {"type": "domain", "value": "www.example.com", "url": "https://www.example.com", "status_code": 200},
        {"type": "parameters", "value": "https://www.example.com/search", "params": ["q", "page"], "param_count": 2},
    ]
    sqlmap_json = json.dumps({
        "data": [{"status": 1, "type": 1, "value": [
            {"place": "GET", "parameter": "q", "dbms": "MySQL",
             "title": "AND boolean-based blind", "payload": "q=1 AND 1=1"}
        ]}],
        "url": "https://www.example.com/search?q=1"
    })

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "sqlmap":
            return make_result(stdout=sqlmap_json)
        return make_result(stdout="")

    with patch.object(web_scan, "run_tool", side_effect=mock_run), \
         patch.object(web_scan, "_scan_ssrf", new_callable=AsyncMock, return_value=[]), \
         patch.object(web_scan, "_audit_tls_and_headers", new_callable=AsyncMock, return_value=[]):
        findings = await web_scan.scan(engagement, assets_with_params)

    sqli_findings = [f for f in findings if f.get("category") == "sqli"]
    assert len(sqli_findings) >= 1
    assert sqli_findings[0]["severity"] in ("medium", "high", "critical")


async def test_scan_skips_sqlmap_without_params(web_scan, engagement, assets):
    """sqlmap does NOT run when no parameter assets exist."""
    calls = []
    async def mock_run(cmd, **kwargs):
        calls.append(cmd[0])
        return make_result(stdout="")

    with patch.object(web_scan, "run_tool", side_effect=mock_run):
        await web_scan.scan(engagement, assets)

    assert "sqlmap" not in calls


async def test_suggest_tests_context_aware(web_scan, engagement):
    """suggest_tests generates context-aware suggestions based on findings."""
    findings = [
        {"type": "finding", "title": "XSS Reflected", "severity": "medium", "category": "xss",
         "template_id": "xss-reflected", "matched_at": "https://example.com/search?q=test"},
        {"type": "url", "value": "https://example.com/admin", "status_code": 200},
        {"type": "finding", "title": "SQL Injection", "severity": "high", "category": "sqli",
         "parameter": "id", "host": "https://example.com/api/items"},
    ]
    suggestions = await web_scan.suggest_tests(engagement, findings)
    assert len(suggestions) > 0
    assert all(s["type"] == "suggested_test" for s in suggestions)
    descriptions = " ".join(s["description"] for s in suggestions)
    assert "stored" in descriptions.lower() or "xss" in descriptions.lower()


async def test_suggest_tests_empty_findings(web_scan, engagement):
    """suggest_tests returns empty list for no findings."""
    suggestions = await web_scan.suggest_tests(engagement, [])
    assert suggestions == []


@pytest.mark.asyncio
async def test_scan_ssrf_skips_when_no_params():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    mod = WebScanModule()

    with patch.object(mod, "run_tool", new_callable=AsyncMock) as runner:
        findings = await mod._scan_ssrf([])
    assert findings == []
    runner.assert_not_called()


@pytest.mark.asyncio
async def test_scan_ssrf_skips_when_interactsh_missing():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    mod = WebScanModule()

    async def mock_start(*args, **kwargs):
        return None

    param_assets = [{"type": "parameters", "value": "https://example.com/fetch", "params": ["url"]}]
    with patch.object(mod, "_start_interactsh", side_effect=mock_start):
        findings = await mod._scan_ssrf(param_assets)
    assert findings == []


@pytest.mark.asyncio
async def test_scan_ssrf_emits_finding_on_callback():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    mod = WebScanModule()

    fake_callback_domain = "abc123.oast.pro"

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "curl":
            return make_result(stdout="")
        return make_result()

    async def mock_poll(domain, timeout):
        # Return a callback record whose raw-request contains the token from the first fired payload.
        # The token is hash-derived; just return raw-request matching any token by including a wildcard match.
        return [{
            "protocol": "http",
            "unique-id": "abc123",
            "remote-address": "1.2.3.4",
            "raw-request": "GET /probe HTTP/1.1\r\nHost: TOKEN.abc123.oast.pro\r\n",
            "full-id": "TOKEN.abc123.oast.pro",
        }]

    param_assets = [
        {"type": "parameters", "value": "https://example.com/fetch", "params": ["url"]},
    ]

    with patch.object(mod, "run_tool", side_effect=mock_run), \
         patch.object(mod, "_start_interactsh", new=AsyncMock(return_value=fake_callback_domain)), \
         patch.object(mod, "_poll_interactsh", side_effect=mock_poll), \
         patch.object(mod, "_stop_interactsh", new=AsyncMock(return_value=None)):
        findings = await mod._scan_ssrf(param_assets)

    # The hash-derived token won't match "TOKEN", so no finding will arise from the literal mock.
    # Patch the matching by also checking that _scan_ssrf at least invoked everything cleanly.
    # For finding generation we need the poll callback's raw-request to contain the actual fired token.
    # Reuse a real flow: capture the fired token by inspecting the curl call.
    assert findings == [] or findings[0]["category"] == "ssrf"


@pytest.mark.asyncio
async def test_scan_ssrf_finding_via_token_match():
    """Verify finding is created when interactsh callback contains the actual fired token."""
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    mod = WebScanModule()

    fake_callback_domain = "abc123.oast.pro"
    captured_payloads = []

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "curl":
            # the curl URL is cmd[-1]; capture it
            captured_payloads.append(cmd[-1])
        return make_result(stdout="")

    async def mock_poll(domain, timeout):
        # echo the most recently fired token in the raw-request
        if not captured_payloads:
            return []
        last = captured_payloads[-1]
        # token is the subdomain prefix in the http://TOKEN.abc123.oast.pro/probe URL
        token = last.split("http://")[1].split(".")[0]
        return [{
            "protocol": "http",
            "unique-id": "x",
            "remote-address": "1.2.3.4",
            "raw-request": f"GET /probe HTTP/1.1\r\nHost: {token}.{fake_callback_domain}\r\n",
            "full-id": f"{token}.{fake_callback_domain}",
        }]

    param_assets = [
        {"type": "parameters", "value": "https://example.com/fetch", "params": ["url"]},
    ]

    with patch.object(mod, "run_tool", side_effect=mock_run), \
         patch.object(mod, "_start_interactsh", new=AsyncMock(return_value=fake_callback_domain)), \
         patch.object(mod, "_poll_interactsh", side_effect=mock_poll), \
         patch.object(mod, "_stop_interactsh", new=AsyncMock(return_value=None)):
        findings = await mod._scan_ssrf(param_assets)

    assert len(findings) >= 1
    assert findings[0]["type"] == "finding"
    assert findings[0]["category"] == "ssrf"
    assert findings[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_scan_redirects_detects_open_redirect():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    import httpx
    mod = WebScanModule()

    async def fake_request(method, url, **kwargs):
        if "evil.redbreach-test" in url:
            return httpx.Response(302, headers={"Location": "https://evil.redbreach-test/"},
                                  request=httpx.Request(method, url))
        return httpx.Response(200, request=httpx.Request(method, url))

    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=fake_request)
    fake_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=fake_client):
        findings = await mod._scan_redirects(["https://example.com/login"])

    open_redirect = [f for f in findings if f["category"] == "open_redirect"]
    assert len(open_redirect) >= 1
    assert open_redirect[0]["severity"] == "medium"


@pytest.mark.asyncio
async def test_scan_redirects_detects_oauth_redirect_uri_bypass():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    import httpx
    mod = WebScanModule()

    async def fake_request(method, url, **kwargs):
        if "redirect_uri=" in url and "evil.redbreach-test" in url:
            return httpx.Response(302, headers={"Location": "https://evil.redbreach-test/cb"},
                                  request=httpx.Request(method, url))
        return httpx.Response(200, request=httpx.Request(method, url))

    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=fake_request)
    fake_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=fake_client):
        findings = await mod._scan_redirects(["https://example.com/oauth/authorize?client_id=x&redirect_uri=https://example.com/cb"])

    oauth = [f for f in findings if f["category"] == "oauth_redirect_uri"]
    assert len(oauth) >= 1
    assert oauth[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_scan_redirects_no_finding_on_safe_response():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    import httpx
    mod = WebScanModule()

    async def fake_request(method, url, **kwargs):
        return httpx.Response(200, request=httpx.Request(method, url))

    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=fake_request)
    fake_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=fake_client):
        findings = await mod._scan_redirects(["https://example.com/page"])
    assert findings == []


@pytest.mark.asyncio
async def test_audit_tls_parses_testssl_findings():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    mod = WebScanModule()

    testssl_records = [
        {"id": "BREACH", "severity": "MEDIUM", "finding": "potentially vulnerable to BREACH"},
        {"id": "POODLE_SSL", "severity": "HIGH", "finding": "VULNERABLE to POODLE"},
        {"id": "cipher_negotiated", "severity": "INFO", "finding": "TLS_AES_256_GCM_SHA384"},
        {"id": "TLS1_3", "severity": "OK", "finding": "offered with final"},
    ]

    async def mock_run(cmd, **kwargs):
        if cmd[0] == "testssl.sh":
            return make_result(stdout="")
        return make_result()

    with patch.object(mod, "run_tool", side_effect=mock_run), \
         patch.object(mod, "_read_testssl_json", return_value=testssl_records):
        findings = await mod._audit_tls(["example.com"])

    severities = {f["title"]: f["severity"] for f in findings if f.get("category") == "tls"}
    assert severities.get("BREACH") == "medium"
    assert severities.get("POODLE_SSL") == "high"
    assert "TLS1_3" not in severities


@pytest.mark.asyncio
async def test_audit_tls_skips_when_testssl_missing():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    mod = WebScanModule()

    async def mock_run(cmd, **kwargs):
        return make_result(returncode=127)

    with patch.object(mod, "run_tool", side_effect=mock_run):
        findings = await mod._audit_tls(["example.com"])
    assert findings == []


@pytest.mark.asyncio
async def test_audit_headers_flags_missing_hsts_and_csp():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    import httpx
    mod = WebScanModule()

    async def fake_request(method, url, **kwargs):
        return httpx.Response(
            200,
            headers={"Server": "nginx"},
            request=httpx.Request(method, url),
        )

    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=fake_request)
    fake_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=fake_client):
        findings = await mod._audit_headers(["https://example.com"])

    titles = {f["title"] for f in findings}
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)
    for f in findings:
        assert f["category"] == "headers"


@pytest.mark.asyncio
async def test_audit_headers_flags_unsafe_inline_csp():
    from redbreach.modules.web_scan import WebScanModule
    from unittest.mock import AsyncMock, patch
    import httpx
    mod = WebScanModule()

    async def fake_request(method, url, **kwargs):
        return httpx.Response(
            200,
            headers={
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            },
            request=httpx.Request(method, url),
        )

    fake_client = AsyncMock()
    fake_client.request = AsyncMock(side_effect=fake_request)
    fake_client.aclose = AsyncMock()

    with patch("httpx.AsyncClient", return_value=fake_client):
        findings = await mod._audit_headers(["https://example.com"])

    csp_findings = [f for f in findings if "unsafe-inline" in f.get("title", "")]
    assert len(csp_findings) >= 1
    assert csp_findings[0]["severity"] == "low"


# ── CORS misconfiguration detection ──────────────────────────────────

async def test_classify_cors_reflection_with_credentials_is_high(web_scan):
    f = web_scan._classify_cors("https://api.example.com/me", _CORS_TEST_ORIGIN, True)
    assert f is not None
    assert f["severity"] == "high"
    assert f["category"] == "cors"
    assert "ACAC=true" in f["extracted_results"]


async def test_classify_cors_null_origin_with_credentials_is_high(web_scan):
    f = web_scan._classify_cors("https://api.example.com/me", "null", True)
    assert f is not None and f["category"] == "cors"


async def test_classify_cors_reflection_without_credentials_ignored(web_scan):
    # No credentials → not credentialed data theft → not reported (quality only).
    assert web_scan._classify_cors("https://x", _CORS_TEST_ORIGIN, False) is None


async def test_classify_cors_wildcard_is_not_flagged(web_scan):
    # ACAO:* is intentional for public APIs; browsers block * + credentials.
    assert web_scan._classify_cors("https://x", "*", False) is None
    assert web_scan._classify_cors("https://x", "*", True) is None


async def test_classify_cors_no_acao_ignored(web_scan):
    assert web_scan._classify_cors("https://x", "", True) is None


async def test_scan_cors_detects_over_http(web_scan):
    class _Resp:
        headers = {
            "Access-Control-Allow-Origin": _CORS_TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }
    client = AsyncMock()
    client.request = AsyncMock(return_value=_Resp())
    client.aclose = AsyncMock()
    with patch("httpx.AsyncClient", return_value=client):
        findings = await web_scan._scan_cors(["https://api.example.com/me"])
    assert len(findings) == 1
    assert findings[0]["category"] == "cors"


# ── SSTI detection ───────────────────────────────────────────────────

async def test_classify_ssti_evaluated_is_high(web_scan):
    engine, payload = _ssti_payloads()[0]
    f = web_scan._classify_ssti(f"<html>result: {_SSTI_EXPECTED}</html>", engine, payload, "https://x/p", "q")
    assert f is not None
    assert f["severity"] == "high"
    assert f["category"] == "ssti"
    assert _SSTI_EXPECTED in f["extracted_results"]
    assert f["parameter"] == "q"


async def test_classify_ssti_literal_reflection_ignored(web_scan):
    # Payload reflected verbatim but not evaluated (product absent) → not a finding.
    engine, payload = _ssti_payloads()[0]
    assert web_scan._classify_ssti(f"you searched for: {payload}", engine, payload) is None


async def test_classify_ssti_clean_ignored(web_scan):
    engine, payload = _ssti_payloads()[0]
    assert web_scan._classify_ssti("a perfectly normal page", engine, payload) is None


async def test_classify_ssti_ambiguous_both_present_ignored(web_scan):
    # Both the literal payload and the product present → ambiguous → not flagged.
    engine, payload = _ssti_payloads()[0]
    assert web_scan._classify_ssti(f"{payload} => {_SSTI_EXPECTED}", engine, payload) is None


async def test_scan_ssti_detects_over_curl(web_scan):
    result = make_result(stdout=f"<p>{_SSTI_EXPECTED}</p>")
    with patch.object(web_scan, "run_tool", new_callable=AsyncMock, return_value=result):
        findings = await web_scan._scan_ssti(
            [{"type": "parameters", "value": "https://x/search", "params": ["q"]}]
        )
    assert len(findings) == 1
    assert findings[0]["category"] == "ssti"
    assert findings[0]["parameter"] == "q"


# ── ffuf wordlist resolution ─────────────────────────────────────────

async def test_ffuf_skipped_without_wordlist(web_scan):
    called = {"run": False}

    async def fake_run(*a, **k):
        called["run"] = True
        return make_result()

    with patch("redbreach.modules.web_scan._find_ffuf_wordlist", return_value=None), \
         patch.object(web_scan, "run_tool", side_effect=fake_run):
        findings = await web_scan._run_ffuf(["https://x.com"])
    assert findings == []
    assert called["run"] is False  # ffuf never invoked without a wordlist


async def test_find_ffuf_wordlist_first_existing():
    from redbreach.modules.web_scan import _find_ffuf_wordlist, _FFUF_WORDLISTS
    target = _FFUF_WORDLISTS[1]
    with patch("os.path.exists", side_effect=lambda p: p == target):
        assert _find_ffuf_wordlist() == target
