"""API attack surface module, endpoint discovery, IDOR, GraphQL, auth bypass testing."""

import json
import logging
import re

from redbreach.modules.base import ModuleBase

logger = logging.getLogger("redbreach.modules.api")

SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}

_OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/v1/api-docs", "/v2/api-docs", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/api/openapi.json",
]

_GRAPHQL_PATHS = ["/graphql", "/gql", "/api/graphql", "/graphql/v1"]

_SENSITIVE_TYPE_NAMES = {"password", "secret", "token", "ssn", "credit_card", "hash", "key", "credential"}

_ID_PATTERN = re.compile(r'/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)', re.IGNORECASE)

_API_TESTS = {
    "graphql": [
        "Test mutations on sensitive types exposed via introspection",
        "Attempt to access admin-only queries/mutations as regular user",
        "Test for persisted query abuse and cache poisoning",
    ],
    "idor": [
        "Test bulk ID enumeration (sequential IDs, UUID prediction)",
        "Check if IDOR exposes PII or financial data",
        "Test IDOR on write operations (PUT/DELETE with another user's resource)",
    ],
    "auth_bypass": [
        "Test all CRUD operations on the unprotected endpoint",
        "Check for privilege escalation via direct API access",
        "Test with different HTTP methods (PUT, DELETE, PATCH)",
    ],
    "api_auth": [
        "Test for broken authentication (missing auth headers)",
        "Test for JWT vulnerabilities (none algorithm, weak secret)",
        "Check for IDOR on all resource endpoints",
    ],
    "api_injection": [
        "Test for SQL injection in query parameters",
        "Test for NoSQL injection in JSON bodies",
        "Check for command injection via API parameters",
    ],
    "default": [
        "Test for rate limiting on sensitive endpoints",
        "Check for mass assignment vulnerabilities",
        "Test for BOLA/BFLA on all CRUD endpoints",
        "Verify proper HTTP method restrictions",
    ],
}


class APIModule(ModuleBase):
    name = "api"
    tools_required = ["nuclei", "ffuf", "katana"]

    def __init__(self, throttled_runner=None, auth_session=None):
        super().__init__(throttled_runner)
        self.auth_session = auth_session

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        target = engagement.get("target", "")
        logger.info("API recon for %s", target)
        result = await self.run_tool(["katana", "-u", target, "-d", "3", "-jc", "-kf", "all"], timeout=180)
        return self._parse_endpoints(result.stdout)

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 3: Detect OpenAPI/Swagger spec, parse endpoints."""
        target = engagement.get("target", "").rstrip("/")
        if not target:
            return assets

        spec = None
        for path in _OPENAPI_PATHS:
            result = await self.run_tool(
                ["curl", "-s", "-f", "-m", "10", f"{target}{path}"],
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                spec = self._parse_openapi_spec(result.stdout)
                if spec:
                    logger.info("OpenAPI spec found at %s%s, %d endpoints", target, path, len(spec))
                    break

        if spec:
            return assets + spec
        return assets

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        if not assets:
            return []
        target = engagement.get("target", "")

        # Nuclei scan (existing)
        nuclei_findings = []
        result = await self.run_tool(
            ["nuclei", "-u", target, "-t", "http/vulnerabilities/", "-jsonl"],
            timeout=300,
        )
        if result.returncode != 127:
            nuclei_findings = self._parse_nuclei(result.stdout)

        # GraphQL testing
        graphql_findings = await self._scan_graphql(target, assets)

        # IDOR testing (requires 2+ auth profiles)
        idor_findings = await self._scan_idor(target, assets)

        # Auth bypass testing (requires auth_session)
        auth_bypass_findings = await self._scan_auth_bypass(target, assets)

        all_findings = nuclei_findings + graphql_findings + idor_findings + auth_bypass_findings
        logger.info(
            "API scan found %d findings (%d nuclei, %d graphql, %d idor, %d auth_bypass)",
            len(all_findings), len(nuclei_findings), len(graphql_findings),
            len(idor_findings), len(auth_bypass_findings),
        )
        return all_findings

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        """Generate context-aware API test suggestions based on findings."""
        suggestions = []
        seen_categories = set()

        for f in findings:
            category = f.get("category", "default")
            if category in seen_categories:
                continue
            seen_categories.add(category)

            tests = _API_TESTS.get(category, _API_TESTS["default"])
            context = f.get("host", "") or f.get("matched_at", "")

            for desc in tests:
                suggestions.append({
                    "type": "suggested_test", "category": category,
                    "description": desc, "context": context,
                })

        return suggestions

    # ── GraphQL testing ──────────────────────────────────────────────

    async def _scan_graphql(self, target: str, assets: list[dict]) -> list[dict]:
        """Test GraphQL endpoints for introspection, batching, and depth limits."""
        findings = []

        gql_endpoints = [
            a["value"] for a in assets
            if a.get("type") == "api_endpoint" and any(gp in a["value"].lower() for gp in _GRAPHQL_PATHS)
        ]

        if not gql_endpoints:
            return []

        for endpoint in gql_endpoints:
            url = f"{target.rstrip('/')}{endpoint}" if not endpoint.startswith("http") else endpoint

            # Test 1: Introspection
            introspection_query = '{"query": "{ __schema { types { name fields { name } } } }"}'
            result = await self.run_tool(
                ["curl", "-s", "-X", "POST", url,
                 "-H", "Content-Type: application/json",
                 "-d", introspection_query],
                timeout=30,
            )
            findings.extend(self._parse_graphql_introspection(result.stdout, url))

            # Test 2: Batch query abuse
            batch_query = '[{"query": "{ __typename }"}, {"query": "{ __typename }"}]'
            result = await self.run_tool(
                ["curl", "-s", "-X", "POST", url,
                 "-H", "Content-Type: application/json",
                 "-d", batch_query],
                timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip().startswith("["):
                findings.append({
                    "type": "finding",
                    "title": f"GraphQL Batch Queries Allowed, {endpoint}",
                    "severity": "medium", "category": "graphql", "host": url,
                    "description": "GraphQL endpoint accepts batched queries, enabling brute-force and rate-limit bypass.",
                })

            # Test 3: Nested query depth
            nested = '{"query": "{ __typename ' + '{ __typename ' * 20 + '} ' * 20 + '}"}'
            result = await self.run_tool(
                ["curl", "-s", "-X", "POST", url,
                 "-H", "Content-Type: application/json",
                 "-d", nested],
                timeout=30,
            )
            if result.returncode == 0:
                try:
                    resp = json.loads(result.stdout)
                    if not resp.get("errors"):
                        findings.append({
                            "type": "finding",
                            "title": f"GraphQL No Query Depth Limit, {endpoint}",
                            "severity": "medium", "category": "graphql", "host": url,
                            "description": "GraphQL endpoint accepts deeply nested queries without depth limiting, enabling DoS.",
                        })
                except json.JSONDecodeError:
                    pass

        return findings

    def _parse_graphql_introspection(self, raw: str, url: str) -> list[dict]:
        """Parse GraphQL introspection response and flag sensitive types."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        schema = data.get("data", {}).get("__schema")
        if not schema:
            return []

        types = schema.get("types", [])
        sensitive_fields = []
        for t in types:
            for field in t.get("fields", []) or []:
                fname = field.get("name", "").lower()
                if any(s in fname for s in _SENSITIVE_TYPE_NAMES):
                    sensitive_fields.append(f"{t['name']}.{field['name']}")

        severity = "high" if sensitive_fields else "low"

        return [{
            "type": "finding",
            "title": f"GraphQL Introspection Enabled, {url}",
            "severity": severity, "category": "graphql", "host": url,
            "description": f"Full schema exposed via introspection. {len(types)} types found.",
            "sensitive_fields": sensitive_fields,
            "type_count": len(types),
        }]

    # ── IDOR testing ────────────────────────────────────────────────���

    async def _scan_idor(self, target: str, assets: list[dict]) -> list[dict]:
        """Test for IDOR by replaying requests across auth profiles."""
        if not self.auth_session or len(self.auth_session.profile_names) < 2:
            logger.debug("IDOR testing requires 2+ auth profiles, skipping")
            return []

        findings = []
        profiles = self.auth_session.profile_names
        profile_a, profile_b = profiles[0], profiles[1]

        resource_endpoints = [
            a for a in assets
            if a.get("type") == "api_endpoint" and _ID_PATTERN.search(a.get("value", ""))
        ]

        for asset in resource_endpoints:
            endpoint = asset["value"]
            url = f"{target.rstrip('/')}{endpoint}" if not endpoint.startswith("http") else endpoint
            methods = asset.get("methods", ["GET"])

            for method in methods:
                if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                    continue
                result = await self.auth_session.compare_profiles(
                    method=method, url=url,
                    profile_a=profile_a, profile_b=profile_b,
                )
                diff = result.get("diff", {})
                if diff.get("possible_idor"):
                    write = method in ("POST", "PUT", "PATCH", "DELETE")
                    findings.append({
                        "type": "finding",
                        "title": f"IDOR, {method} {endpoint}",
                        # Unauthorized modification outranks unauthorized read.
                        "severity": "critical" if write else "high",
                        "category": "idor", "host": url,
                        "matched_at": url,
                        "description": (
                            f"Profile '{profile_b}' received the same successful "
                            f"{diff.get('status_b')} response as resource owner '{profile_a}' "
                            f"for {method} {url} ({diff.get('length_b')} bytes), indicating "
                            f"access to another user's resource."
                        ),
                        "extracted_results": (
                            f"status_b={diff.get('status_b')} body_len={diff.get('length_b')} "
                            f"same_body={diff.get('same_body')}"
                        ),
                        "profile_a": profile_a,
                        "profile_b": profile_b,
                    })

        return findings

    # ── Auth bypass testing ──────────────────────────────────────────

    async def _scan_auth_bypass(self, target: str, assets: list[dict]) -> list[dict]:
        """Test endpoints without auth to check for missing authentication."""
        if not self.auth_session:
            logger.debug("Auth bypass testing requires auth_session, skipping")
            return []

        import httpx
        findings = []
        unauth_client = httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True)
        profile = self.auth_session.profile_names[0]

        try:
            for asset in assets:
                endpoint = asset.get("value", "")
                url = f"{target.rstrip('/')}{endpoint}" if not endpoint.startswith("http") else endpoint
                methods = asset.get("methods", ["GET"])

                for method in methods:
                    if method not in ("GET", "POST"):
                        continue

                    try:
                        async with await self.auth_session.create_client(profile) as auth_client:
                            auth_resp = await auth_client.request(method, url)
                    except Exception:
                        continue

                    try:
                        unauth_resp = await unauth_client.request(method, url)
                    except Exception:
                        continue

                    if (unauth_resp.status_code == auth_resp.status_code
                            and unauth_resp.status_code == 200
                            and len(unauth_resp.content) > 50):
                        findings.append({
                            "type": "finding",
                            "title": f"Authentication Bypass, {method} {endpoint}",
                            "severity": "high", "category": "auth_bypass", "host": url,
                            "description": (
                                f"Endpoint returns data ({len(unauth_resp.content)} bytes) without authentication. "
                                f"Authenticated and unauthenticated responses are identical (status {unauth_resp.status_code})."
                            ),
                        })
        finally:
            await unauth_client.aclose()

        return findings

    # ── OpenAPI parsing ──────────────────────────────────────────────

    def _parse_openapi_spec(self, raw: str) -> list[dict] | None:
        """Parse OpenAPI/Swagger JSON into structured endpoint assets."""
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None

        if not (data.get("openapi") or data.get("swagger") or data.get("paths")):
            return None

        endpoints = []
        for path, methods in data.get("paths", {}).items():
            if not isinstance(methods, dict):
                continue
            method_list = [m.upper() for m in methods if m.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")]
            endpoints.append({
                "type": "api_endpoint", "value": path,
                "methods": method_list, "parameters": self._openapi_params(methods),
                "source": "openapi",
            })

        return endpoints if endpoints else None

    @staticmethod
    def _openapi_params(path_item: dict) -> list[str]:
        """Collect every input name for a path: path/query parameters (path- and
        operation-level) AND OpenAPI 3 requestBody body properties. The old code
        only read operation-level `parameters`, missing body params entirely, which
        left most modern (OpenAPI 3) API inputs untested."""
        params: list[str] = []

        def add(name: str) -> None:
            if name and name not in params:
                params.append(name)

        # Path-level parameters shared across methods.
        if isinstance(path_item.get("parameters"), list):
            for p in path_item["parameters"]:
                if isinstance(p, dict):
                    add(p.get("name", ""))

        for detail in path_item.values():
            if not isinstance(detail, dict):
                continue
            for p in detail.get("parameters", []) or []:
                if isinstance(p, dict):
                    add(p.get("name", ""))
            body = detail.get("requestBody")
            if isinstance(body, dict):
                for content in (body.get("content") or {}).values():
                    if isinstance(content, dict):
                        for prop in ((content.get("schema") or {}).get("properties") or {}):
                            add(prop)

        return params

    # ── Output parsing ───────────────────────────────────────────────

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        if tool == "endpoints":
            return self._parse_endpoints(raw_output)
        elif tool == "nuclei":
            return self._parse_nuclei(raw_output)
        return super().parse_output(tool, raw_output)

    def _parse_endpoints(self, output: str) -> list[dict]:
        return [{"type": "api_endpoint", "value": l.strip()} for l in output.strip().splitlines() if l.strip()]

    def _parse_nuclei(self, output: str) -> list[dict]:
        findings = []
        for line in output.strip().splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            findings.append({
                "type": "finding", "title": info.get("name", "Unknown"),
                "severity": SEVERITY_MAP.get(info.get("severity", ""), "info"),
                "category": "api", "template_id": item.get("template-id", ""),
                "matched_at": item.get("matched-at", ""),
            })
        return findings
