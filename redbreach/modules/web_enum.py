import asyncio
import json
import logging
import os
import re
import tempfile
from pathlib import Path

from redbreach.modules.base import ModuleBase
from redbreach.secrets import SECRET_PATTERNS

logger = logging.getLogger("redbreach.web_enum")

_JS_ENDPOINT_PATTERN = re.compile(
    r'''['"`](
        (?:https?:)?//[^\s'"`<>]{4,}
        |
        /[a-zA-Z0-9_\-./]{3,}
    )['"`]''',
    re.VERBOSE,
)

# Shared with mobile APK analysis; single source is redbreach/secrets.py.
# (Dropped the bare 40-char aws_secret_key pattern: it matched any base64 hash and
# was a false-positive engine, against the quality-only rule.)
_JS_SECRET_PATTERNS = SECRET_PATTERNS


class WebEnumModule(ModuleBase):
    """Web enumeration module, Phase 3."""

    name = "web_enum"
    tools_required = ["httpx", "katana"]
    tools_optional = ["arjun", "gobuster"]

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return []

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        domain_assets = [a for a in assets if a.get("type") == "domain"]
        if not domain_assets:
            logger.info("No domain assets to enumerate")
            return assets

        all_results = []

        # Step 1: httpx probe
        domains = [a["value"] for a in domain_assets]
        probed = await self._probe_hosts(domains)
        all_results.extend(probed)

        # Step 2: katana crawl on live hosts
        live_urls = [r["url"] for r in probed if r.get("status_code") and r["status_code"] < 500]
        if live_urls:
            crawled = await self._crawl_endpoints(live_urls)
            all_results.extend(crawled)

        # Step 3: arjun, hidden parameter discovery on key endpoints
        param_targets = live_urls[:10]  # limit to top endpoints
        if param_targets:
            param_results = await self._discover_params(param_targets)
            all_results.extend(param_results)

        # Step 4: JS analysis, extract endpoints + secrets from .js files
        js_urls = [
            r.get("value", "") for r in all_results
            if r.get("type") == "url" and r.get("value", "").endswith(".js")
        ]
        if js_urls:
            js_results = await self._analyze_javascript(js_urls[:50])
            all_results.extend(js_results)

        logger.info("Enumeration found %d results", len(all_results))
        return all_results

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return []

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        return []

    async def _probe_hosts(self, domains: list[str]) -> list[dict]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            domain_file = f.name

        try:
            result = await self.run_tool(
                ["httpx", "-l", domain_file, "-json", "-td", "-cdn", "-rt", "-server"],
                timeout=300,
            )
        finally:
            try:
                os.unlink(domain_file)
            except OSError:
                pass

        if result.returncode == 127:
            logger.error("httpx not installed")
            return []

        return self.parse_output("httpx", result.stdout)

    async def _crawl_endpoints(self, urls: list[str]) -> list[dict]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            url_file = f.name

        try:
            result = await self.run_tool(
                ["katana", "-list", url_file, "-d", "3", "-silent", "-nc"],
                timeout=300,
            )
        finally:
            try:
                os.unlink(url_file)
            except OSError:
                pass

        if result.returncode == 127:
            logger.error("katana not installed")
            return []

        return self.parse_output("katana", result.stdout)

    def _extract_js_endpoints(self, js_source: str) -> list[str]:
        """Extract URL/path strings from JS source. Returns deduplicated list preserving order."""
        seen: set[str] = set()
        result: list[str] = []
        for match in _JS_ENDPOINT_PATTERN.finditer(js_source):
            candidate = match.group(1).strip()
            if candidate in ("/", "//") or len(candidate) < 4:
                continue
            if candidate.startswith("//") and any(
                cdn in candidate for cdn in ("cdn.", ".googleapis.", ".cloudflare.", "fonts.")
            ):
                continue
            if candidate not in seen:
                seen.add(candidate)
                result.append(candidate)
        return result

    def _extract_js_secrets(self, js_source: str) -> list[dict]:
        """Detect secret-like strings in JS source. Returns list of {pattern, match} dicts."""
        results: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for name, pattern in _JS_SECRET_PATTERNS.items():
            for match in pattern.finditer(js_source):
                value = match.group(0)
                if name == "aws_secret_key":
                    window = js_source[max(0, match.start() - 40):match.end() + 40].lower()
                    if not any(h in window for h in ("aws", "secret", "s3")):
                        continue
                key = (name, value)
                if key in seen:
                    continue
                seen.add(key)
                results.append({"pattern": name, "match": value})
        return results

    async def _fetch_js_files(self, urls: list[str]) -> dict[str, str]:
        """Fetch JS file contents in parallel using httpx. Returns {url: content}."""
        import httpx

        results: dict[str, str] = {}
        semaphore = asyncio.Semaphore(20)

        async def fetch_one(client: httpx.AsyncClient, url: str) -> None:
            async with semaphore:
                try:
                    resp = await client.get(url, timeout=15, follow_redirects=True)
                    if resp.status_code == 200 and len(resp.content) < 5_000_000:
                        results[url] = resp.text
                except Exception as e:
                    logger.debug("Failed to fetch JS %s: %s", url, e)

        async with httpx.AsyncClient(verify=False) as client:
            await asyncio.gather(*(fetch_one(client, url) for url in urls))
        return results

    async def _analyze_javascript(self, js_urls: list[str]) -> list[dict]:
        """Fetch JS files and extract endpoints + secrets. Emits assets and findings."""
        if not js_urls:
            return []

        contents = await self._fetch_js_files(js_urls)
        if not contents:
            return []

        results: list[dict] = []
        seen_endpoints: set[str] = set()
        for url, body in contents.items():
            for endpoint in self._extract_js_endpoints(body):
                if endpoint in seen_endpoints:
                    continue
                seen_endpoints.add(endpoint)
                results.append({
                    "type": "api_endpoint",
                    "value": endpoint,
                    "source": "js_analysis",
                    "discovered_in": url,
                })
            for secret in self._extract_js_secrets(body):
                results.append({
                    "type": "finding",
                    "title": f"Secret in JS, {secret['pattern']} ({url})",
                    "severity": "high",
                    "category": "secret_in_js",
                    "host": url,
                    "template_id": f"js-secret-{secret['pattern']}",
                    "description": f"Detected {secret['pattern']} pattern in {url}",
                    "evidence": secret["match"][:80],
                })

        logger.info(
            "JS analysis: %d files → %d endpoints, %d secret findings",
            len(contents), len(seen_endpoints),
            sum(1 for r in results if r["type"] == "finding"),
        )
        return results

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        if tool == "httpx":
            return self._parse_httpx_probe(raw_output)
        elif tool == "katana":
            return self._parse_url_list(raw_output)
        else:
            return super().parse_output(tool, raw_output)

    def _parse_httpx_probe(self, raw: str) -> list[dict]:
        results = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "type": "domain",
                    "value": data.get("input", ""),
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                    "webserver": data.get("webserver", ""),
                    "cdn": data.get("cdn", False),
                    "content_type": data.get("content_type", ""),
                    "response_time": data.get("response_time", ""),
                })
            except json.JSONDecodeError:
                logger.warning("Failed to parse httpx probe line: %s", line[:100])
        return results

    def _parse_url_list(self, raw: str) -> list[dict]:
        urls = []
        for line in raw.strip().split("\n"):
            url = line.strip()
            if url and url.startswith("http"):
                urls.append({"type": "url", "value": url})
        return urls

    async def _discover_params(self, urls: list[str]) -> list[dict]:
        """Use arjun to discover hidden GET/POST parameters on endpoints."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            url_file = f.name

        try:
            result = await self.run_tool(
                ["arjun", "-i", url_file, "--stable", "-oJ", "/dev/stdout"],
                timeout=300,
            )
        finally:
            try:
                os.unlink(url_file)
            except OSError:
                pass

        if result.returncode == 127:
            logger.debug("arjun not installed, skipping parameter discovery")
            return []

        return self._parse_arjun_output(result.stdout)

    def _parse_arjun_output(self, raw: str) -> list[dict]:
        """Parse arjun JSON output into parameter assets."""
        results = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        # arjun outputs {url: [params]}
        if isinstance(data, dict):
            for url, params in data.items():
                if params:
                    param_list = params if isinstance(params, list) else [params] if not isinstance(params, (dict, set)) else list(params)
                    results.append({
                        "type": "parameters",
                        "value": url,
                        "params": param_list,
                        "param_count": len(param_list),
                    })
        return results
