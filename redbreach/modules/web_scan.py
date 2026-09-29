import asyncio
import hashlib
import json
import logging
import tempfile

import os

from redbreach.modules.base import ModuleBase

# Distinctive attacker-controlled Origin used to detect CORS reflection.
_CORS_TEST_ORIGIN = "https://evil-redbreach-probe.example"

# Directory-fuzzing wordlists, tried in order. The first that exists is used; if
# none do, ffuf fuzzing is skipped with a warning instead of silently failing
# (the old code hardcoded only the seclists path).
_FFUF_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
]


def _find_ffuf_wordlist() -> str | None:
    for path in _FFUF_WORDLISTS:
        if os.path.exists(path):
            return path
    return None

# SSTI: a distinctive product unlikely to appear naturally in a page. If the
# response contains the computed value, the template expression was evaluated.
_SSTI_A, _SSTI_B = 7331, 1907
_SSTI_EXPECTED = str(_SSTI_A * _SSTI_B)


def _ssti_payloads() -> list[tuple[str, str]]:
    expr = f"{_SSTI_A}*{_SSTI_B}"
    return [
        ("jinja2/twig", "{{" + expr + "}}"),
        ("freemarker/jsp/spring", "${" + expr + "}"),
        ("ruby/thymeleaf", "#{" + expr + "}"),
        ("erb", "<%= " + expr + " %>"),
    ]

logger = logging.getLogger("redbreach.web_scan")

SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}

SQLI_SEVERITY = {
    1: "medium",   # boolean-based blind
    2: "high",     # error-based
    3: "high",     # UNION query
    4: "medium",   # stacked queries (time-based)
    5: "critical", # stacked queries (execution)
}

_REDIRECT_PARAMS = [
    "next", "url", "return", "returnTo", "return_to", "redirect", "redirect_url",
    "redirect_uri", "dest", "destination", "continue", "r", "u", "target", "link", "goto",
]

_OAUTH_AUTHORIZE_HINTS = ("/authorize", "/oauth/authorize", "/oauth2/authorize", "/connect/authorize")

_REDIRECT_PAYLOADS = [
    "https://{host}/",
    "//{host}/",
    "https:{host}/",
    "/\\{host}/",
    "//{host}/@target.com",
    "https://target.com.{host}/",
    "https://target.com@{host}/",
]

_ATTACKER_HOST = "evil.redbreach-test"

_TESTSSL_SEVERITY_MAP = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "info",
    "INFO": "info",
}

_REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "Content-Security-Policy",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer-Policy",
}

_SCAN_SUGGESTIONS = {
    "xss": [
        "Test for stored XSS variant on the same parameter",
        "Test for DOM-based XSS via JavaScript sink analysis",
        "Check if CSP headers prevent exploitation",
    ],
    "sqli": [
        "Attempt time-based extraction to enumerate database schema",
        "Test for second-order SQL injection via stored inputs",
        "Check for WAF bypass using encoding techniques",
    ],
    "rce": [
        "Attempt to escalate from RCE to reverse shell",
        "Check if other endpoints share the same vulnerable component",
    ],
    "admin_panel": [
        "Test admin panel for default credentials",
        "Test for authentication bypass via direct URL access",
        "Check for privilege escalation from low-privilege user",
    ],
    "sensitive_file": [
        "Check for additional backup/config files (.bak, .old, .swp)",
        "Verify if exposed file contains credentials or API keys",
    ],
}


class WebScanModule(ModuleBase):
    """Web scanning module, Phase 4. Nuclei templates + ffuf fuzzing."""

    name = "web_scan"
    tools_required = ["nuclei", "ffuf"]
    tools_optional = ["nikto", "sqlmap"]

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return []

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return assets

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        urls = []
        for asset in assets:
            url = asset.get("url")
            if url:
                urls.append(url)
            elif asset.get("type") == "domain":
                urls.append(f"https://{asset['value']}")

        if not urls:
            return []

        nuclei_findings = await self._run_nuclei(urls)
        nikto_findings = await self._run_nikto(urls[:10])
        ffuf_findings = await self._run_ffuf(urls[:20])

        # Gated sqlmap + SSRF: only if assets contain discovered parameters from arjun
        sqlmap_findings = []
        ssrf_findings = []
        ssti_findings = []
        param_assets = [a for a in assets if a.get("type") == "parameters"]
        if param_assets:
            sqlmap_findings = await self._run_sqlmap(param_assets)
            ssrf_findings = await self._scan_ssrf(param_assets)
            ssti_findings = await self._scan_ssti(param_assets)

        redirect_findings = await self._scan_redirects(urls[:30])
        tls_header_findings = await self._audit_tls_and_headers(urls[:20])
        cors_findings = await self._scan_cors(urls[:20])

        all_findings = (
            nuclei_findings + nikto_findings + ffuf_findings
            + sqlmap_findings + ssrf_findings + ssti_findings + redirect_findings
            + tls_header_findings + cors_findings
        )
        logger.info(
            "Scan found %d findings (%d nuclei, %d nikto, %d ffuf, %d sqlmap, %d ssrf, "
            "%d ssti, %d redirect, %d tls/headers, %d cors)",
            len(all_findings), len(nuclei_findings), len(nikto_findings),
            len(ffuf_findings), len(sqlmap_findings), len(ssrf_findings),
            len(ssti_findings), len(redirect_findings), len(tls_header_findings), len(cors_findings),
        )
        return all_findings

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        """Generate context-aware manual test suggestions based on scan findings."""
        suggestions = []
        seen_categories = set()

        for finding in findings:
            category = finding.get("category", "")
            title = finding.get("title", "").lower()

            # Detect admin panels from ffuf results
            if finding.get("type") == "url" and "/admin" in finding.get("value", ""):
                if "admin_panel" not in seen_categories:
                    seen_categories.add("admin_panel")
                    for desc in _SCAN_SUGGESTIONS["admin_panel"]:
                        suggestions.append({
                            "type": "suggested_test", "category": "admin_panel",
                            "description": desc, "context": finding.get("value", ""),
                        })

            # Detect sensitive files from ffuf
            if finding.get("type") == "url":
                val = finding.get("value", "")
                if any(ext in val for ext in [".env", ".bak", ".sql", ".conf", ".log"]):
                    if "sensitive_file" not in seen_categories:
                        seen_categories.add("sensitive_file")
                        for desc in _SCAN_SUGGESTIONS["sensitive_file"]:
                            suggestions.append({
                                "type": "suggested_test", "category": "sensitive_file",
                                "description": desc, "context": val,
                            })

            # Category-based suggestions from scanner findings
            if category and category not in seen_categories:
                cat_key = category if category in _SCAN_SUGGESTIONS else None
                if cat_key is None:
                    for key in _SCAN_SUGGESTIONS:
                        if key in title:
                            cat_key = key
                            break
                if cat_key:
                    seen_categories.add(category)
                    for desc in _SCAN_SUGGESTIONS[cat_key]:
                        suggestions.append({
                            "type": "suggested_test", "category": category,
                            "description": desc,
                            "context": finding.get("matched_at") or finding.get("host", ""),
                        })

        return suggestions

    async def _run_nuclei(self, urls: list[str]) -> list[dict]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            url_file = f.name

        result = await self.run_tool(
            ["nuclei", "-l", url_file, "-jsonl", "-silent", "-nc"],
            timeout=600,
        )

        if result.returncode == 127:
            logger.error("nuclei not installed")
            return []

        return self.parse_output("nuclei", result.stdout)

    async def _run_nikto(self, urls: list[str]) -> list[dict]:
        """Run nikto against target URLs for server-level vulns."""
        all_findings = []
        for url in urls:
            result = await self.run_tool(
                ["nikto", "-h", url, "-Format", "json", "-output", "-", "-Tuning", "x6"],
                timeout=300,
            )
            if result.returncode == 127:
                logger.debug("nikto not installed, skipping")
                return []
            findings = self._parse_nikto_output(result.stdout)
            all_findings.extend(findings)
        return all_findings

    def _parse_nikto_output(self, raw: str) -> list[dict]:
        """Parse nikto JSON output."""
        findings = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            # nikto output can be messy, try line-by-line
            for line in raw.strip().split("\n"):
                line = line.strip()
                if line.startswith("+") and "OSVDB" in line:
                    findings.append({
                        "type": "finding",
                        "title": line.lstrip("+ "),
                        "severity": "info",
                        "category": "nikto",
                        "template_id": "nikto-finding",
                    })
            return findings

        if isinstance(data, dict):
            for vuln in data.get("vulnerabilities", []):
                findings.append({
                    "type": "finding",
                    "title": vuln.get("msg", "Unknown"),
                    "severity": "low" if vuln.get("OSVDB", "0") != "0" else "info",
                    "category": "nikto",
                    "template_id": f"nikto-{vuln.get('id', 'unknown')}",
                    "host": vuln.get("url", ""),
                    "osvdb": vuln.get("OSVDB", ""),
                })
        return findings

    async def _run_ffuf(self, urls: list[str]) -> list[dict]:
        """Run ffuf directory fuzzing on target URLs."""
        wordlist = _find_ffuf_wordlist()
        if not wordlist:
            logger.warning("No directory wordlist found (install seclists); skipping ffuf fuzzing")
            return []

        all_findings = []
        for url in urls:
            result = await self.run_tool(
                [
                    "ffuf", "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", wordlist,
                    "-ac", "-mc", "all", "-of", "json", "-o", "/dev/stdout", "-s",
                ],
                timeout=300,
            )
            if result.returncode == 127:
                logger.debug("ffuf not installed, skipping directory fuzzing")
                return []
            findings = self._parse_ffuf_json(result.stdout)
            all_findings.extend(findings)
        return all_findings

    async def _run_sqlmap(self, param_assets: list[dict]) -> list[dict]:
        """Run sqlmap on endpoints with discovered parameters. Gated, only called when params exist."""
        all_findings = []
        for asset in param_assets:
            url = asset.get("value", "")
            params = asset.get("params", [])
            if not url or not params:
                continue

            param_str = "&".join(f"{p}=1" for p in params)
            target_url = f"{url}?{param_str}" if "?" not in url else url

            result = await self.run_tool(
                [
                    "sqlmap", "-u", target_url,
                    "--batch", "--level", "2", "--risk", "1",
                    "--output-dir", "/tmp/redbreach-sqlmap",
                ],
                timeout=180,
            )
            if result.returncode == 127:
                logger.debug("sqlmap not installed, skipping SQL injection testing")
                return []
            findings = self._parse_sqlmap_output(result.stdout)
            all_findings.extend(findings)
        return all_findings

    def _parse_sqlmap_output(self, raw: str) -> list[dict]:
        """Parse sqlmap output for injection findings."""
        findings = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            if "is vulnerable" in raw or "injectable" in raw.lower():
                findings.append({
                    "type": "finding", "title": "SQL Injection Detected (sqlmap)",
                    "severity": "high", "category": "sqli", "template_id": "sqlmap-detected",
                })
            return findings

        for entry in data.get("data", []):
            sqli_type = entry.get("type", 0)
            for vuln in entry.get("value", []):
                findings.append({
                    "type": "finding",
                    "title": f"SQL Injection, {vuln.get('title', 'Unknown')}",
                    "severity": SQLI_SEVERITY.get(sqli_type, "high"),
                    "category": "sqli",
                    "template_id": f"sqlmap-type-{sqli_type}",
                    "host": data.get("url", ""),
                    "parameter": vuln.get("parameter", ""),
                    "dbms": vuln.get("dbms", ""),
                    "payload": vuln.get("payload", ""),
                })
        return findings

    async def _start_interactsh(self) -> str | None:
        """Start interactsh-client subprocess and return its callback domain.
        Returns None if the tool is not installed."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "interactsh-client", "-json", "-o", "/tmp/redbreach-interactsh.log",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            logger.warning("interactsh-client not installed, skipping SSRF scan")
            return None

        self._interactsh_proc = proc

        def _safe_kill():
            try:
                proc.kill()
            except (ProcessLookupError, AttributeError):
                pass

        try:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=10)
        except asyncio.TimeoutError:
            _safe_kill()
            return None
        domain = line.decode().strip()
        # interactsh-client prints a banner before the domain on its first line; the
        # first usable line we want is the one ending in the OAST domain. Read up to
        # 30 lines looking for one that looks like a hostname.
        attempts = 0
        while attempts < 30 and (not domain or "." not in domain or " " in domain):
            try:
                next_line = await asyncio.wait_for(proc.stdout.readline(), timeout=5)
            except asyncio.TimeoutError:
                break
            if not next_line:
                break
            domain = next_line.decode().strip()
            attempts += 1
        if not domain or "." not in domain or " " in domain:
            _safe_kill()
            return None
        return domain

    async def _poll_interactsh(self, domain: str, timeout: int = 60) -> list[dict]:
        """Poll the interactsh-client log file for callbacks. Returns parsed records."""
        log_path = "/tmp/redbreach-interactsh.log"
        deadline = asyncio.get_event_loop().time() + timeout
        callbacks: list[dict] = []
        seen_ids: set[str] = set()
        while asyncio.get_event_loop().time() < deadline:
            try:
                with open(log_path) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        rid = record.get("unique-id", "") + record.get("timestamp", "")
                        if rid and rid not in seen_ids:
                            seen_ids.add(rid)
                            callbacks.append(record)
            except FileNotFoundError:
                pass
            await asyncio.sleep(2)
        return callbacks

    async def _stop_interactsh(self) -> None:
        proc = getattr(self, "_interactsh_proc", None)
        if proc is not None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            self._interactsh_proc = None

    async def _scan_ssrf(self, param_assets: list[dict]) -> list[dict]:
        """Test endpoints with discovered parameters for SSRF using interactsh OAST callbacks."""
        if not param_assets:
            return []

        callback_domain = await self._start_interactsh()
        if not callback_domain:
            return []

        findings: list[dict] = []
        try:
            fired: list[tuple[str, str, str]] = []  # (target_url, param, payload)

            for asset in param_assets:
                base_url = asset.get("value", "")
                params = asset.get("params", [])
                if not base_url or not params:
                    continue
                for param in params:
                    token = f"{abs(hash((base_url, param))) & 0xFFFFFFFF:x}"
                    payload = f"http://{token}.{callback_domain}/probe"
                    target = f"{base_url}{'&' if '?' in base_url else '?'}{param}={payload}"
                    result = await self.run_tool(
                        ["curl", "-s", "-o", "/dev/null", "-m", "15", target],
                        timeout=20,
                    )
                    if result.returncode == 127:
                        logger.debug("curl missing, aborting SSRF scan")
                        return []
                    fired.append((base_url, param, payload))

            callbacks = await self._poll_interactsh(callback_domain, timeout=60)

            for cb in callbacks:
                raw_req = cb.get("raw-request", "")
                full_id = cb.get("full-id", "")
                for base_url, param, payload in fired:
                    token = payload.split("//")[1].split(".")[0]
                    if token in raw_req or token in full_id:
                        findings.append({
                            "type": "finding",
                            "title": f"SSRF, {param} on {base_url}",
                            "severity": "high",
                            "category": "ssrf",
                            "host": base_url,
                            "matched_at": base_url,
                            "parameter": param,
                            "template_id": "redbreach-ssrf",
                            "description": (
                                f"Out-of-band callback received from injected URL in '{param}'. "
                                f"Protocol: {cb.get('protocol', 'unknown')}, "
                                f"Source IP: {cb.get('remote-address', 'unknown')}."
                            ),
                            "evidence": cb.get("raw-request", "")[:500],
                        })
                        break
        finally:
            await self._stop_interactsh()

        return findings

    async def _scan_ssti(self, param_assets: list[dict]) -> list[dict]:
        """Test discovered parameters for server-side template injection.

        Injects a distinctive arithmetic template; if the computed product appears
        in the response (and the literal payload does not), the template evaluated.
        """
        if not param_assets:
            return []
        from urllib.parse import quote

        findings: list[dict] = []
        for asset in param_assets:
            base_url = asset.get("value", "")
            params = asset.get("params", [])
            if not base_url or not params:
                continue
            for param in params:
                for engine, payload in _ssti_payloads():
                    target = f"{base_url}{'&' if '?' in base_url else '?'}{param}={quote(payload)}"
                    result = await self.run_tool(["curl", "-s", "-m", "15", target], timeout=20)
                    if result.returncode == 127:
                        logger.debug("curl missing, aborting SSTI scan")
                        return findings
                    finding = self._classify_ssti(result.stdout, engine, payload, base_url, param)
                    if finding:
                        findings.append(finding)
                        break  # one confirmed engine per parameter is enough
        return findings

    def _classify_ssti(self, response_text: str, engine: str, payload: str,
                       base_url: str = "", param: str = "") -> dict | None:
        """Pure: did the injected template expression evaluate server-side?"""
        text = response_text or ""
        # Evaluated product present AND the literal payload not merely reflected.
        if _SSTI_EXPECTED in text and payload not in text:
            where = f", {param} on {base_url}" if base_url else ""
            return {
                "type": "finding",
                "title": f"Server-Side Template Injection{where}",
                "severity": "high",
                "category": "ssti",
                "host": base_url,
                "matched_at": base_url,
                "parameter": param,
                "template_id": "redbreach-ssti",
                "description": (
                    f"Injected template expression evaluated server-side ({engine}): the payload "
                    f"computed to {_SSTI_EXPECTED} in the response, indicating template injection "
                    "that can frequently be escalated to remote code execution."
                ),
                "extracted_results": f"engine={engine} payload={payload} evaluated={_SSTI_EXPECTED}",
            }
        return None

    def _build_redirect_payloads(self) -> list[str]:
        return [tpl.format(host=_ATTACKER_HOST) for tpl in _REDIRECT_PAYLOADS]

    def _is_redirect_to_attacker(self, response) -> bool:
        if response.status_code not in (301, 302, 303, 307, 308):
            return False
        location = response.headers.get("Location", "") or response.headers.get("location", "")
        return _ATTACKER_HOST in location

    async def _scan_redirects(self, urls: list[str]) -> list[dict]:
        """Test URLs for open redirect and OAuth redirect_uri bypass."""
        if not urls:
            return []

        import httpx
        from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

        findings: list[dict] = []
        payloads = self._build_redirect_payloads()
        client = httpx.AsyncClient(verify=False, timeout=15, follow_redirects=False)

        try:
            for url in urls:
                parsed = urlparse(url)
                existing_params = dict(parse_qsl(parsed.query))
                is_oauth = any(hint in parsed.path.lower() for hint in _OAUTH_AUTHORIZE_HINTS)

                params_to_test = ["redirect_uri"] if is_oauth else _REDIRECT_PARAMS

                for param in params_to_test:
                    found_for_param = False
                    for payload in payloads:
                        test_params = dict(existing_params)
                        test_params[param] = payload
                        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                        try:
                            resp = await client.request("GET", test_url)
                        except Exception as e:
                            logger.debug("redirect probe failed for %s: %s", test_url, e)
                            continue

                        if self._is_redirect_to_attacker(resp):
                            category = "oauth_redirect_uri" if is_oauth else "open_redirect"
                            severity = "high" if is_oauth else "medium"
                            title = (
                                f"OAuth redirect_uri bypass, {url}" if is_oauth
                                else f"Open Redirect, {param} on {url}"
                            )
                            findings.append({
                                "type": "finding",
                                "title": title,
                                "severity": severity,
                                "category": category,
                                "host": url,
                                "matched_at": test_url,
                                "parameter": param,
                                "template_id": f"redbreach-{category}",
                                "description": (
                                    f"Server returned {resp.status_code} redirect to attacker-controlled host "
                                    f"({_ATTACKER_HOST}) when injecting payload '{payload}' into '{param}'."
                                ),
                                "evidence": resp.headers.get("Location", ""),
                            })
                            found_for_param = True
                            break
                    if found_for_param:
                        continue
        finally:
            await client.aclose()

        return findings

    def _read_testssl_json(self, path: str) -> list[dict]:
        """Read testssl.sh JSON output file. Returns list of finding records."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("scanResult", []) or data.get("findings", [])
        return []

    async def _audit_tls(self, hosts: list[str]) -> list[dict]:
        """Run testssl.sh per host and parse findings."""
        if not hosts:
            return []

        findings: list[dict] = []
        for host in hosts:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                json_path = f.name

            result = await self.run_tool(
                ["testssl.sh", "--jsonfile-pretty", json_path, "--quiet", "--color", "0",
                 f"{host}:443"],
                timeout=300,
            )
            if result.returncode == 127:
                logger.debug("testssl.sh not installed, skipping TLS audit")
                return []

            records = self._read_testssl_json(json_path)
            for rec in records:
                sev_raw = (rec.get("severity") or "").upper()
                if sev_raw == "OK":
                    continue
                mapped = _TESTSSL_SEVERITY_MAP.get(sev_raw)
                if mapped is None:
                    continue
                findings.append({
                    "type": "finding",
                    "title": rec.get("id", "tls-finding"),
                    "severity": mapped,
                    "category": "tls",
                    "host": host,
                    "template_id": f"testssl-{rec.get('id', 'unknown')}",
                    "description": rec.get("finding", ""),
                })
        return findings

    async def _audit_headers(self, urls: list[str]) -> list[dict]:
        """Fetch each URL and inspect security headers + cookie flags."""
        if not urls:
            return []

        import httpx

        findings: list[dict] = []
        client = httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True)
        try:
            for url in urls:
                try:
                    resp = await client.request("GET", url)
                except Exception as e:
                    logger.debug("header probe failed for %s: %s", url, e)
                    continue

                headers = {k.lower(): v for k, v in resp.headers.items()}

                for header_name, label in _REQUIRED_SECURITY_HEADERS.items():
                    if header_name.lower() not in headers:
                        findings.append({
                            "type": "finding",
                            "title": f"Missing {label} header",
                            "severity": "info",
                            "category": "headers",
                            "host": url,
                            "template_id": f"missing-{label.lower()}",
                            "description": f"Response from {url} does not include the {label} header.",
                        })

                csp = headers.get("content-security-policy", "")
                if "'unsafe-inline'" in csp and "nonce-" not in csp:
                    findings.append({
                        "type": "finding",
                        "title": "CSP allows unsafe-inline without nonce",
                        "severity": "low",
                        "category": "headers",
                        "host": url,
                        "template_id": "csp-unsafe-inline",
                        "description": (
                            f"Content-Security-Policy on {url} permits 'unsafe-inline' without a nonce, "
                            "weakening XSS mitigation."
                        ),
                        "evidence": csp[:200],
                    })

                cookie_headers = []
                if hasattr(resp.headers, "get_list"):
                    cookie_headers = resp.headers.get_list("set-cookie")
                for cookie_header in cookie_headers:
                    lower = cookie_header.lower()
                    missing_flags = []
                    if "httponly" not in lower:
                        missing_flags.append("HttpOnly")
                    if "secure" not in lower:
                        missing_flags.append("Secure")
                    if "samesite" not in lower:
                        missing_flags.append("SameSite")
                    if missing_flags:
                        findings.append({
                            "type": "finding",
                            "title": f"Cookie missing flags: {', '.join(missing_flags)}",
                            "severity": "info",
                            "category": "headers",
                            "host": url,
                            "template_id": "cookie-flags",
                            "description": f"Set-Cookie header from {url} missing: {', '.join(missing_flags)}",
                            "evidence": cookie_header[:200],
                        })
        finally:
            await client.aclose()
        return findings

    async def _scan_cors(self, urls: list[str]) -> list[dict]:
        """Probe for exploitable CORS misconfigurations.

        Only credentialed cases are reported: reflecting an arbitrary Origin (or
        returning `null`) together with Access-Control-Allow-Credentials: true lets
        a malicious site read authenticated responses cross-origin. A bare
        `Access-Control-Allow-Origin: *` is intentional for public APIs, not a bug,
        and is deliberately not flagged.
        """
        if not urls:
            return []

        import httpx

        findings: list[dict] = []
        client = httpx.AsyncClient(verify=False, timeout=15, follow_redirects=True)
        try:
            for url in urls:
                try:
                    resp = await client.request("GET", url, headers={"Origin": _CORS_TEST_ORIGIN})
                except Exception as e:
                    logger.debug("CORS probe failed for %s: %s", url, e)
                    continue
                headers = {k.lower(): v for k, v in resp.headers.items()}
                finding = self._classify_cors(
                    url,
                    headers.get("access-control-allow-origin", ""),
                    headers.get("access-control-allow-credentials", "").strip().lower() == "true",
                )
                if finding:
                    findings.append(finding)
        finally:
            await client.aclose()
        return findings

    def _classify_cors(self, url: str, acao: str, allow_credentials: bool) -> dict | None:
        """Pure decision: is this ACAO/credentials combo an exploitable CORS bug?"""
        acao = (acao or "").strip()
        reflects = acao == _CORS_TEST_ORIGIN
        is_null = acao.lower() == "null"
        if allow_credentials and (reflects or is_null):
            how = "reflects an arbitrary request Origin" if reflects else "returns Access-Control-Allow-Origin: null"
            return {
                "type": "finding",
                "title": f"Exploitable CORS misconfiguration, {url}",
                "severity": "high",
                "category": "cors",
                "host": url,
                "matched_at": url,
                "template_id": "cors-credentialed-reflection",
                "description": (
                    f"{url} {how} while also setting Access-Control-Allow-Credentials: true. "
                    "A malicious origin can read authenticated responses cross-origin, "
                    "enabling credentialed data theft."
                ),
                "extracted_results": f"ACAO={acao} ACAC=true origin_sent={_CORS_TEST_ORIGIN}",
                "evidence": f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: true",
            }
        return None

    async def _crack_http_digest(self, auth_header: str, method: str, uri: str,
                                    wordlist: str | None = None) -> dict | None:
        """Crack HTTP Digest auth by testing candidate passwords against the hash.

        Works by recomputing the Digest response for each candidate and comparing
        to the captured response value. Supports MD5 (the most common algorithm).

        Args:
            auth_header: The full Authorization: Digest header value.
            method: HTTP method (GET, POST, etc.).
            uri: The request URI.
            wordlist: Optional path to a password wordlist file.

        Returns:
            A finding dict if cracked, None otherwise.
        """
        # Parse Digest fields from the header
        fields = {}
        for part in auth_header.replace("Digest ", "").split(","):
            part = part.strip()
            if "=" not in part:
                continue
            key, val = part.split("=", 1)
            fields[key.strip()] = val.strip().strip('"')

        username = fields.get("username", "")
        realm = fields.get("realm", "")
        nonce = fields.get("nonce", "")
        response_expected = fields.get("response", "")
        qop = fields.get("qop", "")
        nc = fields.get("nc", "")
        cnonce = fields.get("cnonce", "")
        algorithm = fields.get("algorithm", "MD5").upper()

        if algorithm != "MD5" or not response_expected:
            return None

        # Build candidate list: defaults + wordlist
        candidates = [
            "password", "admin", "root", "guest", "123456", "letmein",
            "L3tmein", "changeme", "default", "test", "operator",
            username, f"{username}123", f"{username}hmi",
        ]
        if wordlist:
            try:
                with open(wordlist) as f:
                    candidates.extend(line.strip() for line in f if line.strip())
            except FileNotFoundError:
                pass

        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

        for pw in candidates:
            ha1 = hashlib.md5(f"{username}:{realm}:{pw}".encode()).hexdigest()
            if qop == "auth":
                computed = hashlib.md5(
                    f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
                ).hexdigest()
            else:
                computed = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

            if computed == response_expected:
                return {
                    "type": "finding",
                    "title": f"Weak HTTP Digest credential, {username}:{pw}",
                    "severity": "high",
                    "category": "auth",
                    "template_id": "redbreach-digest-crack",
                    "description": (
                        f"HTTP Digest auth for user '{username}' on realm '{realm}' "
                        f"uses a weak password: '{pw}'. Cracked via offline MD5 hash computation."
                    ),
                    "evidence": f"username={username}, realm={realm}, password={pw}",
                }
        return None

    async def _audit_tls_and_headers(self, urls: list[str]) -> list[dict]:
        """Run TLS audit (per host) + header audit (per URL)."""
        from urllib.parse import urlparse
        hosts: list[str] = []
        seen_hosts: set[str] = set()
        for u in urls:
            host = urlparse(u).hostname
            if host and host not in seen_hosts:
                seen_hosts.add(host)
                hosts.append(host)

        tls = await self._audit_tls(hosts)
        headers = await self._audit_headers(urls)
        return tls + headers

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        if tool == "nuclei":
            return self._parse_nuclei_jsonl(raw_output)
        elif tool == "ffuf":
            return self._parse_ffuf_json(raw_output)
        else:
            return super().parse_output(tool, raw_output)

    def _parse_nuclei_jsonl(self, raw: str) -> list[dict]:
        findings = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info", {})
                findings.append({
                    "type": "finding",
                    "template_id": data.get("template-id", ""),
                    "title": info.get("name", "Unknown"),
                    "severity": SEVERITY_MAP.get(info.get("severity", "info"), "info"),
                    "tags": info.get("tags", []),
                    "host": data.get("host", ""),
                    "matched_at": data.get("matched-at", ""),
                    "ip": data.get("ip", ""),
                    "matcher_name": data.get("matcher-name", ""),
                    "extracted_results": data.get("extracted-results", []),
                    "timestamp": data.get("timestamp", ""),
                })
            except json.JSONDecodeError:
                logger.warning("Failed to parse nuclei line: %s", line[:100])
        return findings

    def _parse_ffuf_json(self, raw: str) -> list[dict]:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []

        paths = []
        for entry in data.get("results", []):
            paths.append({
                "type": "url",
                "value": entry.get("url", ""),
                "status_code": entry.get("status"),
                "length": entry.get("length"),
                "content_type": entry.get("content-type", ""),
                "input": entry.get("input", {}),
            })
        return paths
