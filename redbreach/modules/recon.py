import json
import logging
from urllib.parse import urlparse

import httpx

from redbreach.modules.base import ModuleBase

logger = logging.getLogger("redbreach.recon")


class ReconModule(ModuleBase):
    """Shared reconnaissance module, Phase 1 (intelligence) and Phase 2 (discovery).

    Wraps: subfinder, httpx, crt.sh, waybackurls, whois, theHarvester
    """

    name = "recon"
    tools_required = ["subfinder", "httpx", "whois", "curl"]
    tools_optional = ["waybackurls", "dnsx", "wafw00f"]

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 2: Discover subdomains and assets for the target domain."""
        target = engagement["target"]
        discovered = []
        seen = set()

        # Subfinder, subdomain enumeration
        result = await self.run_tool(
            ["subfinder", "-d", target, "-silent"], timeout=120
        )
        if result.returncode == 0:
            for asset in self.parse_output("subfinder", result.stdout):
                if asset["value"] not in seen:
                    seen.add(asset["value"])
                    discovered.append(asset)

        # crt.sh, Certificate Transparency
        try:
            crtsh_assets = await self._query_crtsh(target)
            for asset in crtsh_assets:
                if asset["value"] not in seen:
                    seen.add(asset["value"])
                    discovered.append(asset)
        except Exception as e:
            logger.warning("crt.sh query failed: %s", e)

        # Waybackurls, historical URL discovery
        result = await self.run_tool(
            ["waybackurls", target], timeout=120
        )
        if result.returncode == 0:
            for asset in self.parse_output("waybackurls", result.stdout):
                if asset["value"] not in seen:
                    seen.add(asset["value"])
                    discovered.append(asset)

        # dnsx, DNS resolution and record enrichment
        domains_for_dns = [a["value"] for a in discovered if a.get("type") == "domain"]
        if domains_for_dns:
            dns_results = await self._resolve_dns(domains_for_dns)
            for asset in dns_results:
                if asset["value"] not in seen:
                    seen.add(asset["value"])
                    discovered.append(asset)

        # wafw00f, WAF detection on live domains
        sample_domains = domains_for_dns[:20]  # limit to avoid hammering
        for domain in sample_domains:
            waf_info = await self._detect_waf(domain)
            if waf_info:
                # Annotate existing domain asset with WAF info
                for asset in discovered:
                    if asset["value"] == domain:
                        asset["waf"] = waf_info
                        break

        logger.info("Recon discovered %d unique assets for %s", len(discovered), target)
        return discovered

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 3: Validate live hosts with httpx. (Stub, expanded in Phase B.)"""
        return assets

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        """Phase 4: Not implemented in Phase A MVP."""
        return []

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        """Phase 5: Not implemented in Phase A MVP."""
        return []

    async def _query_crtsh(self, domain: str) -> list[dict]:
        """Query crt.sh Certificate Transparency logs."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%25.{domain}&output=json"
            )
            resp.raise_for_status()
            return self.parse_output("crtsh", resp.text)

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        """Parse tool output into structured asset dicts."""
        if tool == "subfinder":
            return self._parse_domain_list(raw_output)
        elif tool == "httpx":
            return self._parse_httpx_jsonl(raw_output)
        elif tool == "crtsh":
            return self._parse_crtsh_json(raw_output)
        elif tool == "waybackurls":
            return self._parse_url_list(raw_output)
        else:
            return super().parse_output(tool, raw_output)

    def _parse_domain_list(self, raw: str) -> list[dict]:
        """Parse newline-separated domain list (subfinder, amass, etc.)."""
        domains = []
        for line in raw.strip().split("\n"):
            domain = line.strip().lower()
            if domain and not domain.startswith("*"):
                domains.append({"type": "domain", "value": domain})
        return domains

    def _parse_httpx_jsonl(self, raw: str) -> list[dict]:
        """Parse httpx JSON-lines output."""
        results = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                value = data.get("input", "")
                if not value and data.get("url"):
                    value = urlparse(data["url"]).hostname or ""
                results.append({
                    "type": "domain",
                    "value": value,
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                })
            except json.JSONDecodeError:
                logger.warning("Failed to parse httpx line: %s", line[:100])
        return results

    def _parse_crtsh_json(self, raw: str) -> list[dict]:
        """Parse crt.sh JSON response."""
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError:
            return []

        seen = set()
        domains = []
        for entry in entries:
            # crt.sh packs several newline-separated SANs into one name_value;
            # splitting them recovers subdomains that were previously merged into
            # a single malformed asset.
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and name not in seen:
                    seen.add(name)
                    domains.append({"type": "domain", "value": name})
        return domains

    def _parse_url_list(self, raw: str) -> list[dict]:
        """Parse newline-separated URL list (waybackurls, gau, etc.)."""
        urls = []
        for line in raw.strip().split("\n"):
            url = line.strip()
            if url and url.startswith("http"):
                urls.append({"type": "url", "value": url})
        return urls

    async def _resolve_dns(self, domains: list[str]) -> list[dict]:
        """Use dnsx to resolve domains and discover additional hosts."""
        import os
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(domains))
            domain_file = f.name

        try:
            result = await self.run_tool(
                ["dnsx", "-l", domain_file, "-resp", "-a", "-cname", "-silent"],
                timeout=120,
            )
        finally:
            # Always remove the temp domain list, it used to leak one file per cycle.
            try:
                os.unlink(domain_file)
            except OSError:
                pass

        if result.returncode == 127:
            logger.debug("dnsx not installed, skipping DNS enrichment")
            return []

        hosts = []
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                parts = line.split()
                hosts.append({
                    "type": "host",
                    "value": parts[0],
                    "dns_records": parts[1:] if len(parts) > 1 else [],
                })
        return hosts

    async def _detect_waf(self, domain: str) -> str | None:
        """Use wafw00f to detect WAF on a domain."""
        result = await self.run_tool(
            ["wafw00f", f"https://{domain}", "-o", "-"],
            timeout=30,
        )
        if result.returncode == 127:
            logger.debug("wafw00f not installed, skipping WAF detection")
            return None

        output = result.stdout + result.stderr
        # wafw00f outputs "is behind X" or "No WAF detected"
        if "is behind" in output:
            for line in output.split("\n"):
                if "is behind" in line:
                    return line.strip()
        return None
