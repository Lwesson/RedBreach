"""Subdomain takeover module, detects dangling DNS records pointing at takeoverable services."""

import json
import logging
import tempfile

from redbreach.modules.base import ModuleBase

logger = logging.getLogger("redbreach.modules.takeover")


class TakeoverModule(ModuleBase):
    name = "takeover"
    tools_required = ["nuclei", "subzy"]

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        import os

        subdomains = [a["value"] for a in assets if a.get("type") == "domain" and a.get("value")]
        if not subdomains:
            return []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(subdomains))
            sub_file = f.name
        subzy_out = sub_file + ".subzy.json"

        merged: dict[str, dict] = {}
        try:
            nuclei_result = await self.run_tool(
                ["nuclei", "-l", sub_file, "-t", "http/takeovers/", "-jsonl", "-silent", "-nc"],
                timeout=600,
            )
            if nuclei_result.returncode == 127:
                logger.debug("nuclei not installed, skipping nuclei takeover scan")
            else:
                for finding in self._parse_nuclei_takeovers(nuclei_result.stdout):
                    merged[finding["host"]] = finding

            # subzy --output is a FILENAME (it writes JSON there, not to stdout).
            subzy_result = await self.run_tool(
                ["subzy", "run", "--targets", sub_file, "--output", subzy_out, "--vuln", "--hide_fails"],
                timeout=600,
            )
            if subzy_result.returncode == 127:
                logger.debug("subzy not installed, skipping subzy scan")
            elif os.path.exists(subzy_out):
                try:
                    subzy_json = open(subzy_out, encoding="utf-8").read()
                except OSError:
                    subzy_json = ""
                for finding in self._parse_subzy_output(subzy_json):
                    host = finding["host"]
                    if host in merged:
                        existing_sources = set(merged[host].get("sources", []))
                        existing_sources.update(finding.get("sources", []))
                        merged[host]["sources"] = sorted(existing_sources)
                    else:
                        merged[host] = finding
        finally:
            for path in (sub_file, subzy_out):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        logger.info("Takeover scan found %d candidates", len(merged))
        return list(merged.values())

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return []

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return []

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        return []

    def _parse_nuclei_takeovers(self, raw: str) -> list[dict]:
        findings = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = data.get("host") or data.get("matched-at", "")
            if not host:
                continue
            info = data.get("info", {})
            findings.append({
                "type": "finding",
                "title": f"Subdomain Takeover, {info.get('name', 'Unknown')} ({host})",
                "severity": "high",
                "category": "subdomain_takeover",
                "host": host,
                "template_id": data.get("template-id", ""),
                "description": info.get("description", info.get("name", "")),
                "sources": ["nuclei"],
            })
        return findings

    def _parse_subzy_output(self, raw: str) -> list[dict]:
        findings = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings
        if not isinstance(data, list):
            return findings
        for entry in data:
            status = (entry.get("status") or "").upper()
            if status not in ("VULNERABLE", "HTTP_ERROR_VULNERABLE"):
                continue
            host = entry.get("subdomain") or entry.get("host", "")
            if not host:
                continue
            findings.append({
                "type": "finding",
                "title": f"Subdomain Takeover, {entry.get('engine', 'Unknown')} ({host})",
                "severity": "high",
                "category": "subdomain_takeover",
                "host": host,
                "template_id": f"subzy-{entry.get('engine', 'unknown').lower().replace('/', '-')}",
                "description": entry.get("details", ""),
                "sources": ["subzy"],
            })
        return findings
