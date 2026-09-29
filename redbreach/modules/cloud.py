"""Cloud attack surface module, AWS, GCP, Azure recon and scanning."""

import json
import logging

from redbreach.modules.base import ModuleBase

logger = logging.getLogger("redbreach.modules.cloud")

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info",
}

_CLOUD_TESTS = {
    "cloud_storage": [
        "Check bucket ACLs for public-write",
        "Enumerate bucket objects for sensitive files",
        "Test for bucket policy misconfiguration",
    ],
    "iam": [
        "Check for overly permissive IAM roles",
        "Test for privilege escalation paths",
        "Verify MFA enforcement",
    ],
    "default": [
        "Review cloud security group rules",
        "Check for exposed metadata endpoints",
        "Test for SSRF to cloud metadata (169.254.169.254)",
    ],
}


class CloudModule(ModuleBase):
    name = "cloud"
    tools_required = ["aws", "gcloud", "s3scanner"]

    async def recon(self, engagement: dict, assets: list[dict]) -> list[dict]:
        target = engagement.get("target", "")
        logger.info("Cloud recon for %s", target)
        # s3scanner uses single-dash Go-style flags; the flag is -bucket (not
        # --bucket-name), and -json makes the output parseable.
        result = await self.run_tool(["s3scanner", "-bucket", target, "-json"], timeout=120)
        return self._parse_s3scanner(result.stdout)

    async def enumerate(self, engagement: dict, assets: list[dict]) -> list[dict]:
        return assets

    async def scan(self, engagement: dict, assets: list[dict]) -> list[dict]:
        if not assets:
            return []
        target = engagement.get("target", "")
        result = await self.run_tool(["cloudsploit", "--json", "--target", target], timeout=300)
        return self._parse_cloudsploit(result.stdout)

    async def suggest_tests(self, engagement: dict, findings: list[dict]) -> list[dict]:
        suggestions = []
        seen = set()
        for f in findings:
            cat = f.get("category", "default")
            if cat not in seen:
                seen.add(cat)
                for test in _CLOUD_TESTS.get(cat, _CLOUD_TESTS["default"]):
                    suggestions.append({"type": "suggested_test", "category": cat, "description": test})
        return suggestions

    def parse_output(self, tool: str, raw_output: str) -> list[dict]:
        if tool == "s3scanner":
            return self._parse_s3scanner(raw_output)
        elif tool == "cloudsploit":
            return self._parse_cloudsploit(raw_output)
        return super().parse_output(tool, raw_output)

    def _parse_s3scanner(self, output: str) -> list[dict]:
        """Parse s3scanner -json output (one JSON log record per line).

        Defensive across schema variants (bucket as a string or an object with a
        name); non-JSON lines are skipped, so an unexpected format yields nothing
        rather than treating status text as bucket names.
        """
        assets = []
        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            bucket = data.get("bucket")
            name = bucket.get("name") if isinstance(bucket, dict) else bucket
            if not name:
                continue
            message = str(data.get("message", "")).lower()
            perms = bucket if isinstance(bucket, dict) else {}
            open_bucket = (
                "open" in message or "public" in message
                or any(("read" in k or "write" in k) and v for k, v in perms.items())
            )
            assets.append({"type": "cloud_storage", "value": name, "open": bool(open_bucket)})
        return assets

    def _parse_cloudsploit(self, output: str) -> list[dict]:
        try:
            items = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            return []
        return [{"type": "finding", "title": i.get("rule", "Unknown"),
                 "severity": SEVERITY_MAP.get(i.get("severity", ""), "info"),
                 "category": "cloud", "resource": i.get("resource", "")} for i in items]
