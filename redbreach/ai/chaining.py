"""Vulnerability chaining engine, AI-powered attack path identification."""
import json
import logging
from dataclasses import dataclass

from redbreach.ai.client import AIClient, extract_json

logger = logging.getLogger("redbreach.ai.chaining")

CHAINING_SYSTEM_PROMPT = """You are an expert penetration tester analyzing findings for vulnerability chains.

Given a list of individual findings, identify attack chains where multiple lower-severity bugs combine into higher-impact exploits.

For each chain, provide:
1. finding_ids, indices of findings in the chain
2. combined_severity, the severity of the chain as a whole
3. attack_path, step-by-step chain description (e.g., "SSRF → Internal API → RCE")
4. business_impact, real-world impact statement
5. cvss_override, estimated CVSS for the chain

Respond with JSON only:
{
    "chains": [
        {
            "finding_ids": [0, 2],
            "combined_severity": "critical",
            "attack_path": "XSS → Session Hijack",
            "business_impact": "Full account takeover.",
            "cvss_override": 9.1
        }
    ]
}

If no chains exist, return {"chains": []}."""


@dataclass
class VulnChain:
    finding_ids: list[int]
    combined_severity: str
    attack_path: str
    business_impact: str
    cvss_override: float | None = None


class ChainingEngine:
    def __init__(self, ai_client: AIClient):
        self.ai = ai_client

    async def identify_chains(
        self, findings: list[dict], engagement_context: str
    ) -> list[VulnChain]:
        if not findings or len(findings) < 2:
            return []

        prompt = self._build_prompt(findings, engagement_context)

        try:
            response = await self.ai.analyze(
                system=CHAINING_SYSTEM_PROMPT,
                prompt=prompt,
            )
        except Exception as e:
            logger.error("AI chaining failed: %s", e)
            return []

        return self._parse_response(response.text)

    def _build_prompt(self, findings: list[dict], context: str) -> str:
        lines = []
        for i, f in enumerate(findings):
            line = (
                f"[{i}] {f.get('title', '?')} "
                f"(severity: {f.get('severity', '?')}, "
                f"category: {f.get('category', '?')}, "
                f"at: {f.get('matched_at', '?')})"
            )
            # Real attack paths (SSRF -> internal API -> RCE) need the endpoint
            # and detail, not just a title, for the model to connect findings.
            detail = f.get("description") or f.get("reasoning") or f.get("impact")
            if detail:
                text = " ".join(str(detail).split())
                line += f"\n    detail: {text[:300]}" + ("..." if len(text) > 300 else "")
            lines.append(line)
        return f"Engagement: {context}\n\nFindings:\n" + "\n".join(lines)

    def _parse_response(self, text: str) -> list[VulnChain]:
        data = extract_json(text)
        if not isinstance(data, dict):
            logger.warning("AI returned non-JSON for chaining")
            return []

        chains = []
        for item in data.get("chains", []):
            try:
                chains.append(VulnChain(
                    finding_ids=item["finding_ids"],
                    combined_severity=item["combined_severity"],
                    attack_path=item["attack_path"],
                    business_impact=item["business_impact"],
                    cvss_override=item.get("cvss_override"),
                ))
            except (KeyError, TypeError) as e:
                logger.warning("Failed to parse chain: %s", e)
        return chains
