import json
import logging
from dataclasses import dataclass

from redbreach.ai.client import AIClient, extract_json

logger = logging.getLogger("redbreach.ai.triage")

TRIAGE_SYSTEM_PROMPT = """You are an expert security analyst triaging automated scan results.

For each finding, determine:
1. Is it a false positive? (common with automated scanners)
2. Confidence level (0.0 to 1.0)
3. Brief reasoning (1-2 sentences)
4. Priority (1=investigate immediately, 2=investigate soon, 3=low priority)

Consider:
- Template reliability (some Nuclei templates have high false positive rates)
- Extracted evidence strength (actual error messages vs generic matches)
- Target context (tech stack, application type)
- Severity vs actual exploitability

Respond with JSON only:
{
    "results": [
        {
            "finding_index": 0,
            "is_false_positive": false,
            "confidence": 0.85,
            "reasoning": "SQL error in response body confirms real injection point.",
            "priority": 1
        }
    ]
}"""


@dataclass
class TriageResult:
    finding_index: int
    is_false_positive: bool
    confidence: float
    reasoning: str
    priority: int


class TriageEngine:
    def __init__(self, ai_client: AIClient, batch_size: int = 20):
        self.ai = ai_client
        self.batch_size = batch_size

    async def triage(self, findings: list[dict], engagement_context: str) -> list[TriageResult]:
        if not findings:
            return []

        all_results = []
        for batch_start in range(0, len(findings), self.batch_size):
            batch = findings[batch_start:batch_start + self.batch_size]
            batch_results = await self._triage_batch(batch, engagement_context, batch_start)
            all_results.extend(batch_results)

        return all_results

    async def _triage_batch(self, findings: list[dict], context: str, offset: int) -> list[TriageResult]:
        prompt = self._build_prompt(findings, context)

        try:
            response = await self.ai.analyze(
                system=TRIAGE_SYSTEM_PROMPT,
                prompt=prompt,
            )
        except Exception as e:
            logger.error("AI triage failed: %s", e)
            return []

        return self._parse_response(response.text, offset)

    def _build_prompt(self, findings: list[dict], context: str) -> str:
        findings_text = []
        for i, f in enumerate(findings):
            line = (
                f"[{i}] {f.get('title', 'Unknown')} "
                f"(severity: {f.get('severity', '?')}, "
                f"category: {f.get('category') or f.get('template_id', '?')}, "
                f"at: {f.get('matched_at', '?')})"
            )
            evidence = self._evidence_snippet(f)
            if evidence:
                # The system prompt asks the model to weigh evidence strength,
                # so it must actually receive the extracted evidence.
                line += f"\n    evidence: {evidence}"
            findings_text.append(line)
        return (
            f"Engagement context: {context}\n\n"
            f"Findings to triage:\n" + "\n".join(findings_text)
        )

    @staticmethod
    def _evidence_snippet(f: dict, limit: int = 400) -> str:
        for key in ("extracted_results", "evidence", "poc_text", "description", "reasoning"):
            val = f.get(key)
            if val:
                text = " ".join(str(val).split())
                return text[:limit] + ("..." if len(text) > limit else "")
        return ""

    def _parse_response(self, text: str, offset: int) -> list[TriageResult]:
        data = extract_json(text)
        if not isinstance(data, dict):
            logger.warning("AI returned non-JSON response")
            return []

        results = []
        for item in data.get("results", []):
            try:
                results.append(TriageResult(
                    finding_index=item["finding_index"] + offset,
                    is_false_positive=item["is_false_positive"],
                    confidence=item["confidence"],
                    reasoning=item["reasoning"],
                    priority=item["priority"],
                ))
            except (KeyError, TypeError) as e:
                logger.warning("Failed to parse triage result: %s", e)
                continue

        return results
