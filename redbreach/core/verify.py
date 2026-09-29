"""Verification engine, replay findings, generate PoCs, assess confidence."""

import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from redbreach.ai.client import AIClient, extract_json

logger = logging.getLogger("redbreach.core.verify")

VERIFY_SYSTEM_PROMPT = """You are an expert security researcher verifying vulnerability findings.

Given the original finding details and the HTTP replay results, assess whether this is a true positive.

Respond with JSON only:
{
    "confidence": "verified" | "likely" | "unconfirmed" | "false_positive",
    "reasoning": "Why you believe this assessment, reference specific evidence from the response.",
    "impact": "What an attacker could actually do with this."
}

Be conservative: only mark "verified" if the response clearly demonstrates the vulnerability.
Mark "likely" if the evidence is suggestive but not conclusive.
Mark "false_positive" if the response shows the vulnerability is mitigated."""


class Confidence:
    VERIFIED = "verified"
    LIKELY = "likely"
    UNCONFIRMED = "unconfirmed"
    FALSE_POSITIVE = "false_positive"


@dataclass
class VerificationResult:
    finding_id: int
    confidence: str
    replay_status_code: int | None = None
    replay_evidence: str | None = None
    poc_command: str | None = None
    poc_script: str | None = None
    ai_assessment: str | None = None


class VerificationEngine:
    def __init__(self, ai_client: AIClient, timeout: int = 15, auth_session=None) -> None:
        self.ai = ai_client
        self.timeout = timeout
        self.auth_session = auth_session

    async def verify(self, finding: dict) -> VerificationResult:
        finding_id = finding.get("id", 0)
        url = finding.get("matched_at", "")
        poc_text = finding.get("poc_text", "")
        method, replay_url, headers, body = self._parse_poc(poc_text, url)
        poc = generate_poc_script(method, replay_url, headers, body)

        try:
            if self.auth_session:
                client = await self.auth_session.create_client()
            else:
                client = httpx.AsyncClient(verify=False, timeout=self.timeout)
            async with client:
                response = await client.request(method=method, url=replay_url, headers=headers, content=body)
            status_code = response.status_code
            response_text = response.text[:2000]
            response_headers = dict(response.headers)
        except Exception as e:
            logger.warning("Replay failed for finding %d: %s", finding_id, e)
            return VerificationResult(finding_id=finding_id, confidence=Confidence.UNCONFIRMED,
                                       poc_command=poc["curl"], poc_script=poc["python"])

        ai_assessment = await self._ai_assess(finding, status_code, response_text, response_headers)
        return VerificationResult(
            finding_id=finding_id,
            confidence=ai_assessment.get("confidence", Confidence.UNCONFIRMED),
            replay_status_code=status_code,
            replay_evidence=response_text[:500],
            poc_command=poc["curl"],
            poc_script=poc["python"],
            ai_assessment=ai_assessment.get("reasoning", ""),
        )

    async def verify_batch(self, findings: list[dict]) -> list[VerificationResult]:
        results = []
        for finding in findings:
            results.append(await self.verify(finding))
        return results

    def _parse_poc(self, poc_text: str, fallback_url: str) -> tuple[str, str, dict, str | None]:
        method, url, headers, body = "GET", fallback_url, {}, None
        if not poc_text:
            return method, url, headers, body
        match = re.match(r"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)", poc_text, re.IGNORECASE)
        if match:
            method = match.group(1).upper()
            path_or_url = match.group(2)
            if path_or_url.startswith("http"):
                url = path_or_url
            elif fallback_url:
                parsed = urlparse(fallback_url)
                url = f"{parsed.scheme}://{parsed.netloc}{path_or_url}"
        if "curl" in poc_text.lower():
            url_match = re.search(r"['\"]?(https?://\S+?)['\"]?\s*$", poc_text, re.MULTILINE)
            if url_match:
                url = url_match.group(1).strip("'\"")
            if "-X POST" in poc_text or "-d " in poc_text:
                method = "POST"
            data_match = re.search(r"-d\s+['\"](.+?)['\"]", poc_text)
            if data_match:
                body = data_match.group(1)
        return method, url, headers, body

    async def _ai_assess(self, finding: dict, status_code: int, response_text: str, response_headers: dict) -> dict:
        prompt = f"""Finding: {finding.get('title', 'Unknown')}
Severity: {finding.get('severity', 'unknown')}
Category: {finding.get('category', 'unknown')}
Original PoC: {finding.get('poc_text', 'N/A')}
Description: {finding.get('description', 'N/A')}

Replay Results:
- Status Code: {status_code}
- Response Headers: {json.dumps(dict(list(response_headers.items())[:10]))}
- Response Body (first 1000 chars): {response_text[:1000]}

Is this vulnerability real? Assess the evidence."""
        try:
            response = await self.ai.analyze(system=VERIFY_SYSTEM_PROMPT, prompt=prompt)
        except Exception as e:
            logger.warning("AI assessment failed: %s", e)
            return {"confidence": Confidence.UNCONFIRMED, "reasoning": str(e), "impact": ""}

        data = extract_json(response.text)
        if not isinstance(data, dict):
            logger.warning("AI assessment returned unparseable output for finding %s", finding.get("id"))
            return {"confidence": Confidence.UNCONFIRMED, "reasoning": "unparseable AI response", "impact": ""}
        # Guard against an out-of-vocabulary confidence value.
        valid = {Confidence.VERIFIED, Confidence.LIKELY, Confidence.UNCONFIRMED, Confidence.FALSE_POSITIVE}
        if data.get("confidence") not in valid:
            data["confidence"] = Confidence.UNCONFIRMED
        return data


def generate_poc_script(method: str = "GET", url: str = "", headers: dict | None = None, body: str | None = None) -> dict[str, str]:
    headers = headers or {}
    curl_parts = ["curl", "-s", "-k"]
    if method != "GET":
        curl_parts.extend(["-X", method])
    for k, v in headers.items():
        curl_parts.extend(["-H", f"'{k}: {v}'"])
    if body:
        curl_parts.extend(["-d", f"'{body}'"])
    curl_parts.append(f"'{url}'")
    curl_cmd = " ".join(curl_parts)

    py_lines = ["import httpx", "", f'url = "{url}"']
    if headers:
        py_lines.append(f"headers = {json.dumps(headers)}")
    else:
        py_lines.append("headers = {}")
    if body:
        py_lines.append(f'body = """{body}"""')
        py_lines.append(f"resp = httpx.request('{method}', url, headers=headers, content=body, verify=False)")
    else:
        py_lines.append(f"resp = httpx.request('{method}', url, headers=headers, verify=False)")
    py_lines.extend(["print(f'Status: {resp.status_code}')", "print(f'Body: {resp.text[:500]}')"])
    return {"curl": curl_cmd, "python": "\n".join(py_lines)}
