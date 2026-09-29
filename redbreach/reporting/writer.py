"""AI-powered report writer, produces human-quality vulnerability reports."""

import json
import logging

from redbreach.ai.client import AIClient, extract_json

logger = logging.getLogger("redbreach.reporting.writer")

_PLATFORM_GUIDANCE = {
    "hackerone": "Write for HackerOne. Be concise, technical, and professional. Include clear reproduction steps. HackerOne reviewers value brevity and actionable PoCs.",
    "bugcrowd": "Write for Bugcrowd. Include VRT category context. Emphasize who is affected and business impact.",
    "intigriti": "Write for Intigriti. Include an attack scenario section. Focus on HTTP request/response evidence.",
    "yeswehack": "Write for YesWeHack. Technical depth is valued. Include chain potential if applicable.",
    "synack": "Write for Synack. Professional, executive-ready language. Include executive summary and technical analysis.",
    "immunefi": "Write for Immunefi (Web3/DeFi). Focus on funds at risk, smart contract impact, and provide Foundry/Hardhat reproduction steps if applicable.",
    "client": "Write a professional client-facing security assessment report. Executive summary first, then technical details.",
}

WRITER_SYSTEM_PROMPT = """You are a senior penetration tester writing vulnerability reports for bug bounty platforms and clients.

Write reports that sound like an experienced human researcher, not a tool or template. Be specific, reference the actual evidence, and explain why this matters in real-world terms.

Requirements:
- Title: Clear, specific, includes the vulnerability type and affected component
- Summary: 2-3 sentences that a non-technical person could understand
- Description: Technical explanation of the root cause
- Impact: What an attacker can actually DO, not theoretical, grounded in evidence
- Steps to Reproduce: Numbered, specific, anyone can follow them to reproduce
- Recommended Fix: Actionable, specific to this codebase/app

Respond with JSON:
{
    "title": "...",
    "summary": "...",
    "description": "...",
    "impact": "...",
    "steps_to_reproduce": "...",
    "recommended_fix": "..."
}"""


class ReportWriter:
    def __init__(self, ai_client: AIClient) -> None:
        self.ai = ai_client

    async def write(self, finding: dict, verification: dict, platform: str = "hackerone") -> dict:
        platform_guide = _PLATFORM_GUIDANCE.get(platform, _PLATFORM_GUIDANCE["hackerone"])
        prompt = self._build_prompt(finding, verification, platform, platform_guide)
        try:
            response = await self.ai.analyze(system=WRITER_SYSTEM_PROMPT, prompt=prompt)
        except Exception as e:
            logger.warning("AI report writing failed: %s, falling back to raw data", e)
            return self._fallback_report(finding, verification)

        # Tolerate ```json fences / prose around the JSON; a bare json.loads here
        # silently dumped the AI-written report and fell back to raw data whenever
        # the model wrapped its output.
        report = extract_json(response.text)
        if not isinstance(report, dict):
            logger.warning("AI report JSON unparseable, falling back to raw data")
            return self._fallback_report(finding, verification)

        report["poc_command"] = verification.get("poc_command", finding.get("poc_text", ""))
        report["confidence"] = verification.get("confidence", "unconfirmed")
        report["severity"] = finding.get("severity", "medium")
        report["category"] = finding.get("category", "")
        return report

    def _build_prompt(self, finding: dict, verification: dict, platform: str, platform_guide: str) -> str:
        return "\n".join([
            f"Platform: {platform}",
            f"Platform guidance: {platform_guide}",
            "", "--- Raw Finding ---",
            f"Title: {finding.get('title', 'Unknown')}",
            f"Severity: {finding.get('severity', 'unknown')}",
            f"Category: {finding.get('category', 'unknown')}",
            f"Description: {finding.get('description', 'N/A')}",
            f"Original PoC: {finding.get('poc_text', 'N/A')}",
            "", "--- Verification Evidence ---",
            f"Confidence: {verification.get('confidence', 'unconfirmed')}",
            f"Replay Evidence: {verification.get('replay_evidence', 'N/A')}",
            f"PoC Command: {verification.get('poc_command', 'N/A')}",
            f"AI Assessment: {verification.get('ai_assessment', 'N/A')}",
            "", "Write the report now. Make it sound like a seasoned researcher, not a scanner.",
        ])

    def _fallback_report(self, finding: dict, verification: dict) -> dict:
        return {
            "title": finding.get("title", "Unknown Vulnerability"),
            "summary": finding.get("description", ""),
            "description": finding.get("description", ""),
            "impact": finding.get("impact", ""),
            "steps_to_reproduce": finding.get("steps_to_reproduce", finding.get("poc_text", "")),
            "recommended_fix": finding.get("recommended_fix", ""),
            "poc_command": verification.get("poc_command", finding.get("poc_text", "")),
            "confidence": verification.get("confidence", "unconfirmed"),
            "severity": finding.get("severity", "medium"),
            "category": finding.get("category", ""),
        }
