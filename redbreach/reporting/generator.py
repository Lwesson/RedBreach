import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

import redbreach

logger = logging.getLogger("redbreach.reporting")

SUPPORTED_PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "synack", "immunefi", "client"]

# Bundled defaults ship inside the package so `report generate` works on a plain
# `pip install` (they used to live at the repo root, outside the wheel).
BUNDLED_TEMPLATES = Path(__file__).resolve().parent.parent / "templates"


class ReportGenerator:
    """Jinja2-based report generator for bug bounty and pentest findings.

    Templates resolve through a search path so users can bring their own: any
    `<platform>.md` in ``user_templates_dir`` overrides the bundled default,
    per file, with the packaged version used for anything not overridden.
    """

    def __init__(self, templates_dir: Path | None = None, user_templates_dir: Path | None = None):
        base = Path(templates_dir) if templates_dir else BUNDLED_TEMPLATES
        self.templates_dir = base

        search: list[str] = []
        if user_templates_dir:
            user = Path(user_templates_dir)
            if user.is_dir():
                search.append(str(user))
        search.append(str(base))
        self.search_path = search

        self.env = Environment(
            loader=FileSystemLoader(search),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, platform: str, finding: dict) -> str:
        """Render a finding into a platform-specific report."""
        template_name = f"{platform}.md"
        if platform not in SUPPORTED_PLATFORMS:
            raise ValueError(f"Unknown platform: {platform}. Supported: {SUPPORTED_PLATFORMS}")

        template = self.env.get_template(template_name)

        context = {
            "title": finding.get("title", "Untitled Finding"),
            "summary": finding.get("description", ""),
            "category": finding.get("category", "unknown"),
            "severity": finding.get("severity", "info"),
            "cvss_score": finding.get("cvss_score"),
            "cvss_vector": finding.get("cvss_vector"),
            "epss_score": finding.get("epss_score"),
            "cwe": finding.get("cwe"),
            "attack_technique": finding.get("attack_technique"),
            "description": finding.get("description", ""),
            "steps_to_reproduce": finding.get("steps_to_reproduce", ""),
            "poc_text": finding.get("poc_text"),
            "impact": finding.get("impact", ""),
            "recommended_fix": finding.get("recommended_fix"),
            "evidence_files": finding.get("evidence_files", []),
            "target": finding.get("target", ""),
            "client_name": finding.get("client_name"),
            "report_date": finding.get("report_date", ""),
            "chain_parent": finding.get("chain_parent_id"),
            "funds_at_risk": finding.get("funds_at_risk"),
            "version": redbreach.__version__,
        }

        return template.render(**context)

    def save(self, platform: str, finding: dict, output_path: Path) -> None:
        """Generate and save a report to a file."""
        report = self.generate(platform, finding)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report)
        logger.info("Report saved to %s", output_path)
