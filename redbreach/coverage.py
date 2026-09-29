"""Per-engagement CWE Top 25 and MITRE ATT&CK coverage, from stored findings.

Pure summary so it is testable without the CLI or db; the `coverage` command just
fetches findings and formats this.
"""
from __future__ import annotations

from redbreach.attack import tactic_coverage
from redbreach.cwe import CWE_NAMES, CWE_TOP_25_2023, top25_coverage


def coverage_summary(findings: list[dict]) -> dict:
    """Summarize CWE Top-25 and ATT&CK tactic coverage across a list of findings."""
    categories = [f.get("category") for f in findings if f.get("category")]
    covered = top25_coverage(categories)
    return {
        "total_findings": len(findings),
        "cwe_top25_total": len(CWE_TOP_25_2023),
        "cwe_top25_covered": sorted(covered),
        "cwe_top25_covered_count": len(covered),
        "cwe_top25_uncovered_count": len(CWE_TOP_25_2023) - len(covered),
        "attack_tactics": tactic_coverage(categories),
    }


def format_coverage(summary: dict) -> str:
    """Render a coverage summary as plain lines for the terminal."""
    lines = [
        f"Findings: {summary['total_findings']}",
        f"CWE Top 25 covered: {summary['cwe_top25_covered_count']}/{summary['cwe_top25_total']}",
    ]
    for cwe in summary["cwe_top25_covered"]:
        lines.append(f"  {cwe}  {CWE_NAMES.get(cwe, '')}")
    tactics = summary["attack_tactics"]
    if tactics:
        lines.append("MITRE ATT&CK tactics:")
        for tactic, techniques in tactics.items():
            lines.append(f"  {tactic}: {', '.join(techniques)}")
    return "\n".join(lines)
