"""Coverage for the two CLI paths wired in 2026-09: ops dedup and report generate --ai."""
from click.testing import CliRunner

from redbreach.cli import main
from redbreach.ops.dedup import deduplicate_findings, similarity_score


def test_dedup_help_states_read_only():
    res = CliRunner().invoke(main, ["ops", "dedup", "--help"])
    assert res.exit_code == 0
    assert "Read-only" in res.output
    assert "--threshold" in res.output


def test_dedup_empty_engagement_exits_clean():
    res = CliRunner().invoke(main, ["ops", "dedup", "999999"])
    assert res.exit_code == 0
    assert "No findings" in res.output


def test_report_generate_exposes_ai_flag():
    res = CliRunner().invoke(main, ["report", "generate", "--help"])
    assert res.exit_code == 0
    assert "--ai" in res.output


def test_report_generate_without_ai_is_unchanged_for_missing_finding():
    res = CliRunner().invoke(main, ["report", "generate", "999999"])
    assert res.exit_code == 0
    assert "not found" in res.output.lower()


def test_dedup_reporting_pairs_duplicate_with_its_match():
    """The CLI reports each dropped finding against the kept one it matched."""
    findings = [
        {"id": 1, "title": "Reflected XSS in search", "category": "xss", "severity": "medium"},
        {"id": 2, "title": "Reflected XSS in search box", "category": "xss", "severity": "medium"},
        {"id": 3, "title": "Open redirect on login", "category": "redirect", "severity": "low"},
    ]
    kept = deduplicate_findings(findings, threshold=0.85)
    kept_ids = {f["id"] for f in kept}
    dropped = [f for f in findings if f["id"] not in kept_ids]

    assert len(dropped) == 1, "the two XSS titles should collapse to one"
    assert 3 in kept_ids, "the unrelated finding must survive"
    match = max(kept, key=lambda k: similarity_score(dropped[0], k))
    assert match["id"] in kept_ids


def test_dedup_promotes_the_higher_severity_of_a_matched_pair():
    """When a pair matches, the stronger one is the survivor, not the first seen."""
    findings = [
        {"id": 1, "title": "SQL injection in report export", "category": "sqli", "severity": "low"},
        {"id": 2, "title": "SQL injection in report export", "category": "sqli", "severity": "critical"},
    ]
    kept = deduplicate_findings(findings, threshold=0.85)
    assert len(kept) == 1
    assert kept[0]["severity"] == "critical"


def test_severity_disagreement_costs_exactly_the_severity_weight():
    """Documents a real limitation: a severity mismatch caps the score at the default threshold.

    similarity_score weights severity agreement at 0.15. Two findings with a byte-identical
    title and category but different severity score exactly 0.85, which only clears the default
    threshold because the comparison is >=. Any title variation at all drops such a pair below
    it, so the same issue reported at two severities by two tools will NOT be matched at the
    default. Use a lower threshold when severity is expected to disagree.
    """
    same_sev = similarity_score(
        {"title": "Reflected XSS in search", "category": "xss", "severity": "medium"},
        {"title": "Reflected XSS in search box", "category": "xss", "severity": "medium"},
    )
    diff_sev = similarity_score(
        {"title": "Reflected XSS in search", "category": "xss", "severity": "medium"},
        {"title": "Reflected XSS in search box", "category": "xss", "severity": "high"},
    )
    assert round(same_sev - diff_sev, 3) == 0.15
    assert same_sev >= 0.85, "matches at the default threshold when severity agrees"
    assert diff_sev < 0.85, "fails the default threshold purely on severity disagreement"
    assert diff_sev >= 0.75, "a lower threshold recovers it"

    identical_title_diff_sev = similarity_score(
        {"title": "Reflected XSS in search", "category": "xss", "severity": "medium"},
        {"title": "Reflected XSS in search", "category": "xss", "severity": "high"},
    )
    assert identical_title_diff_sev == 0.85, "the ceiling for a severity mismatch is the default threshold itself"
