from redbreach.coverage import coverage_summary, format_coverage


def _f(category):
    return {"category": category, "title": "x", "severity": "high"}


def test_summary_counts_top25_and_tactics():
    findings = [_f("sqli"), _f("idor"), _f("ssrf"), _f("cors"), _f("headers")]
    s = coverage_summary(findings)
    assert s["total_findings"] == 5
    assert s["cwe_top25_total"] == 25
    assert "CWE-89" in s["cwe_top25_covered"]      # sqli
    assert "CWE-862" in s["cwe_top25_covered"]     # idor rollup
    assert "CWE-918" in s["cwe_top25_covered"]     # ssrf
    assert s["cwe_top25_covered_count"] == len(s["cwe_top25_covered"])
    assert s["cwe_top25_uncovered_count"] == 25 - s["cwe_top25_covered_count"]
    assert "Initial Access" in s["attack_tactics"]


def test_summary_empty():
    s = coverage_summary([])
    assert s["total_findings"] == 0
    assert s["cwe_top25_covered"] == []
    assert s["attack_tactics"] == {}


def test_findings_without_category_ignored():
    s = coverage_summary([{"title": "no category"}, _f("sqli")])
    assert s["total_findings"] == 2
    assert s["cwe_top25_covered"] == ["CWE-89"]


def test_format_coverage_renders_lines():
    out = format_coverage(coverage_summary([_f("sqli"), _f("ssrf")]))
    assert "CWE Top 25 covered:" in out
    assert "CWE-89" in out
    assert "MITRE ATT&CK tactics:" in out
