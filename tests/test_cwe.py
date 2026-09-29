from redbreach.cwe import (
    CWE_TOP_25_2023,
    classify_cwe,
    cwe_for_category,
    top25_coverage,
)


def test_direct_top25_mappings():
    assert cwe_for_category("sqli") == "CWE-89"
    assert cwe_for_category("ssrf") == "CWE-918"
    assert cwe_for_category("auth_bypass") == "CWE-306"
    for cat in ("sqli", "ssrf", "auth_bypass", "secret_in_js"):
        assert classify_cwe(cat)["in_top25"] is True


def test_idor_rolls_up_to_top25_parent():
    info = classify_cwe("idor")
    assert info["cwe"] == "CWE-639"          # precise id
    assert info["in_top25"] is False          # CWE-639 itself is not top-25
    assert info["related_top25"] == "CWE-862"  # but rolls up to Missing Authorization


def test_non_top25_mappings_still_classify():
    info = classify_cwe("cors")
    assert info["cwe"] == "CWE-942"
    assert info["in_top25"] is False


def test_unmapped_and_empty_return_none():
    assert classify_cwe("totally_unknown_category") is None
    assert classify_cwe(None) is None
    assert cwe_for_category("") is None


def test_template_id_categories_map():
    assert cwe_for_category("cors-credentialed-reflection") == "CWE-942"
    assert cwe_for_category("sqlmap-detected") == "CWE-89"


def test_top25_coverage_counts_direct_and_parent():
    covered = top25_coverage(["sqli", "idor", "cors", "ssrf"])
    assert "CWE-89" in covered      # sqli direct
    assert "CWE-918" in covered     # ssrf direct
    assert "CWE-862" in covered     # idor via parent
    assert "CWE-942" not in covered  # cors is not top-25


def test_top25_set_has_25_entries():
    assert len(CWE_TOP_25_2023) == 25
