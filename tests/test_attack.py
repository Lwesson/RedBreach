from redbreach.attack import (
    ATTACK_TECHNIQUES,
    attack_for_category,
    classify_attack,
    tactic_coverage,
)


def test_web_categories_map_to_techniques():
    assert attack_for_category("sqli") == "T1190"
    assert attack_for_category("cors") == "T1539"
    assert attack_for_category("hardcoded_secret") == "T1552.001"


def test_ai_category_maps_to_atlas():
    info = classify_attack("prompt_injection")
    assert info["technique"] == "AML.T0051"
    assert "ATLAS" in info["tactic"]


def test_mobile_category_maps_to_mobile_matrix():
    assert attack_for_category("exported_component") == "T1416"
    assert attack_for_category("cleartext_traffic") == "T1439"


def test_classify_includes_name_and_tactic():
    info = classify_attack("ssrf")
    assert info["technique"] == "T1190"
    assert info["technique_name"] == "Exploit Public-Facing Application"
    assert info["tactic"] == "Initial Access"


def test_unmapped_and_empty_return_none():
    assert classify_attack("headers") is None      # hardening gap, no clean technique
    assert classify_attack(None) is None
    assert attack_for_category("") is None


def test_every_mapped_technique_has_metadata():
    from redbreach.attack import CATEGORY_ATTACK
    for tid in set(CATEGORY_ATTACK.values()):
        assert tid in ATTACK_TECHNIQUES, f"{tid} missing name/tactic"


def test_tactic_coverage_groups_by_tactic():
    cov = tactic_coverage(["sqli", "ssrf", "cors", "prompt_injection"])
    assert "T1190" in cov["Initial Access"]        # sqli + ssrf collapse to one technique
    assert cov["Initial Access"].count("T1190") == 1
    assert "T1539" in cov["Credential Access"]
