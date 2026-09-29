"""CVSS v3.1 Base Score calculator and EPSS estimator."""
import math

# CVSS v3.1 metric values
_AV = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.20}
_AC = {"low": 0.77, "high": 0.44}
_PR_UNCHANGED = {"none": 0.85, "low": 0.62, "high": 0.27}
_PR_CHANGED = {"none": 0.85, "low": 0.68, "high": 0.50}
_UI = {"none": 0.85, "required": 0.62}
_CIA = {"high": 0.56, "low": 0.22, "none": 0.0}


def calculate_cvss(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> float:
    """Calculate CVSS v3.1 Base Score.

    Returns a float from 0.0 to 10.0.
    """
    av = _AV.get(attack_vector, 0.85)
    ac = _AC.get(attack_complexity, 0.77)
    pr_table = _PR_CHANGED if scope == "changed" else _PR_UNCHANGED
    pr = pr_table.get(privileges_required, 0.85)
    ui = _UI.get(user_interaction, 0.85)

    c = _CIA.get(confidentiality, 0.0)
    i = _CIA.get(integrity, 0.0)
    a = _CIA.get(availability, 0.0)

    # Impact Sub Score
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if iss <= 0:
        return 0.0

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if scope == "changed":
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    if scope == "changed":
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    # Round up to nearest 0.1
    return math.ceil(base * 10) / 10


def severity_from_cvss(score: float) -> str:
    """Map CVSS score to severity label."""
    if score == 0.0:
        return "info"
    elif score < 4.0:
        return "low"
    elif score < 7.0:
        return "medium"
    elif score < 9.0:
        return "high"
    else:
        return "critical"


def estimate_epss(
    cvss_score: float,
    has_public_exploit: bool = False,
    age_days: int = 0,
) -> float:
    """Estimate EPSS (Exploit Prediction Scoring System) probability.

    This is a simplified heuristic, real EPSS uses ML on CVE data.
    Returns probability between 0.0 and 1.0.
    """
    # Base probability from CVSS
    base = cvss_score / 10.0

    # Public exploit multiplier
    if has_public_exploit:
        base = min(base * 2.0, 0.95)

    # Age decay (older vulns less likely to be exploited if not already)
    if age_days > 90:
        decay = max(0.5, 1.0 - (age_days - 90) / 1000)
        base *= decay

    return round(min(max(base, 0.0), 1.0), 4)


# Metric -> (vector abbreviation, {value: letter}, default letter). The defaults
# mirror calculate_cvss()'s .get() fallbacks so the vector always matches the score.
_VECTOR_METRICS = [
    ("attack_vector",       "AV", {"network": "N", "adjacent": "A", "local": "L", "physical": "P"}, "N"),
    ("attack_complexity",   "AC", {"low": "L", "high": "H"}, "L"),
    ("privileges_required", "PR", {"none": "N", "low": "L", "high": "H"}, "N"),
    ("user_interaction",    "UI", {"none": "N", "required": "R"}, "N"),
    ("scope",               "S",  {"unchanged": "U", "changed": "C"}, "U"),
    ("confidentiality",     "C",  {"high": "H", "low": "L", "none": "N"}, "N"),
    ("integrity",           "I",  {"high": "H", "low": "L", "none": "N"}, "N"),
    ("availability",        "A",  {"high": "H", "low": "L", "none": "N"}, "N"),
]

_METRIC_DEFAULTS = {
    "attack_vector": "network", "attack_complexity": "low",
    "privileges_required": "none", "user_interaction": "none", "scope": "unchanged",
    "confidentiality": "none", "integrity": "none", "availability": "none",
}


def build_vector(**metrics: str) -> str:
    """Build the CVSS v3.1 base vector string from metric words."""
    parts = ["CVSS:3.1"]
    for key, abbr, mapping, default in _VECTOR_METRICS:
        parts.append(f"{abbr}:{mapping.get(metrics.get(key, ''), default)}")
    return "/".join(parts)


def score_finding(has_public_exploit: bool = False, age_days: int = 0, **metrics: str) -> dict:
    """Compute CVSS score, vector, derived severity, and estimated EPSS in one call.

    Missing metrics fall back to the CVSS 'worst-plausible-default' used by
    calculate_cvss, so a partial spec still yields a consistent score+vector.
    """
    full = {**_METRIC_DEFAULTS, **{k: v for k, v in metrics.items() if v}}
    score = calculate_cvss(**full)
    return {
        "cvss_score": score,
        "cvss_vector": build_vector(**full),
        "severity": severity_from_cvss(score),
        "epss_score": estimate_epss(score, has_public_exploit, age_days),
    }
