"""Tests for the priority scoring engine."""

import pytest

from redbreach.intel.priority import PriorityScorer


@pytest.fixture
def scorer():
    return PriorityScorer()


def test_kev_scores_highest(scorer):
    """KEV entry beats non-KEV even with higher CVSS."""
    kev_cve = {"kev_known_exploited": 1, "cvss_score": 7.0, "epss_score": 0.5}
    high_cvss = {"kev_known_exploited": 0, "cvss_score": 10.0, "epss_score": 0.99}

    kev_score = scorer.score_cve(kev_cve)
    high_score = scorer.score_cve(high_cvss)

    assert kev_score > high_score


def test_poc_boosts_score(scorer):
    """With PoC scores higher than without."""
    cve = {"cvss_score": 7.5, "epss_score": 0.3}

    with_poc = scorer.score_cve(cve, has_poc=True)
    without_poc = scorer.score_cve(cve, has_poc=False)

    assert with_poc > without_poc
    assert with_poc - without_poc == scorer.WEIGHT_POC


def test_cross_pattern_boost(scorer):
    """Cross-engagement hit adds score."""
    cve = {"cvss_score": 5.0}

    with_cross = scorer.score_cve(cve, cross_engagement_hit=True)
    without_cross = scorer.score_cve(cve, cross_engagement_hit=False)

    assert with_cross > without_cross
    assert with_cross - without_cross == scorer.WEIGHT_CROSS_ENGAGEMENT


def test_score_target(scorer):
    """Multiple signals produce high score."""
    cves = [{"kev_known_exploited": 1, "cvss_score": 9.8, "epss_score": 0.95}]

    score = scorer.score_target(
        matching_cves=cves,
        has_pocs=True,
        cross_engagement_hit=True,
        scope_age_days=7,
    )

    # KEV(100) + POC(50) + cross(30) + EPSS(0.95*15) + CVSS(9.8/10*10) + fresh(20)
    assert score > 200


def test_negative_signals_reduce_score(scorer):
    """WAF/rate limiting reduce score."""
    base = scorer.score_target(has_pocs=True)
    penalized = scorer.score_target(
        has_pocs=True,
        waf_detected=True,
        rate_limited=True,
        heavily_researched=True,
    )

    assert penalized < base


def test_score_floor_is_zero(scorer):
    """Score never goes negative."""
    score = scorer.score_target(
        waf_detected=True,
        rate_limited=True,
        heavily_researched=True,
    )
    assert score == 0


def test_fresh_scope_bonus(scorer):
    """Scope newer than 60 days gets bonus, older does not."""
    fresh = scorer.score_target(scope_age_days=30)
    stale = scorer.score_target(scope_age_days=365)

    assert fresh > stale
    assert fresh - stale == scorer.WEIGHT_FRESH_SCOPE
