"""Tests for the cross-engagement pattern matcher."""

import json

import pytest

from redbreach.intel.patterns import PatternMatcher

pytestmark = pytest.mark.asyncio


async def _seed_two_engagements(db):
    """Create 2 engagements with AEM-related findings."""
    eng1 = await db.create_engagement("bounty", "hackerone", "target1.com", "{}")
    eng2 = await db.create_engagement("bounty", "hackerone", "target2.com", "{}")

    # Asset on eng1 with AEM tech stack
    a1 = await db.create_asset(
        eng1, "web", "https://target1.com",
        tech_stack_json=json.dumps({"aem": "6.5", "java": "11"}),
    )
    # Asset on eng2 with AEM tech stack
    a2 = await db.create_asset(
        eng2, "web", "https://target2.com",
        tech_stack_json=json.dumps({"aem": "6.4", "nginx": "1.18"}),
    )

    # Findings on both engagements
    await db.create_finding(eng1, a1, "AEM Default Servlet Exposed", "high", category="misconfiguration")
    await db.create_finding(eng1, a1, "AEM Dispatcher Bypass", "critical", category="access_control")
    await db.create_finding(eng2, a2, "AEM CRX/DE Console Open", "high", category="misconfiguration")

    return eng1, eng2


async def test_find_cross_patterns(db):
    """Patterns found across engagements for matching tech."""
    eng1, eng2 = await _seed_two_engagements(db)
    matcher = PatternMatcher(db)

    # From eng1's perspective, find patterns in eng2
    patterns = await matcher.find_patterns(eng1, tech_stack=["aem"])
    assert len(patterns) > 0
    assert any(p["category"] == "misconfiguration" for p in patterns)


async def test_hit_rate_calculation(db):
    """Hit rates include the finding categories."""
    await _seed_two_engagements(db)
    matcher = PatternMatcher(db)

    rates = await matcher.get_hit_rates()
    assert "misconfiguration" in rates
    assert rates["misconfiguration"]["count"] >= 2
    assert rates["misconfiguration"]["engagements"] >= 1


async def test_no_patterns_for_unrelated_tech(db):
    """No matches when tech doesn't overlap."""
    eng1, _ = await _seed_two_engagements(db)
    matcher = PatternMatcher(db)

    patterns = await matcher.find_patterns(eng1, tech_stack=["kubernetes"])
    assert len(patterns) == 0


async def test_patterns_without_tech_filter(db):
    """Without tech filter, all cross-engagement findings returned."""
    eng1, _ = await _seed_two_engagements(db)
    matcher = PatternMatcher(db)

    patterns = await matcher.find_patterns(eng1)
    # Should get findings from eng2
    assert len(patterns) > 0
