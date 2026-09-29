import pytest
from unittest.mock import patch

from redbreach.wizard import (
    build_engagement_params,
    validate_target,
    ENGAGEMENT_TYPES,
    PLATFORMS,
    ATTACK_SURFACES,
)


def test_validate_target_domain():
    assert validate_target("example.com") is True


def test_validate_target_ip():
    assert validate_target("192.168.1.1") is True


def test_validate_target_url():
    assert validate_target("https://example.com") is True


def test_validate_target_empty():
    assert validate_target("") is False


def test_validate_target_whitespace():
    assert validate_target("   ") is False


def test_engagement_types_defined():
    assert "bounty" in ENGAGEMENT_TYPES
    assert "pentest" in ENGAGEMENT_TYPES
    assert "private" in ENGAGEMENT_TYPES


def test_platforms_defined():
    assert "hackerone" in PLATFORMS
    assert "bugcrowd" in PLATFORMS
    assert "immunefi" in PLATFORMS


def test_attack_surfaces_defined():
    assert "web" in ATTACK_SURFACES
    assert "api" in ATTACK_SURFACES
    assert "cloud" in ATTACK_SURFACES
    assert "mobile" in ATTACK_SURFACES
    assert "network" in ATTACK_SURFACES
    assert "web3" in ATTACK_SURFACES
    assert "ai_llm" in ATTACK_SURFACES


@patch("builtins.input", side_effect=["1", "1", "example.com", "n", "1,2", "2", "n"])
def test_build_engagement_params(mock_input):
    """Wizard collects params through interactive prompts."""
    params = build_engagement_params()
    assert params["type"] == "bounty"
    assert params["platform"] == "hackerone"
    assert params["target"] == "example.com"
    assert "web" in params["surfaces"]
    assert "api" in params["surfaces"]
    assert params["depth"] == "standard"


@patch("builtins.input", side_effect=["3", "10.0.0.1", "n", "1", "1", "n"])
def test_build_engagement_private_no_platform(mock_input):
    """Private engagement skips platform selection."""
    params = build_engagement_params()
    assert params["type"] == "private"
    assert params["platform"] is None
