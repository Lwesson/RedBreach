import json
from pathlib import Path

from redbreach.config import load_config, DEFAULT_CONFIG, RedBreachConfig


def test_load_default_config_when_no_file(tmp_path):
    """load_config returns defaults when config.json doesn't exist."""
    cfg = load_config(tmp_path)
    assert cfg.data_dir == tmp_path
    assert cfg.rate_limit_rps == DEFAULT_CONFIG["rate_limits"]["default_requests_per_second"]


def test_load_config_from_file(tmp_path):
    """load_config reads and merges config.json."""
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "rate_limits": {"default_requests_per_second": 20}
    }))
    cfg = load_config(tmp_path)
    assert cfg.rate_limit_rps == 20


def test_config_creates_subdirectories(tmp_path):
    """load_config creates required subdirectories."""
    cfg = load_config(tmp_path)
    assert (tmp_path / "evidence").is_dir()
    assert (tmp_path / "reports").is_dir()
    assert (tmp_path / "sessions").is_dir()


def test_config_db_path(tmp_path):
    """Config provides database path."""
    cfg = load_config(tmp_path)
    assert cfg.db_path == tmp_path / "redbreach.db"


def test_config_has_ai_defaults(tmp_path):
    """Config includes AI budget and model defaults."""
    cfg = load_config(tmp_path)
    assert "ai" in cfg.raw
    assert cfg.raw["ai"]["budget_dollars"] > 0
    assert cfg.raw["ai"]["model"] is not None
