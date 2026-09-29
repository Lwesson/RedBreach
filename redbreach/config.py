import json
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG = {
    "rate_limits": {
        "default_requests_per_second": 10,
        "aggressive_requests_per_second": 50,
    },
    "notifications": {
        "terminal": True,
        "webhook_url": None,
        "min_severity": "high",
    },
    "ai": {
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "base_url": None,
        "budget_dollars": 10.0,
        "max_tokens": 4096,
        "batch_size": 20,
    },
}

SUBDIRS = ["evidence", "reports", "sessions", "engagements"]


@dataclass
class RedBreachConfig:
    """Resolved configuration with computed paths."""

    data_dir: Path
    raw: dict

    @property
    def db_path(self) -> Path:
        return self.data_dir / "redbreach.db"

    @property
    def engagements_dir(self) -> Path:
        return self.data_dir / "engagements"

    @property
    def rate_limit_rps(self) -> int:
        return self.raw["rate_limits"]["default_requests_per_second"]

    @property
    def aggressive_rps(self) -> int:
        return self.raw["rate_limits"]["aggressive_requests_per_second"]

    @property
    def ai_model(self) -> str:
        return self.raw.get("ai", {}).get("model", "claude-sonnet-4-20250514")

    @property
    def ai_provider(self) -> str:
        return self.raw.get("ai", {}).get("provider", "anthropic")

    @property
    def ai_base_url(self) -> str | None:
        return self.raw.get("ai", {}).get("base_url")

    @property
    def nvd_api_key(self) -> str | None:
        """NVD API key from config or environment."""
        import os
        return os.environ.get("NVD_API_KEY") or self.raw.get("nvd_api_key")


def load_config(data_dir: Path) -> RedBreachConfig:
    """Load config from data_dir/config.json, falling back to defaults.

    Creates required subdirectories if they don't exist.
    """
    config_path = data_dir / "config.json"
    raw = dict(DEFAULT_CONFIG)

    if config_path.exists():
        with open(config_path) as f:
            user_cfg = json.load(f)
        # Deep merge one level
        for key, value in user_cfg.items():
            if key in raw and isinstance(raw[key], dict) and isinstance(value, dict):
                raw[key] = {**raw[key], **value}
            else:
                raw[key] = value

    # Create subdirectories
    data_dir.mkdir(parents=True, exist_ok=True)
    for subdir in SUBDIRS:
        (data_dir / subdir).mkdir(exist_ok=True)

    return RedBreachConfig(data_dir=data_dir, raw=raw)
