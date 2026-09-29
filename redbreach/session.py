import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("redbreach.session")


class SessionManager:
    def __init__(self, sessions_dir: Path):
        self.sessions_dir = Path(sessions_dir)

    def save(self, engagement_id: int, state: dict) -> Path:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        filepath = self.sessions_dir / f"{engagement_id}.json"
        state["saved_at"] = datetime.now(timezone.utc).isoformat()
        filepath.write_text(json.dumps(state, indent=2))
        logger.info("Session saved for engagement %d", engagement_id)
        return filepath

    def load(self, engagement_id: int) -> dict | None:
        filepath = self.sessions_dir / f"{engagement_id}.json"
        if not filepath.exists():
            return None
        try:
            return json.loads(filepath.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load session %d: %s", engagement_id, e)
            return None

    def delete(self, engagement_id: int) -> None:
        filepath = self.sessions_dir / f"{engagement_id}.json"
        if filepath.exists():
            filepath.unlink()
            logger.info("Session deleted for engagement %d", engagement_id)

    def list_sessions(self) -> list[dict]:
        if not self.sessions_dir.exists():
            return []
        sessions = []
        for filepath in sorted(self.sessions_dir.glob("*.json")):
            try:
                data = json.loads(filepath.read_text())
                sessions.append(data)
            except (json.JSONDecodeError, OSError):
                continue
        return sessions
