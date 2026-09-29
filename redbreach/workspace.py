"""Per-engagement workspace, each bounty/pentest gets its own directory."""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("redbreach.workspace")

WORKSPACE_SUBDIRS = ["evidence", "reports", "sessions", "notes"]


def slugify(text: str) -> str:
    """Convert text to a filesystem-safe slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"-+", "-", text)
    return text.strip("-")[:60]


class EngagementWorkspace:
    """Manages the directory structure for a single engagement."""

    def __init__(self, workspace_dir: Path) -> None:
        self.root = Path(workspace_dir)

    @classmethod
    def create(
        cls,
        engagements_dir: Path,
        engagement_id: int,
        target: str,
        eng_type: str,
        scope: dict | None = None,
    ) -> "EngagementWorkspace":
        """Create a new engagement workspace on disk."""
        slug = slugify(target)
        dir_name = f"ENG-{engagement_id:03d}-{slug}"
        workspace_dir = engagements_dir / dir_name

        workspace_dir.mkdir(parents=True, exist_ok=True)
        for subdir in WORKSPACE_SUBDIRS:
            (workspace_dir / subdir).mkdir(exist_ok=True)

        # Write scope file if provided
        if scope:
            scope_path = workspace_dir / "scope.json"
            scope_path.write_text(json.dumps(scope, indent=2))

        # Write metadata
        meta = {
            "engagement_id": engagement_id,
            "target": target,
            "type": eng_type,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        (workspace_dir / "meta.json").write_text(json.dumps(meta, indent=2))

        logger.info("Workspace created: %s", workspace_dir)
        return cls(workspace_dir)

    @classmethod
    def find(cls, engagements_dir: Path, engagement_id: int) -> "EngagementWorkspace | None":
        """Find an existing workspace by engagement ID."""
        if not engagements_dir.exists():
            return None
        prefix = f"ENG-{engagement_id:03d}-"
        for d in engagements_dir.iterdir():
            if d.is_dir() and d.name.startswith(prefix):
                return cls(d)
        return None

    @classmethod
    def list_all(cls, engagements_dir: Path) -> list["EngagementWorkspace"]:
        """List all engagement workspaces."""
        if not engagements_dir.exists():
            return []
        workspaces = []
        for d in sorted(engagements_dir.iterdir()):
            if d.is_dir() and d.name.startswith("ENG-"):
                workspaces.append(cls(d))
        return workspaces

    @property
    def evidence_dir(self) -> Path:
        return self.root / "evidence"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def sessions_dir(self) -> Path:
        return self.root / "sessions"

    @property
    def notes_dir(self) -> Path:
        return self.root / "notes"

    @property
    def scope_path(self) -> Path:
        return self.root / "scope.json"

    @property
    def meta_path(self) -> Path:
        return self.root / "meta.json"

    def load_scope(self) -> dict | None:
        """Load scope.json if it exists."""
        if self.scope_path.exists():
            return json.loads(self.scope_path.read_text())
        return None

    def load_meta(self) -> dict | None:
        """Load meta.json if it exists."""
        if self.meta_path.exists():
            return json.loads(self.meta_path.read_text())
        return None

    def save_scope(self, scope: dict) -> Path:
        """Save/update scope.json."""
        self.scope_path.write_text(json.dumps(scope, indent=2))
        return self.scope_path
