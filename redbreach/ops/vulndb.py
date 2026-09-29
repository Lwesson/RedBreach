"""Local vulnerability database cache."""
import json
from pathlib import Path

class VulnDBCache:
    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        self._data: dict[str, dict] = {}
        if self._path.exists():
            self._data = json.loads(self._path.read_text())

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(self._data, indent=2))

    def store(self, cve_id: str, entry: dict) -> None:
        self._data[cve_id] = entry
        self._save()

    def lookup(self, cve_id: str) -> dict | None:
        return self._data.get(cve_id)

    def search(self, keyword: str) -> list[dict]:
        keyword_lower = keyword.lower()
        return [e for e in self._data.values()
                if keyword_lower in f"{e.get('id', '')} {e.get('description', '')}".lower()]

    def stats(self) -> dict:
        return {"total": len(self._data)}

    def delete(self, cve_id: str) -> None:
        self._data.pop(cve_id, None)
        self._save()
