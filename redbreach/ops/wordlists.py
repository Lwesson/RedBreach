"""Wordlist management, store, merge, and retrieve wordlists."""
from pathlib import Path

class WordlistManager:
    def __init__(self, base_dir: Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _safe_path(self, name: str) -> Path:
        """Resolve a wordlist name to a path INSIDE base_dir, stripping any
        directory components so a name like '../../etc/x' cannot escape."""
        safe = Path(name).name
        return self.base_dir / f"{safe}.txt"

    def add(self, name: str, content: str) -> Path:
        path = self._safe_path(name)
        path.write_text(content)
        return path

    def get_path(self, name: str) -> Path | None:
        path = self._safe_path(name)
        return path if path.exists() else None

    def list_available(self) -> list[str]:
        return sorted(p.stem for p in self.base_dir.glob("*.txt"))

    def merge(self, names: list[str]) -> list[str]:
        seen = set()
        result = []
        for name in names:
            path = self.get_path(name)
            if path:
                for line in path.read_text().strip().splitlines():
                    word = line.strip()
                    if word and word not in seen:
                        seen.add(word)
                        result.append(word)
        return result

    def delete(self, name: str) -> None:
        path = self._safe_path(name)
        if path.exists():
            path.unlink()
