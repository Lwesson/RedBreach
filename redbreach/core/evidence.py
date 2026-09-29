import base64
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

logger = logging.getLogger("redbreach.evidence")

# Fixed application salt so the same passphrase derives the same key across
# sessions (evidence must stay decryptable later). The protection is PBKDF2's
# iteration cost against brute force plus a full 32 bytes of derived key
# material, not the old truncate-and-null-pad, which left a short passphrase as
# mostly null bytes. NOTE: files encrypted under the old scheme need re-encrypting.
_KDF_SALT = b"redbreach-evidence-v1"
_KDF_ITERATIONS = 200_000


def _derive_fernet_key(passphrase: str) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=_KDF_SALT, iterations=_KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


class EvidenceManager:
    """Manages raw tool output and evidence files on disk."""

    def __init__(self, base_dir: Path, encryption_key: str | None = None):
        self.base_dir = Path(base_dir)
        self._fernet = None
        if encryption_key and HAS_CRYPTO:
            self._fernet = Fernet(_derive_fernet_key(encryption_key))

    def save_tool_output(
        self, engagement_id: int, tool: str, stdout: str, stderr: str
    ) -> Path:
        logs_dir = self.base_dir / str(engagement_id) / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{tool}_{timestamp}.log"
        filepath = logs_dir / filename

        content = f"=== STDOUT ===\n{stdout}\n"
        if stderr:
            content += f"\n=== STDERR ===\n{stderr}\n"

        if self._fernet:
            filepath = filepath.with_suffix(".log.enc")
            filepath.write_bytes(self._fernet.encrypt(content.encode()))
        else:
            filepath.write_text(content)

        logger.debug("Evidence saved: %s", filepath)
        return filepath

    def decrypt_file(self, filepath: Path) -> str:
        """Decrypt an encrypted evidence file."""
        if not self._fernet:
            return filepath.read_text()
        return self._fernet.decrypt(filepath.read_bytes()).decode()

    def hash_file(self, filepath: Path) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def list_files(self, engagement_id: int) -> list[Path]:
        eng_dir = self.base_dir / str(engagement_id)
        if not eng_dir.exists():
            return []
        return sorted([p for p in eng_dir.rglob("*") if p.is_file()], key=lambda p: p.name)
