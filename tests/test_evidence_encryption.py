import pytest
from pathlib import Path

from redbreach.core.evidence import EvidenceManager


@pytest.fixture
def encrypted_mgr(tmp_path):
    return EvidenceManager(tmp_path / "evidence", encryption_key="test-secret-key-1234")


@pytest.fixture
def plain_mgr(tmp_path):
    return EvidenceManager(tmp_path / "evidence")


def test_encrypt_and_decrypt(encrypted_mgr):
    """Encrypted evidence can be decrypted back."""
    path = encrypted_mgr.save_tool_output(1, "nuclei", "SECRET DATA", "")
    content = path.read_bytes()
    # Encrypted content should NOT contain plaintext
    assert b"SECRET DATA" not in content

    # Decrypt should return original
    decrypted = encrypted_mgr.decrypt_file(path)
    assert "SECRET DATA" in decrypted


def test_unencrypted_saves_plaintext(plain_mgr):
    """Without encryption key, saves as plaintext."""
    path = plain_mgr.save_tool_output(1, "nuclei", "PLAIN DATA", "")
    content = path.read_text()
    assert "PLAIN DATA" in content


def test_hash_works_on_encrypted(encrypted_mgr):
    """Hash works on encrypted files."""
    path = encrypted_mgr.save_tool_output(1, "test", "data", "")
    file_hash = encrypted_mgr.hash_file(path)
    assert len(file_hash) == 64


def test_list_files_includes_encrypted(encrypted_mgr):
    encrypted_mgr.save_tool_output(1, "a", "data1", "")
    encrypted_mgr.save_tool_output(1, "b", "data2", "")
    files = encrypted_mgr.list_files(1)
    assert len(files) == 2


def test_short_passphrase_still_encrypts(tmp_path):
    # A short key used to be truncated + null-padded; the KDF now derives a full key.
    mgr = EvidenceManager(tmp_path / "ev", encryption_key="x")
    path = mgr.save_tool_output(1, "t", "SENSITIVE", "")
    assert b"SENSITIVE" not in path.read_bytes()
    assert "SENSITIVE" in mgr.decrypt_file(path)


def test_wrong_key_cannot_decrypt(tmp_path):
    from cryptography.fernet import InvalidToken
    a = EvidenceManager(tmp_path / "ev", encryption_key="key-alpha")
    path = a.save_tool_output(1, "t", "SENSITIVE", "")
    b = EvidenceManager(tmp_path / "ev", encryption_key="key-bravo")
    with pytest.raises(InvalidToken):
        b.decrypt_file(path)
