import pytest
from pathlib import Path
from redbreach.ops.wordlists import WordlistManager

@pytest.fixture
def mgr(tmp_path):
    return WordlistManager(tmp_path / "wordlists")

def test_create_manager(mgr):
    assert mgr.base_dir.exists()

def test_add_wordlist(mgr):
    mgr.add("dirs", "admin\nbackup\nconfig\n")
    path = mgr.get_path("dirs")
    assert path.exists()
    assert "admin" in path.read_text()

def test_list_wordlists(mgr):
    mgr.add("dirs", "admin\nbackup\n")
    mgr.add("params", "id\npage\n")
    names = mgr.list_available()
    assert "dirs" in names
    assert "params" in names

def test_merge_wordlists(mgr):
    mgr.add("a", "apple\nbanana\n")
    mgr.add("b", "banana\ncherry\n")
    merged = mgr.merge(["a", "b"])
    assert len(merged) == 3
    assert "banana" in merged

def test_get_nonexistent(mgr):
    assert mgr.get_path("nope") is None

def test_delete_wordlist(mgr):
    mgr.add("temp", "data\n")
    mgr.delete("temp")
    assert mgr.get_path("temp") is None


def test_add_rejects_path_traversal(tmp_path):
    from redbreach.ops.wordlists import WordlistManager
    base = tmp_path / "wl"
    mgr = WordlistManager(base)
    path = mgr.add("../../evil", "secret")
    assert path.parent == base                 # stayed inside base_dir
    assert not (tmp_path / "evil.txt").exists()  # did not escape
    assert mgr.get_path("../../evil") == path    # same sanitized mapping
