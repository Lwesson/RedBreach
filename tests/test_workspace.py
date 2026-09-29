import json
import pytest
from pathlib import Path

from redbreach.workspace import EngagementWorkspace, slugify


@pytest.fixture
def eng_dir(tmp_path):
    return tmp_path / "engagements"


def test_slugify():
    assert slugify("api.example.com") == "apiexamplecom"
    assert slugify("Hello World!") == "hello-world"
    assert slugify("*.example.org") == "exampleorg"


def test_create_workspace(eng_dir):
    ws = EngagementWorkspace.create(eng_dir, 1, "api.example.com", "bounty")
    assert ws.root.exists()
    assert ws.evidence_dir.exists()
    assert ws.reports_dir.exists()
    assert ws.sessions_dir.exists()
    assert ws.notes_dir.exists()
    assert ws.meta_path.exists()


def test_create_with_scope(eng_dir):
    scope = {"in_scope": ["*.example.com"], "out_of_scope": ["status.example.com"]}
    ws = EngagementWorkspace.create(eng_dir, 1, "example.com", "bounty", scope=scope)
    loaded = ws.load_scope()
    assert loaded["in_scope"] == ["*.example.com"]


def test_find_workspace(eng_dir):
    EngagementWorkspace.create(eng_dir, 1, "api.example.com", "bounty")
    ws = EngagementWorkspace.find(eng_dir, 1)
    assert ws is not None
    assert "ENG-001" in ws.root.name


def test_find_nonexistent(eng_dir):
    assert EngagementWorkspace.find(eng_dir, 999) is None


def test_list_all(eng_dir):
    EngagementWorkspace.create(eng_dir, 1, "api.example.com", "bounty")
    EngagementWorkspace.create(eng_dir, 2, "example.com", "pentest")
    workspaces = EngagementWorkspace.list_all(eng_dir)
    assert len(workspaces) == 2


def test_meta_content(eng_dir):
    ws = EngagementWorkspace.create(eng_dir, 5, "target.com", "private")
    meta = ws.load_meta()
    assert meta["engagement_id"] == 5
    assert meta["target"] == "target.com"
    assert meta["type"] == "private"


def test_save_scope(eng_dir):
    ws = EngagementWorkspace.create(eng_dir, 1, "example.com", "bounty")
    ws.save_scope({"in_scope": ["*.example.com", "api.example.com"]})
    loaded = ws.load_scope()
    assert len(loaded["in_scope"]) == 2


def test_dir_name_format(eng_dir):
    ws = EngagementWorkspace.create(eng_dir, 42, "api.example.com", "bounty")
    assert ws.root.name.startswith("ENG-042-")
