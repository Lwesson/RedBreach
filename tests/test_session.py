import json
import pytest
from pathlib import Path

from redbreach.session import SessionManager


@pytest.fixture
def session_mgr(tmp_path):
    return SessionManager(tmp_path / "sessions")


def test_save_session(session_mgr):
    state = {"engagement_id": 1, "current_phase": 2, "completed_phases": [1], "assets_count": 15, "findings_count": 3}
    path = session_mgr.save(engagement_id=1, state=state)
    assert path.exists()
    loaded = json.loads(path.read_text())
    assert loaded["engagement_id"] == 1
    assert loaded["current_phase"] == 2


def test_load_session(session_mgr):
    state = {"engagement_id": 2, "current_phase": 3, "completed_phases": [1, 2]}
    session_mgr.save(engagement_id=2, state=state)
    loaded = session_mgr.load(engagement_id=2)
    assert loaded is not None
    assert loaded["current_phase"] == 3
    assert loaded["completed_phases"] == [1, 2]


def test_load_missing_session(session_mgr):
    assert session_mgr.load(engagement_id=999) is None


def test_delete_session(session_mgr):
    session_mgr.save(engagement_id=1, state={"engagement_id": 1})
    session_mgr.delete(engagement_id=1)
    assert session_mgr.load(engagement_id=1) is None


def test_list_sessions(session_mgr):
    session_mgr.save(1, {"engagement_id": 1})
    session_mgr.save(2, {"engagement_id": 2})
    sessions = session_mgr.list_sessions()
    assert len(sessions) == 2


def test_save_overwrites(session_mgr):
    session_mgr.save(1, {"phase": 2})
    session_mgr.save(1, {"phase": 4})
    loaded = session_mgr.load(1)
    assert loaded["phase"] == 4
