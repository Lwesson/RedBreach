import pytest
from pathlib import Path

from redbreach.core.evidence import EvidenceManager


@pytest.fixture
def evidence_mgr(tmp_path):
    return EvidenceManager(tmp_path / "evidence")


def test_save_tool_output(evidence_mgr):
    path = evidence_mgr.save_tool_output(
        engagement_id=1, tool="nuclei",
        stdout="[critical] CVE-2024-1234 found", stderr="",
    )
    assert path.exists()
    assert "nuclei" in path.name
    content = path.read_text()
    assert "CVE-2024-1234" in content


def test_save_tool_output_creates_dirs(evidence_mgr):
    path = evidence_mgr.save_tool_output(
        engagement_id=42, tool="ffuf", stdout="results", stderr="",
    )
    assert "42" in str(path.parent)
    assert path.exists()


def test_hash_file(evidence_mgr):
    path = evidence_mgr.save_tool_output(
        engagement_id=1, tool="test", stdout="hello", stderr=""
    )
    file_hash = evidence_mgr.hash_file(path)
    assert len(file_hash) == 64


def test_list_evidence_for_engagement(evidence_mgr):
    evidence_mgr.save_tool_output(1, "nuclei", "out1", "")
    evidence_mgr.save_tool_output(1, "ffuf", "out2", "")
    evidence_mgr.save_tool_output(2, "nuclei", "out3", "")
    files = evidence_mgr.list_files(engagement_id=1)
    assert len(files) == 2


def test_save_returns_absolute_path(evidence_mgr):
    path = evidence_mgr.save_tool_output(1, "nuclei", "out", "")
    assert path.is_absolute() or str(evidence_mgr.base_dir) in str(path)
