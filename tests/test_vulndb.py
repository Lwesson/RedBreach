import pytest
from redbreach.ops.vulndb import VulnDBCache

@pytest.fixture
def cache(tmp_path):
    return VulnDBCache(tmp_path / "vulndb.json")

def test_empty_cache(cache):
    assert cache.lookup("CVE-2024-0001") is None

def test_store_and_lookup(cache):
    cache.store("CVE-2024-0001", {"id": "CVE-2024-0001", "severity": "critical", "description": "RCE in example", "cvss": 9.8})
    entry = cache.lookup("CVE-2024-0001")
    assert entry is not None
    assert entry["severity"] == "critical"

def test_persistence(tmp_path):
    path = tmp_path / "vulndb.json"
    cache1 = VulnDBCache(path)
    cache1.store("CVE-2024-0002", {"id": "CVE-2024-0002", "severity": "high"})
    cache2 = VulnDBCache(path)
    assert cache2.lookup("CVE-2024-0002") is not None

def test_search_by_keyword(cache):
    cache.store("CVE-2024-0001", {"id": "CVE-2024-0001", "description": "SQL injection in login"})
    cache.store("CVE-2024-0002", {"id": "CVE-2024-0002", "description": "XSS in search"})
    results = cache.search("SQL")
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2024-0001"

def test_stats(cache):
    cache.store("CVE-2024-0001", {"id": "CVE-2024-0001", "severity": "high"})
    cache.store("CVE-2024-0002", {"id": "CVE-2024-0002", "severity": "critical"})
    assert cache.stats()["total"] == 2

def test_delete(cache):
    cache.store("CVE-2024-0001", {"id": "CVE-2024-0001"})
    cache.delete("CVE-2024-0001")
    assert cache.lookup("CVE-2024-0001") is None
