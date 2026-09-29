import json
import pytest

from redbreach.core.scope import ScopeEnforcer


@pytest.fixture
def bounty_scope():
    scope = {
        "in_scope": ["*.example.com", "api.example.com", "10.0.0.0/24"],
        "out_of_scope": ["admin.example.com", "staging.example.com"],
    }
    return ScopeEnforcer(json.dumps(scope), mode="bounty")


@pytest.fixture
def private_scope():
    return ScopeEnforcer("{}", mode="private")


def test_in_scope_subdomain(bounty_scope):
    assert bounty_scope.is_in_scope("www.example.com") is True


def test_in_scope_exact(bounty_scope):
    assert bounty_scope.is_in_scope("api.example.com") is True


def test_out_of_scope_explicit(bounty_scope):
    assert bounty_scope.is_in_scope("admin.example.com") is False


def test_out_of_scope_unrelated(bounty_scope):
    assert bounty_scope.is_in_scope("evil.com") is False


def test_in_scope_ip_in_cidr(bounty_scope):
    assert bounty_scope.is_in_scope("10.0.0.5") is True


def test_out_of_scope_ip(bounty_scope):
    assert bounty_scope.is_in_scope("192.168.1.1") is False


def test_private_mode_allows_everything(private_scope):
    assert private_scope.is_in_scope("anything.com") is True
    assert private_scope.is_in_scope("10.0.0.1") is True


def test_filter_targets(bounty_scope):
    targets = ["www.example.com", "evil.com", "api.example.com", "admin.example.com"]
    filtered = bounty_scope.filter_targets(targets)
    assert filtered == ["www.example.com", "api.example.com"]


def test_empty_scope_bounty_rejects_all():
    enforcer = ScopeEnforcer("{}", mode="bounty")
    assert enforcer.is_in_scope("example.com") is False


def test_out_of_scope_subtree_beats_wildcard_in_scope(bounty_scope):
    # sub.admin.example.com matches in-scope *.example.com, but admin.example.com
    # is out of scope, so the whole subtree must be denied (deny-wins).
    assert bounty_scope.is_in_scope("sub.admin.example.com") is False
    assert bounty_scope.is_in_scope("deep.nested.staging.example.com") is False


def test_out_of_scope_wildcard_pattern():
    scope = {"in_scope": ["*.example.com"], "out_of_scope": ["*.internal.example.com"]}
    enforcer = ScopeEnforcer(json.dumps(scope), mode="bounty")
    assert enforcer.is_in_scope("app.example.com") is True
    assert enforcer.is_in_scope("db.internal.example.com") is False
    assert enforcer.is_in_scope("internal.example.com") is False


def test_out_of_scope_cidr():
    scope = {"in_scope": ["10.0.0.0/8"], "out_of_scope": ["10.1.2.0/24"]}
    enforcer = ScopeEnforcer(json.dumps(scope), mode="bounty")
    assert enforcer.is_in_scope("10.5.5.5") is True
    assert enforcer.is_in_scope("10.1.2.50") is False


def test_bare_in_scope_host_not_broadened():
    # A bare in-scope host must NOT pull its subdomains into scope.
    scope = {"in_scope": ["api.example.com"], "out_of_scope": []}
    enforcer = ScopeEnforcer(json.dumps(scope), mode="bounty")
    assert enforcer.is_in_scope("api.example.com") is True
    assert enforcer.is_in_scope("secret.api.example.com") is False
