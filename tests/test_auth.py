from redbreach.core.auth import (
    AuthConfig,
    AuthSession,
    AuthType,
    summarize_idor_diff,
)


def _resp(status, body='{"id":1}', length=100):
    return {"status_code": status, "body_preview": body, "body_length": length}


# ── IDOR diff heuristic (the false-positive fix) ─────────────────────

def test_identical_2xx_responses_flag_idor():
    diff = summarize_idor_diff(_resp(200), _resp(200))
    assert diff["possible_idor"] is True


def test_identical_404_responses_are_not_idor():
    # Both users getting "not found" is expected, not a finding.
    diff = summarize_idor_diff(_resp(404, body="Not Found"), _resp(404, body="Not Found"))
    assert diff["possible_idor"] is False


def test_identical_403_responses_are_not_idor():
    diff = summarize_idor_diff(_resp(403, body="Forbidden"), _resp(403, body="Forbidden"))
    assert diff["possible_idor"] is False


def test_different_bodies_are_not_idor():
    diff = summarize_idor_diff(_resp(200, body='{"id":1}'), _resp(200, body='{"id":2}'))
    assert diff["possible_idor"] is False


def test_b_denied_is_not_idor():
    # A sees the resource (200) but B is correctly denied (403), no IDOR.
    diff = summarize_idor_diff(_resp(200), _resp(403, body="Forbidden"))
    assert diff["possible_idor"] is False


def test_error_response_returns_error_diff():
    assert summarize_idor_diff({"error": "boom"}, _resp(200)) == {"error": "One or both requests failed"}


# ── header assembly ──────────────────────────────────────────────────

def test_bearer_header():
    s = AuthSession(rotate_ua=False)
    s.add_profile("u", AuthConfig(auth_type=AuthType.BEARER, token="abc"))
    assert s.get_headers("u")["Authorization"] == "Bearer abc"


def test_api_key_header_uses_custom_name():
    s = AuthSession(rotate_ua=False)
    s.add_profile("u", AuthConfig(auth_type=AuthType.API_KEY, token="k", header_name="X-API-Key"))
    assert s.get_headers("u")["X-API-Key"] == "k"


def test_custom_headers_win_over_defaults():
    s = AuthSession(rotate_ua=False)
    s.add_profile("u", AuthConfig(auth_type=AuthType.BEARER, token="abc",
                                  custom_headers={"Authorization": "Bearer override"}))
    assert s.get_headers("u")["Authorization"] == "Bearer override"
