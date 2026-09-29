"""Authenticated HTTP session support for redbreach's scanning and verification pipeline.

Provides persistent cookie jars, bearer/API-key auth, user-agent rotation,
multi-profile IDOR testing, and login/token-refresh flows, all built on
httpx async.
"""

from __future__ import annotations

import json
import logging
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("redbreach.core.auth")

# ---------------------------------------------------------------------------
# Real browser User-Agent strings, rotated per-client to reduce fingerprinting
# ---------------------------------------------------------------------------
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


# ---------------------------------------------------------------------------
# AuthType enum
# ---------------------------------------------------------------------------
class AuthType(str, Enum):
    NONE = "none"
    COOKIE = "cookie"
    BEARER = "bearer"
    API_KEY = "api_key"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# AuthConfig, per-engagement auth settings
# ---------------------------------------------------------------------------
@dataclass
class AuthConfig:
    """Authentication configuration for a single engagement profile."""

    auth_type: AuthType = AuthType.NONE
    token: str | None = None
    header_name: str = "Authorization"
    cookies: dict[str, str] = field(default_factory=dict)
    cookie_file: str | None = None
    custom_headers: dict[str, str] = field(default_factory=dict)
    login_url: str | None = None
    login_payload: dict[str, str] = field(default_factory=dict)
    token_refresh_url: str | None = None

    # ---- serialization ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "auth_type": self.auth_type.value,
            "token": self.token,
            "header_name": self.header_name,
            "cookies": self.cookies,
            "cookie_file": self.cookie_file,
            "custom_headers": self.custom_headers,
            "login_url": self.login_url,
            "login_payload": self.login_payload,
            "token_refresh_url": self.token_refresh_url,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthConfig:
        raw_type = data.get("auth_type", "none")
        try:
            auth_type = AuthType(raw_type)
        except ValueError:
            logger.warning("Unknown auth_type '%s', falling back to none", raw_type)
            auth_type = AuthType.NONE
        return cls(
            auth_type=auth_type,
            token=data.get("token"),
            header_name=data.get("header_name", "Authorization"),
            cookies=data.get("cookies", {}),
            cookie_file=data.get("cookie_file"),
            custom_headers=data.get("custom_headers", {}),
            login_url=data.get("login_url"),
            login_payload=data.get("login_payload", {}),
            token_refresh_url=data.get("token_refresh_url"),
        )


# ---------------------------------------------------------------------------
# AuthProfile, named config + runtime state for one user identity
# ---------------------------------------------------------------------------
@dataclass
class AuthProfile:
    """A named auth identity (for multi-user IDOR testing)."""

    name: str
    config: AuthConfig
    cookies: httpx.Cookies = field(default_factory=httpx.Cookies)
    _last_login: float = 0.0


def summarize_idor_diff(ra: dict[str, Any], rb: dict[str, Any]) -> dict[str, Any]:
    """Compare two response summaries and decide whether B's result looks like IDOR.

    A credible IDOR signal is: profile B (who should NOT have access) received the
    same body as resource owner A *and* a success (2xx) status. Identical error
    responses (both 404/403/401) are expected, not a finding, and must not be
    flagged, otherwise every missing resource reads as an IDOR false positive.
    """
    if "error" in ra or "error" in rb:
        return {"error": "One or both requests failed"}
    same_status = ra["status_code"] == rb["status_code"]
    same_body = ra["body_preview"] == rb["body_preview"]
    b_success = 200 <= rb["status_code"] < 300
    return {
        "same_status": same_status,
        "same_body_length": ra["body_length"] == rb["body_length"],
        "same_body": same_body,
        "status_a": ra["status_code"],
        "status_b": rb["status_code"],
        "length_a": ra["body_length"],
        "length_b": rb["body_length"],
        "b_success": b_success,
        "possible_idor": same_status and same_body and b_success,
    }


# ---------------------------------------------------------------------------
# AuthSession, the main interface
# ---------------------------------------------------------------------------
class AuthSession:
    """Wraps httpx.AsyncClient with persistent auth state and multi-profile support.

    Usage::

        cfg = AuthConfig(auth_type=AuthType.BEARER, token="eyJ...")
        session = AuthSession(timeout=15)
        session.add_profile("admin", cfg)
        session.set_active_profile("admin")

        async with await session.create_client() as client:
            resp = await client.get("https://target.example.com/api/me")
    """

    def __init__(self, timeout: int = 15, rotate_ua: bool = True) -> None:
        self.timeout = timeout
        self.rotate_ua = rotate_ua
        self._profiles: dict[str, AuthProfile] = {}
        self._active_profile: str | None = None

    # ---- profile management -----------------------------------------------
    def add_profile(self, name: str, config: AuthConfig) -> None:
        """Register a named auth profile."""
        profile = AuthProfile(name=name, config=config)
        # Pre-load cookies from config dict
        for k, v in config.cookies.items():
            profile.cookies.set(k, v)
        # Pre-load cookies from file if specified
        if config.cookie_file:
            try:
                self._load_cookies_from_file(profile, config.cookie_file)
            except Exception as exc:
                logger.warning("Failed to load cookie file for profile '%s': %s", name, exc)
        self._profiles[name] = profile
        # Auto-activate if this is the first profile
        if self._active_profile is None:
            self._active_profile = name
        logger.debug("Added auth profile '%s' (type=%s)", name, config.auth_type.value)

    def set_active_profile(self, name: str) -> None:
        """Switch the active auth profile."""
        if name not in self._profiles:
            raise KeyError(f"Auth profile '{name}' not found. Available: {list(self._profiles)}")
        self._active_profile = name
        logger.info("Switched active auth profile to '%s'", name)

    def get_profile(self, name: str | None = None) -> AuthProfile:
        """Return the named profile or the active one."""
        target = name or self._active_profile
        if target is None:
            raise RuntimeError("No auth profiles configured")
        if target not in self._profiles:
            raise KeyError(f"Auth profile '{target}' not found")
        return self._profiles[target]

    @property
    def profile_names(self) -> list[str]:
        return list(self._profiles)

    # ---- header assembly --------------------------------------------------
    def get_headers(self, profile_name: str | None = None) -> dict[str, str]:
        """Build the full header dict for the given (or active) profile."""
        profile = self.get_profile(profile_name)
        cfg = profile.config
        headers: dict[str, str] = {}

        # User-Agent
        if self.rotate_ua:
            headers["User-Agent"] = random.choice(_USER_AGENTS)

        # Auth-specific headers
        if cfg.auth_type == AuthType.BEARER and cfg.token:
            headers["Authorization"] = f"Bearer {cfg.token}"
        elif cfg.auth_type == AuthType.API_KEY and cfg.token:
            headers[cfg.header_name] = cfg.token
        elif cfg.auth_type == AuthType.CUSTOM and cfg.token:
            headers[cfg.header_name] = cfg.token

        # Merge custom headers (these win over auth defaults)
        headers.update(cfg.custom_headers)
        return headers

    # ---- client factory ---------------------------------------------------
    async def create_client(self, profile_name: str | None = None) -> httpx.AsyncClient:
        """Build a configured httpx.AsyncClient with auth headers and cookies.

        The caller is responsible for closing the client (use ``async with``).
        """
        profile = self.get_profile(profile_name)
        headers = self.get_headers(profile_name)
        client = httpx.AsyncClient(
            headers=headers,
            cookies=profile.cookies,
            verify=False,
            timeout=self.timeout,
            follow_redirects=True,
        )
        logger.debug(
            "Created httpx client for profile '%s' (type=%s, cookies=%d)",
            profile.name,
            profile.config.auth_type.value,
            len(profile.cookies),
        )
        return client

    # ---- login flow -------------------------------------------------------
    async def login(
        self,
        url: str | None = None,
        payload: dict[str, str] | None = None,
        profile_name: str | None = None,
    ) -> bool:
        """POST credentials to a login endpoint and capture session cookies.

        Uses ``login_url`` / ``login_payload`` from the profile config as
        defaults; explicit arguments override them.

        Returns True if the server responded with a 2xx/3xx status.
        """
        profile = self.get_profile(profile_name)
        cfg = profile.config
        target_url = url or cfg.login_url
        target_payload = payload or cfg.login_payload

        if not target_url:
            logger.error("No login URL provided for profile '%s'", profile.name)
            return False
        if not target_payload:
            logger.error("No login payload provided for profile '%s'", profile.name)
            return False

        logger.info("Attempting login for profile '%s' at %s", profile.name, target_url)
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                follow_redirects=True,
            ) as client:
                headers = self.get_headers(profile_name)
                resp = await client.post(target_url, data=target_payload, headers=headers)

                # Capture all cookies from the response
                for name, value in resp.cookies.items():
                    profile.cookies.set(name, value)

                # Also capture Set-Cookie headers that httpx may have followed through redirects
                profile._last_login = time.time()

                if resp.is_success or resp.is_redirect:
                    logger.info(
                        "Login succeeded for '%s', status %d, captured %d cookies",
                        profile.name,
                        resp.status_code,
                        len(resp.cookies),
                    )
                    return True
                else:
                    logger.warning(
                        "Login returned %d for '%s' at %s",
                        resp.status_code,
                        profile.name,
                        target_url,
                    )
                    return False
        except Exception as exc:
            logger.error("Login failed for '%s': %s", profile.name, exc)
            return False

    # ---- token refresh ----------------------------------------------------
    async def refresh_token(self, profile_name: str | None = None) -> bool:
        """Call the token refresh endpoint and update the stored token.

        Expects a JSON response with a ``token``, ``access_token``, or
        ``id_token`` field.
        """
        profile = self.get_profile(profile_name)
        cfg = profile.config
        if not cfg.token_refresh_url:
            logger.error("No token_refresh_url for profile '%s'", profile.name)
            return False

        logger.info("Refreshing token for profile '%s'", profile.name)
        try:
            async with await self.create_client(profile_name) as client:
                resp = await client.post(cfg.token_refresh_url)
                if not resp.is_success:
                    logger.warning("Token refresh returned %d for '%s'", resp.status_code, profile.name)
                    return False

                data = resp.json()
                new_token = (
                    data.get("token")
                    or data.get("access_token")
                    or data.get("id_token")
                )
                if not new_token:
                    logger.warning("Token refresh response missing token field for '%s'", profile.name)
                    return False

                cfg.token = new_token
                logger.info("Token refreshed for '%s'", profile.name)
                return True
        except Exception as exc:
            logger.error("Token refresh failed for '%s': %s", profile.name, exc)
            return False

    # ---- cookie persistence -----------------------------------------------
    def save_cookies(self, path: str | Path, profile_name: str | None = None) -> None:
        """Persist the profile's cookies to a JSON file."""
        profile = self.get_profile(profile_name)
        cookie_path = Path(path)
        cookie_path.parent.mkdir(parents=True, exist_ok=True)

        jar_dict: dict[str, str] = {}
        for name, value in profile.cookies.items():
            jar_dict[name] = value

        cookie_path.write_text(json.dumps(jar_dict, indent=2), encoding="utf-8")
        logger.info("Saved %d cookies to %s for profile '%s'", len(jar_dict), cookie_path, profile.name)

    def load_cookies(self, path: str | Path, profile_name: str | None = None) -> None:
        """Load cookies from a JSON file into the profile."""
        profile = self.get_profile(profile_name)
        self._load_cookies_from_file(profile, str(path))

    @staticmethod
    def _load_cookies_from_file(profile: AuthProfile, path: str) -> None:
        cookie_path = Path(path)
        if not cookie_path.exists():
            logger.debug("Cookie file %s does not exist, skipping", cookie_path)
            return
        data = json.loads(cookie_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Cookie file must contain a JSON object, got {type(data).__name__}")
        count = 0
        for name, value in data.items():
            profile.cookies.set(name, str(value))
            count += 1
        logger.info("Loaded %d cookies from %s for profile '%s'", count, cookie_path, profile.name)

    # ---- IDOR / multi-profile comparison ----------------------------------
    async def compare_profiles(
        self,
        method: str,
        url: str,
        profile_a: str,
        profile_b: str,
        *,
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send the same request as two different profiles and compare results.

        Returns a dict with both responses and a diff summary, useful for
        detecting IDOR and privilege escalation.
        """
        if profile_a not in self._profiles:
            raise KeyError(f"Profile '{profile_a}' not found")
        if profile_b not in self._profiles:
            raise KeyError(f"Profile '{profile_b}' not found")

        results: dict[str, Any] = {
            "url": url,
            "method": method,
            "profile_a": profile_a,
            "profile_b": profile_b,
        }

        for label, pname in [("response_a", profile_a), ("response_b", profile_b)]:
            try:
                async with await self.create_client(pname) as client:
                    kwargs: dict[str, Any] = {}
                    if body is not None:
                        kwargs["content"] = body
                    if headers:
                        kwargs["headers"] = headers
                    resp = await client.request(method, url, **kwargs)
                    results[label] = {
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "body_length": len(resp.content),
                        "body_preview": resp.text[:2000],
                    }
            except Exception as exc:
                logger.error("Request as '%s' failed: %s", pname, exc)
                results[label] = {"error": str(exc)}

        # Build a quick diff summary (success-gated so identical errors are not IDOR)
        results["diff"] = summarize_idor_diff(
            results.get("response_a", {}), results.get("response_b", {})
        )
        if results["diff"].get("possible_idor"):
            logger.warning(
                "Possible IDOR: %s %s returned identical 2xx responses for '%s' and '%s'",
                method, url, profile_a, profile_b,
            )

        return results
