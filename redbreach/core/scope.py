import ipaddress
import json
import logging

logger = logging.getLogger("redbreach.scope")


def _split_patterns(patterns: list[str]) -> tuple[list[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Split raw scope patterns into (domain_patterns, ip_networks)."""
    domains: list[str] = []
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for pattern in patterns:
        p = pattern.strip().lower()
        if not p:
            continue
        try:
            networks.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            domains.append(p)
    return domains, networks


def _domain_match(target: str, pattern: str, subtree_bare: bool) -> bool:
    """Match a hostname against one domain pattern.

    ``*.base`` matches ``base`` and any subdomain of it.
    A bare host matches exactly, and also its whole subtree when
    ``subtree_bare`` is set (used for out-of-scope so excluding a host
    excludes everything under it).
    """
    if pattern.startswith("*."):
        base = pattern[2:]
        return target == base or target.endswith("." + base)
    if subtree_bare:
        return target == pattern or target.endswith("." + pattern)
    return target == pattern


class ScopeEnforcer:
    """Validates targets against engagement scope rules.

    In bounty mode, only explicitly in-scope targets are allowed.
    In private mode, everything is allowed (no restrictions).
    In pentest mode, same as bounty (scope-aware).

    Precedence is deny-wins: a target matching any out-of-scope rule is
    rejected even if it also matches an in-scope rule. Out-of-scope rules
    support the same wildcard and CIDR forms as in-scope rules, and a bare
    out-of-scope host excludes its entire subdomain subtree.
    """

    def __init__(self, scope_json: str, mode: str = "bounty"):
        self.mode = mode
        scope = json.loads(scope_json) if scope_json else {}
        self.in_scope_patterns: list[str] = scope.get("in_scope", [])
        self.out_of_scope_patterns: list[str] = scope.get("out_of_scope", [])

        self._in_scope_domains, self._in_scope_networks = _split_patterns(self.in_scope_patterns)
        self._out_of_scope_domains, self._out_of_scope_networks = _split_patterns(self.out_of_scope_patterns)

    def is_in_scope(self, target: str) -> bool:
        if self.mode == "private":
            return True

        target = target.strip().lower()

        ip = None
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            pass

        # Deny wins: any out-of-scope match rejects immediately.
        if ip is not None:
            if any(ip in net for net in self._out_of_scope_networks):
                logger.warning("Target %s is in an out-of-scope network", target)
                return False
        elif any(_domain_match(target, p, subtree_bare=True) for p in self._out_of_scope_domains):
            logger.warning("Target %s is explicitly out of scope", target)
            return False

        # In-scope match (bare hosts are exact only, never broadened).
        if ip is not None:
            return any(ip in net for net in self._in_scope_networks)
        return any(_domain_match(target, p, subtree_bare=False) for p in self._in_scope_domains)

    def filter_targets(self, targets: list[str]) -> list[str]:
        return [t for t in targets if self.is_in_scope(t)]
