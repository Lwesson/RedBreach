"""Finding deduplication engine."""
from difflib import SequenceMatcher

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Hygiene findings are typically reported once for a site, so they may merge
# across different hosts/paths. Substantive findings on different endpoints are
# distinct and must NOT be merged (that would silently drop a real finding).
_HYGIENE_CATEGORIES = {"headers", "tls", "cookie-flags", "csp-unsafe-inline"}


def _norm_location(f: dict) -> str:
    """Normalized location (host+path, query/fragment stripped) for comparison."""
    loc = (f.get("matched_at") or f.get("host") or "").strip().lower()
    for sep in ("?", "#"):
        loc = loc.split(sep, 1)[0]
    return loc.rstrip("/")


def similarity_score(a: dict, b: dict) -> float:
    title_sim = SequenceMatcher(None, a.get("title", ""), b.get("title", "")).ratio()
    cat_match = 1.0 if a.get("category") == b.get("category") else 0.0
    sev_match = 1.0 if a.get("severity") == b.get("severity") else 0.0
    base = title_sim * 0.6 + cat_match * 0.25 + sev_match * 0.15

    # Same weakness on genuinely different endpoints is a separate finding.
    # Query-string differences (?q=1 vs ?q=2) normalize to the same location and
    # still merge; hygiene findings may merge across hosts.
    la, lb = _norm_location(a), _norm_location(b)
    if la and lb and la != lb and a.get("category") not in _HYGIENE_CATEGORIES:
        return min(0.5, base)
    return base


def deduplicate_findings(findings: list[dict], threshold: float = 0.85) -> list[dict]:
    if not findings:
        return []
    kept: list[dict] = []
    for finding in findings:
        merged = False
        for i, existing in enumerate(kept):
            if similarity_score(finding, existing) >= threshold:
                f_rank = _SEVERITY_RANK.get(finding.get("severity", ""), 0)
                e_rank = _SEVERITY_RANK.get(existing.get("severity", ""), 0)
                if f_rank > e_rank:
                    kept[i] = finding
                merged = True
                break
        if not merged:
            kept.append(finding)
    return kept
