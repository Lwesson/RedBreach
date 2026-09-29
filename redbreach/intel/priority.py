"""Priority stack scoring engine."""

from __future__ import annotations


class PriorityScorer:
    """Scores CVEs and targets for attack prioritization."""

    WEIGHT_KEV = 100
    WEIGHT_POC = 50
    WEIGHT_CROSS_ENGAGEMENT = 30
    WEIGHT_FRESH_SCOPE = 20
    WEIGHT_EPSS_MAX = 15
    WEIGHT_CVSS_MAX = 10

    PENALTY_HEAVILY_RESEARCHED = -20
    PENALTY_WAF = -10
    PENALTY_RATE_LIMITED = -10

    def score_cve(
        self,
        cve: dict,
        has_poc: bool = False,
        cross_engagement_hit: bool = False,
    ) -> float:
        """Score an individual CVE based on exploitability signals."""
        score = 0.0
        if cve.get("kev_known_exploited"):
            score += self.WEIGHT_KEV
        if has_poc:
            score += self.WEIGHT_POC
        if cross_engagement_hit:
            score += self.WEIGHT_CROSS_ENGAGEMENT
        score += (cve.get("epss_score") or 0) * self.WEIGHT_EPSS_MAX
        score += ((cve.get("cvss_score") or 0) / 10) * self.WEIGHT_CVSS_MAX
        return score

    def score_target(
        self,
        matching_cves: list[dict] | None = None,
        has_pocs: bool = False,
        cross_engagement_hit: bool = False,
        scope_age_days: int | None = None,
        waf_detected: bool = False,
        rate_limited: bool = False,
        heavily_researched: bool = False,
    ) -> float:
        """Score a target asset combining CVE, recon, and environmental signals."""
        score = 0.0

        if matching_cves:
            score += max(
                self.score_cve(c, has_poc=has_pocs, cross_engagement_hit=cross_engagement_hit)
                for c in matching_cves
            )
        else:
            if has_pocs:
                score += self.WEIGHT_POC
            if cross_engagement_hit:
                score += self.WEIGHT_CROSS_ENGAGEMENT

        if scope_age_days is not None and scope_age_days <= 60:
            score += self.WEIGHT_FRESH_SCOPE

        if heavily_researched:
            score += self.PENALTY_HEAVILY_RESEARCHED
        if waf_detected:
            score += self.PENALTY_WAF
        if rate_limited:
            score += self.PENALTY_RATE_LIMITED

        return max(score, 0)
