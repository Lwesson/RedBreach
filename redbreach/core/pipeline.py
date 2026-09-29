import logging
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

logger = logging.getLogger("redbreach.pipeline")
console = Console()

# Asset types that resolve to a host we can scope-check. Others (e.g.
# "parameters") are not host-bound and are never scope-filtered.
_HOST_ASSET_TYPES = {"host", "subdomain", "domain", "url", "api_endpoint", "ip"}


def _asset_host(item: dict) -> str | None:
    """Extract a hostname/IP from an asset dict, or None if not host-bound."""
    if item.get("type") not in _HOST_ASSET_TYPES:
        return None
    value = (item.get("value") or "").strip()
    if not value:
        return None
    if "://" in value:
        return urlparse(value).hostname
    # bare host, host:port, or host/path
    return value.split("/", 1)[0].split(":", 1)[0] or None


def display_brief(brief: dict) -> None:
    """Display intelligence brief summary to console."""
    from rich.panel import Panel

    lines = []
    kev_hits = brief.get("kev_hits", [])
    if kev_hits:
        lines.append(f"[red bold]CISA KEV HITS ({len(kev_hits)}):[/red bold]")
        for hit in kev_hits[:5]:
            lines.append(f"  {hit['cve_id']}  CVSS:{hit.get('cvss_score', '?')}  {hit.get('description', '')[:80]}")

    high_value = brief.get("high_value", [])
    if high_value:
        lines.append(f"\n[yellow bold]HIGH-VALUE ({len(high_value)}):[/yellow bold]")
        for hv in high_value[:5]:
            lines.append(f"  {hv['cve_id']}  CVSS:{hv.get('cvss_score', '?')}  {hv.get('description', '')[:80]}")

    notable = brief.get("notable_no_poc", [])
    if notable:
        lines.append(f"\n[red]CRITICAL, NO PUBLIC PoC ({len(notable)}), manual targets:[/red]")
        for n in notable[:5]:
            lines.append(f"  {n['cve_id']}  CVSS:{n.get('cvss_score', '?')}  {(n.get('description') or '')[:80]}")

    tech = brief.get("tech_coverage", [])
    if tech:
        lines.append(f"\n[cyan]TECH COVERAGE:[/cyan]")
        for t in tech:
            lines.append(f"  {t['product']}  CVEs:{t['cve_count']}  PoCs:{t['poc_count']}  Nuclei:{t['nuclei_count']}")

    patterns = brief.get("cross_patterns", [])
    if patterns:
        lines.append(f"\n[magenta]CROSS-ENGAGEMENT PATTERNS ({len(patterns)}):[/magenta]")
        for p in patterns[:3]:
            lines.append(f"  {p.get('category', 'N/A')} on {p.get('target', '?')} (x{p.get('hit_count', 0)})")

    unmatched = brief.get("unmatched_tech", [])
    if unmatched:
        lines.append(f"\n[dim]UNMATCHED TECH: {', '.join(unmatched)}[/dim]")

    if lines:
        console.print(Panel("\n".join(lines), title="Intelligence Brief", border_style="cyan"))


class Pipeline:
    """Phase orchestrator, runs modules through the 7-phase pipeline.

    Functional phases: 1 (intelligence), 2 (recon), 3 (enumerate), 4 (scan),
    5 (suggest manual tests). When an AI client is supplied, findings are
    triaged automatically after phase 4 and phase 6 identifies vuln chains.
    Phase 7 (report generation) is per-finding via `redbreach report generate`.
    """

    def __init__(self, db, modules: list, auth_session=None, scope_enforcer=None, ai_client=None):
        self.db = db
        self.modules = modules
        self.auth_session = auth_session
        self.scope_enforcer = scope_enforcer
        self.ai_client = ai_client
        # Only filter when scope is actually configured. An empty in_scope in
        # bounty mode would otherwise reject every asset and silently run
        # nothing; instead we pass through and warn (see run_phase).
        self._scope_active = bool(
            scope_enforcer is not None
            and getattr(scope_enforcer, "mode", None) != "private"
            and getattr(scope_enforcer, "in_scope_patterns", None)
        )

    def _asset_allowed(self, item: dict) -> bool:
        """True unless scope is active and the asset's host is out of scope."""
        if not self._scope_active:
            return True
        host = _asset_host(item)
        if host is None:
            return True  # not host-bound (e.g. parameters), never blocked
        if self.scope_enforcer.is_in_scope(host):
            return True
        logger.warning(
            "SCOPE: skipping out-of-scope asset %s (%s), flagged, not probed",
            item.get("value"), item.get("type"),
        )
        return False

    async def run_phase(self, phase: int, engagement: dict) -> list[dict]:
        """Run a specific phase across all registered modules."""
        phase_methods = {
            2: "recon",
            3: "enumerate",
            4: "scan",
            5: "suggest_tests",
        }

        method_name = phase_methods.get(phase)
        if method_name is None:
            logger.warning("Phase %d not implemented yet", phase)
            return []

        all_results = []
        existing_assets = await self.db.get_assets(engagement["id"])

        if self._scope_active:
            before = len(existing_assets)
            existing_assets = [a for a in existing_assets if self._asset_allowed(a)]
            dropped = before - len(existing_assets)
            if dropped:
                logger.warning("SCOPE: withheld %d out-of-scope asset(s) from phase %d", dropped, phase)
        elif self.scope_enforcer is not None and getattr(self.scope_enforcer, "mode", None) != "private":
            logger.warning(
                "SCOPE: enforcer present but no in_scope patterns configured, "
                "scope filtering is OFF for this engagement"
            )

        for module in self.modules:
            method = getattr(module, method_name, None)
            if method is None:
                continue

            try:
                logger.info("Phase %d: running %s.%s", phase, module.name, method_name)
                results = await method(engagement, existing_assets)

                # Store discovered assets / findings (recon phase)
                if method_name == "recon":
                    for item in results:
                        if item.get("type") == "finding":
                            await self.db.create_finding(
                                engagement_id=engagement["id"],
                                asset_id=None,
                                title=item.get("title", "Untitled"),
                                severity=item.get("severity", "info"),
                                category=item.get("category"),
                                description=item.get("description"),
                                steps_to_reproduce=f"Host: {item.get('host', 'N/A')}",
                                poc_text=str(item.get("evidence", "")),
                                impact=None,
                                recommended_fix=None,
                            )
                        elif self._asset_allowed(item):
                            await self.db.create_asset(
                                engagement_id=engagement["id"],
                                asset_type=item.get("type", "unknown"),
                                value=item["value"],
                                tech_stack_json=str(item.get("tech", "{}")),
                                notes=item.get("notes"),
                            )

                # Store enumerated assets / findings (enumerate phase)
                if method_name == "enumerate":
                    for item in results:
                        if item.get("type") == "finding":
                            await self.db.create_finding(
                                engagement_id=engagement["id"],
                                asset_id=None,
                                title=item.get("title", "Untitled"),
                                severity=item.get("severity", "info"),
                                category=item.get("category"),
                                description=item.get("description"),
                                steps_to_reproduce=f"Host: {item.get('host', 'N/A')}",
                                poc_text=str(item.get("evidence", "")),
                                impact=None,
                                recommended_fix=None,
                            )
                        elif (item.get("type") in ("api_endpoint", "parameters", "host", "url")
                              and self._asset_allowed(item)):
                            await self.db.create_asset(
                                engagement_id=engagement["id"],
                                asset_type=item.get("type", "unknown"),
                                value=item.get("value", ""),
                                tech_stack_json=str(item.get("tech", item.get("methods", "{}"))),
                                notes=item.get("source"),
                            )

                # Store findings from scan phase
                if method_name == "scan":
                    for finding in results:
                        if finding.get("type") == "finding":
                            await self.db.create_finding(
                                engagement_id=engagement["id"],
                                asset_id=None,
                                title=finding.get("title", "Untitled"),
                                severity=finding.get("severity", "info"),
                                category=finding.get("template_id") or finding.get("category"),
                                description=finding.get("reasoning") or finding.get("description"),
                                steps_to_reproduce=f"Matched at: {finding.get('matched_at', 'N/A')}",
                                poc_text=str(finding.get("extracted_results", "")),
                                impact=None,
                                recommended_fix=None,
                            )

                # Store suggestions as findings (suggest_tests phase)
                if method_name == "suggest_tests":
                    for suggestion in results:
                        if suggestion.get("type") == "suggested_test":
                            await self.db.create_finding(
                                engagement_id=engagement["id"],
                                asset_id=None,
                                title=suggestion.get("description", "Manual test suggestion"),
                                severity="info",
                                category=suggestion.get("category", "manual_test"),
                                description=f"Suggested manual test. Context: {suggestion.get('context', 'N/A')}",
                            )

                all_results.extend(results)
                logger.info(
                    "Phase %d: %s.%s returned %d results",
                    phase, module.name, method_name, len(results),
                )

            except Exception as e:
                logger.error(
                    "Phase %d: %s.%s failed: %s", phase, module.name, method_name, e
                )
                continue

        # After scanning, triage findings so false positives are filtered before
        # they ever reach a report (serves the "quality only, never volume" rule).
        if method_name == "scan" and self.ai_client is not None:
            await self._triage_findings(engagement)

        return all_results

    async def run(self, engagement: dict, phases: list[int] | None = None) -> None:
        """Run multiple phases sequentially."""
        if phases is None:
            phases = [1, 2, 3, 4, 5]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Phase 1: Intelligence (standalone, not per-module)
            if 1 in phases:
                task = progress.add_task("Phase 1: Intelligence...", total=None)
                try:
                    from redbreach.intel.brief import BriefGenerator
                    gen = BriefGenerator(self.db)
                    brief = await gen.generate(engagement["id"], save=True)
                    kev_count = len(brief.get("kev_hits", []))
                    hv_count = len(brief.get("high_value", []))
                    progress.update(task, description=f"Phase 1: {kev_count} KEV hits, {hv_count} high-value CVEs")
                    display_brief(brief)
                except Exception as e:
                    logger.error("Phase 1 failed: %s", e)
                    progress.update(task, description="Phase 1: failed")
                progress.remove_task(task)

            # Phases 2-5: Module loop (existing behavior)
            for phase in phases:
                if phase < 2:
                    continue
                task = progress.add_task(f"Phase {phase}...", total=None)
                results = await self.run_phase(phase, engagement)
                progress.update(task, description=f"Phase {phase}: {len(results)} results")
                progress.remove_task(task)

        # Phase 6: Chaining (outside module loop, uses AI engine directly)
        if 6 in phases:
            if self.ai_client is not None:
                created = await self._run_chaining(engagement)
                console.print(f"[cyan]Phase 6:[/cyan] {created} vulnerability chain(s) identified")
            else:
                logger.info("Phase 6 (chaining) skipped: no AI client configured")

        # Phase 7: Reporting is per-finding via `redbreach report generate`.
        if 7 in phases:
            logger.info("Phase 7: use `redbreach report generate <finding_id>` per finding")

        console.print(f"[green]Pipeline complete for {engagement['target']}[/green]")

    # ── AI post-processing ───────────────────────────────────────────

    def _engagement_context(self, engagement: dict) -> str:
        return f"{engagement.get('type', 'bounty')} engagement on {engagement.get('target', '?')}"

    async def _triage_findings(self, engagement: dict) -> None:
        """Run AI triage on untriaged findings and persist verdicts."""
        from redbreach.ai.triage import TriageEngine

        findings = await self.db.get_findings(engagement["id"])
        untriaged = [
            f for f in findings
            if f.get("confidence") is None
            and f.get("status") not in ("false_positive", "rejected")
        ]
        if not untriaged:
            return

        engine = TriageEngine(self.ai_client)
        try:
            results = await engine.triage(untriaged, self._engagement_context(engagement))
        except Exception as e:
            logger.error("Triage failed: %s", e)
            return

        fp = 0
        for r in results:
            if 0 <= r.finding_index < len(untriaged):
                await self.db.set_triage_result(
                    untriaged[r.finding_index]["id"],
                    r.is_false_positive, r.confidence, r.priority, r.reasoning,
                )
                fp += int(r.is_false_positive)
        logger.info("Triage: %d finding(s), %d flagged false-positive", len(results), fp)

    async def _run_chaining(self, engagement: dict) -> int:
        """Identify vuln chains among real findings; persist as parent findings."""
        from redbreach.ai.chaining import ChainingEngine

        _VALID_SEV = {"info", "low", "medium", "high", "critical"}
        findings = await self.db.get_findings(engagement["id"])
        candidates = [
            f for f in findings
            if f.get("status") not in ("false_positive", "rejected")
            and f.get("chain_parent_id") is None
            and f.get("category") != "vuln_chain"  # don't chain existing chains
        ]
        if len(candidates) < 2:
            return 0

        engine = ChainingEngine(self.ai_client)
        try:
            chains = await engine.identify_chains(candidates, self._engagement_context(engagement))
        except Exception as e:
            logger.error("Chaining failed: %s", e)
            return 0

        created = 0
        for chain in chains:
            member_ids = [
                candidates[i]["id"] for i in chain.finding_ids
                if isinstance(i, int) and 0 <= i < len(candidates)
            ]
            if len(member_ids) < 2:
                continue
            sev = (chain.combined_severity or "high").lower().strip()
            if sev not in _VALID_SEV:
                sev = "high"
            desc = chain.business_impact or chain.attack_path
            if chain.cvss_override is not None:
                desc = f"{desc}\n\nEstimated chain CVSS: {chain.cvss_override}"
            parent_id = await self.db.create_finding(
                engagement_id=engagement["id"],
                asset_id=None,
                title=f"[CHAIN] {chain.attack_path}",
                severity=sev,
                category="vuln_chain",
                description=desc,
                impact=chain.business_impact,
            )
            await self.db.link_chain(parent_id, member_ids)
            created += 1
            logger.info("Chain created: %s (%s, %d members)", chain.attack_path, sev, len(member_ids))
        return created
