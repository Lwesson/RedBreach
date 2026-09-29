import asyncio
import logging
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

import redbreach
from redbreach.config import load_config
from redbreach.db import Database
from redbreach.log import setup_logging

console = Console()
DEFAULT_DATA_DIR = Path.home() / ".redbreach"


@click.group()
@click.version_option(version=redbreach.__version__, prog_name="redbreach")
@click.option("--data-dir", type=click.Path(), default=str(DEFAULT_DATA_DIR), help="Data directory")
@click.pass_context
def main(ctx, data_dir):
    """RedBreach: Full-spectrum security testing platform."""
    ctx.ensure_object(dict)
    ctx.obj["data_dir"] = Path(data_dir)


@main.command()
@click.pass_context
def new(ctx):
    """Create a new engagement via interactive wizard."""
    from redbreach.wizard import build_engagement_params

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)
    setup_logging(data_dir)

    params = build_engagement_params()

    async def _create():
        db = Database(str(cfg.db_path))
        await db.initialize()
        eng_id = await db.create_engagement(
            eng_type=params["type"],
            platform=params["platform"],
            target=params["target"],
            scope_json=params["scope_json"],
        )
        await db.close()
        return eng_id

    eng_id = asyncio.run(_create())

    from redbreach.workspace import EngagementWorkspace
    import json as _json

    # Load scope file if provided in params, or create empty scope
    scope_data = _json.loads(params["scope_json"]) if params["scope_json"] != "{}" else None

    ws = EngagementWorkspace.create(
        engagements_dir=cfg.engagements_dir,
        engagement_id=eng_id,
        target=params["target"],
        eng_type=params["type"],
        scope=scope_data,
    )

    console.print(f"\n[green]Engagement ENG-{eng_id:03d} created[/green]")
    console.print(f"Target: {params['target']} | Type: {params['type']}")
    console.print(f"Surfaces: {', '.join(params['surfaces'])} | Depth: {params['depth']}")
    console.print(f"  Workspace: {ws.root}")


@main.command("list")
@click.pass_context
def list_engagements(ctx):
    """List all engagements."""
    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _list():
        db = Database(str(cfg.db_path))
        await db.initialize()
        engagements = await db.list_engagements()
        await db.close()
        return engagements

    engagements = asyncio.run(_list())

    if not engagements:
        console.print("[dim]No engagements found.[/dim]")
        return

    table = Table(title="Engagements")
    table.add_column("ID", style="cyan")
    table.add_column("Type")
    table.add_column("Target")
    table.add_column("Platform")
    table.add_column("Status")
    table.add_column("Created")

    for eng in engagements:
        table.add_row(
            f"ENG-{eng['id']:03d}",
            eng["type"],
            eng["target"],
            eng["platform"] or "-",
            eng["status"],
            eng["created_at"][:10],
        )

    console.print(table)


@main.command()
@click.argument("engagement_id", type=int)
@click.option("--phase", type=int, default=None, help="Run specific phase (1-7)")
@click.option("--quick", is_flag=True, help="Quick scan, phases 1-4 only")
@click.option("--speed", type=click.Choice(["stealth", "normal", "aggressive"]),
              default="normal", help="Scan speed profile (rate limiting)")
@click.option("--auth-file", type=click.Path(exists=True), default=None,
              help="Auth config JSON file for authenticated scanning")
@click.pass_context
def scan(ctx, engagement_id, phase, quick, speed, auth_file):
    """Run the scanning pipeline on an engagement."""
    from redbreach.core.pipeline import Pipeline
    from redbreach.core.throttle import get_throttled_runner
    from redbreach.modules.recon import ReconModule

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)
    setup_logging(data_dir)

    async def _scan():
        db = Database(str(cfg.db_path))
        await db.initialize()

        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return

        # Set up throttled runner
        runner = get_throttled_runner(profile=speed, domain=eng["target"])
        console.print(f"[cyan]Speed profile:[/cyan] {speed} ({runner.profile.requests_per_second} req/s)")

        # Set up auth session if provided
        auth_session = None
        if auth_file:
            import json as _json
            from redbreach.core.auth import AuthSession, AuthConfig
            auth_data = _json.loads(Path(auth_file).read_text())
            auth_session = AuthSession()
            if isinstance(auth_data, list):
                for profile in auth_data:
                    auth_session.add_profile(profile["name"], AuthConfig.from_dict(profile))
            else:
                auth_session.add_profile("default", AuthConfig.from_dict(auth_data))
            console.print(f"[cyan]Auth profiles:[/cyan] {', '.join(auth_session.profile_names)}")

        from redbreach.modules.web_enum import WebEnumModule
        from redbreach.modules.web_scan import WebScanModule
        from redbreach.modules.cloud import CloudModule
        from redbreach.modules.network import NetworkModule
        from redbreach.modules.api import APIModule
        from redbreach.modules.ai_llm import AILLMModule
        from redbreach.modules.takeover import TakeoverModule
        modules = [
            ReconModule(throttled_runner=runner),
            WebEnumModule(throttled_runner=runner),
            WebScanModule(throttled_runner=runner),
            TakeoverModule(throttled_runner=runner),
            CloudModule(throttled_runner=runner),
            NetworkModule(throttled_runner=runner),
            APIModule(throttled_runner=runner),
            AILLMModule(throttled_runner=runner),
        ]
        from redbreach.core.scope import ScopeEnforcer
        scope_enforcer = ScopeEnforcer(eng.get("scope_json", "{}"), mode=eng.get("type", "bounty"))
        if eng.get("type") != "private" and not scope_enforcer.in_scope_patterns:
            console.print("[yellow]Scope not configured (no in_scope patterns), scope filtering is OFF.[/yellow]")
        elif eng.get("type") != "private" and not scope_enforcer.is_in_scope(eng["target"]):
            console.print(f"[yellow]Warning: seed target {eng['target']} is not within configured in_scope.[/yellow]")

        ai_client = None
        try:
            from redbreach.ai.client import AIClient
            ai_client = AIClient.from_config(cfg)
            console.print(f"[cyan]AI:[/cyan] triage + chaining enabled ({ai_client.provider}: {ai_client.model})")
        except ValueError:
            console.print("[yellow]AI disabled (no provider configured), triage/chaining skipped. See the AI section of the README.[/yellow]")

        pipe = Pipeline(db=db, modules=modules, auth_session=auth_session,
                        scope_enforcer=scope_enforcer, ai_client=ai_client)

        if phase:
            await pipe.run_phase(phase, eng)
        elif quick:
            await pipe.run(eng, [1, 2])  # Intel + recon
        else:
            await pipe.run(eng, [1, 2, 3, 4, 6])  # Intel + scan + triage + chaining

        await db.close()

    asyncio.run(_scan())


@main.command()
@click.argument("finding_id", type=int)
@click.option("--av", "attack_vector", type=click.Choice(["network", "adjacent", "local", "physical"]), default="network")
@click.option("--ac", "attack_complexity", type=click.Choice(["low", "high"]), default="low")
@click.option("--pr", "privileges_required", type=click.Choice(["none", "low", "high"]), default="none")
@click.option("--ui", "user_interaction", type=click.Choice(["none", "required"]), default="none")
@click.option("--scope", "cvss_scope", type=click.Choice(["unchanged", "changed"]), default="unchanged")
@click.option("--c", "confidentiality", type=click.Choice(["high", "low", "none"]), default="none")
@click.option("--i", "integrity", type=click.Choice(["high", "low", "none"]), default="none")
@click.option("--a", "availability", type=click.Choice(["high", "low", "none"]), default="none")
@click.option("--public-exploit", is_flag=True, help="A public exploit exists (raises EPSS estimate)")
@click.option("--set-severity", is_flag=True, help="Also overwrite the finding's severity from the CVSS band")
@click.pass_context
def score(ctx, finding_id, attack_vector, attack_complexity, privileges_required,
          user_interaction, cvss_scope, confidentiality, integrity, availability,
          public_exploit, set_severity):
    """Compute and store a CVSS v3.1 score + vector for a finding (so reports show it)."""
    from redbreach.reporting.scoring import score_finding

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _score():
        db = Database(str(cfg.db_path))
        await db.initialize()
        finding = await db.get_finding(finding_id)
        if not finding:
            console.print(f"[red]Finding {finding_id} not found.[/red]")
            await db.close()
            return
        result = score_finding(
            has_public_exploit=public_exploit,
            attack_vector=attack_vector, attack_complexity=attack_complexity,
            privileges_required=privileges_required, user_interaction=user_interaction,
            scope=cvss_scope, confidentiality=confidentiality,
            integrity=integrity, availability=availability,
        )
        updates = {
            "cvss_score": result["cvss_score"],
            "cvss_vector": result["cvss_vector"],
            "epss_score": result["epss_score"],
        }
        if set_severity:
            updates["severity"] = result["severity"]
        await db.update_finding(finding_id, **updates)
        console.print(
            f"[green]CVSS {result['cvss_score']}[/green] ({result['severity']})  "
            f"{result['cvss_vector']}  EPSS~{result['epss_score']}"
        )
        await db.close()

    asyncio.run(_score())


@main.command()
@click.argument("apk_path", type=click.Path(exists=True))
@click.option("--engagement-id", type=int, default=None, help="Persist non-info findings under this engagement")
@click.pass_context
def mobile(ctx, apk_path, engagement_id):
    """Static analysis of an Android APK (manifest, hardcoded secrets, endpoints)."""
    from collections import Counter
    from redbreach.modules.mobile import MobileAnalyzer

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _mobile():
        findings = await MobileAnalyzer().analyze_apk(apk_path)
        if not findings:
            console.print("[yellow]No findings (or apktool/jadx unavailable).[/yellow]")
            return
        by_sev = Counter(f.get("severity", "info") for f in findings)
        console.print(f"[green]{len(findings)} finding(s):[/green] " +
                      ", ".join(f"{k}={v}" for k, v in by_sev.items()))
        for f in findings[:40]:
            console.print(f"  [{f.get('severity')}] {f.get('title')}")

        if engagement_id:
            db = Database(str(cfg.db_path))
            await db.initialize()
            eng = await db.get_engagement(engagement_id)
            if not eng:
                console.print(f"[red]Engagement {engagement_id} not found; not stored.[/red]")
            else:
                stored = 0
                for f in findings:
                    if f.get("severity") == "info":
                        continue  # endpoints are leads, not findings to report
                    await db.create_finding(
                        engagement_id=engagement_id, asset_id=None,
                        title=f.get("title", "Mobile finding"), severity=f.get("severity", "info"),
                        category=f.get("category"), description=f.get("description"),
                        steps_to_reproduce=f"Source: {f.get('matched_at', 'APK')}",
                        poc_text=f.get("extracted_results", ""),
                    )
                    stored += 1
                console.print(f"[cyan]Stored {stored} finding(s) under engagement {engagement_id}.[/cyan]")
            await db.close()

    asyncio.run(_mobile())


@main.command()
@click.argument("engagement_id", type=int)
@click.pass_context
def coverage(ctx, engagement_id):
    """Show CWE Top 25 and MITRE ATT&CK coverage for an engagement's findings."""
    from redbreach.coverage import coverage_summary, format_coverage

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _coverage():
        db = Database(str(cfg.db_path))
        await db.initialize()
        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return
        findings = await db.get_findings(engagement_id)
        console.print(format_coverage(coverage_summary(findings)))
        await db.close()

    asyncio.run(_coverage())


@main.command()
@click.argument("engagement_id", type=int)
@click.pass_context
def resume(ctx, engagement_id):
    """Resume a saved engagement session."""
    from redbreach.session import SessionManager
    from redbreach.core.pipeline import Pipeline
    from redbreach.modules.recon import ReconModule
    from redbreach.modules.web_enum import WebEnumModule
    from redbreach.modules.web_scan import WebScanModule

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)
    setup_logging(data_dir)

    session_mgr = SessionManager(data_dir / "sessions")
    state = session_mgr.load(engagement_id)

    if not state:
        console.print(f"[red]No saved session for engagement {engagement_id}.[/red]")
        return

    console.print(f"[cyan]Resuming engagement {engagement_id} from phase {state.get('current_phase', '?')}[/cyan]")

    completed = set(state.get("completed_phases", []))
    remaining = [p for p in [2, 3, 4] if p not in completed]

    if not remaining:
        console.print("[green]All phases already complete.[/green]")
        return

    async def _resume():
        db = Database(str(cfg.db_path))
        await db.initialize()
        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return

        modules = [ReconModule(), WebEnumModule(), WebScanModule()]
        pipe = Pipeline(db=db, modules=modules)
        await pipe.run(eng, remaining)

        state["completed_phases"] = list(completed | set(remaining))
        state["current_phase"] = max(remaining)
        session_mgr.save(engagement_id, state)

        await db.close()

    asyncio.run(_resume())


@main.group()
def session():
    """Manage engagement sessions."""
    pass


@session.command("list")
@click.pass_context
def session_list(ctx):
    """List saved sessions."""
    from redbreach.session import SessionManager

    data_dir = ctx.obj["data_dir"]
    session_mgr = SessionManager(data_dir / "sessions")
    sessions = session_mgr.list_sessions()

    if not sessions:
        console.print("[dim]No saved sessions.[/dim]")
        return

    table = Table(title="Saved Sessions")
    table.add_column("Engagement", style="cyan")
    table.add_column("Phase")
    table.add_column("Saved At")

    for s in sessions:
        table.add_row(
            str(s.get("engagement_id", "?")),
            str(s.get("current_phase", "?")),
            s.get("saved_at", "?")[:19],
        )

    console.print(table)


@main.command()
@click.pass_context
def health(ctx):
    """Check tool installation and versions."""
    from redbreach.core.tool_health import (
        check_tools, PHASE_A_TOOLS, PHASE_B_TOOLS, PHASE_C_TOOLS, PHASE_D_TOOLS,
    )

    phases = [
        ("Phase A, Recon", PHASE_A_TOOLS),
        ("Phase B, Web Enum & Scan", PHASE_B_TOOLS),
        ("Phase C, Exploitation", PHASE_C_TOOLS),
        ("Phase D, Network", PHASE_D_TOOLS),
    ]

    async def _health():
        all_results = []
        for label, tools in phases:
            results = await check_tools(tools)
            all_results.append((label, results))
        return all_results

    all_results = asyncio.run(_health())

    for label, results in all_results:
        table = Table(title=label)
        table.add_column("Tool", style="cyan")
        table.add_column("Status")
        table.add_column("Version")

        for tool in results:
            if not tool.installed:
                status, detail = "[red]Missing[/red]", tool.version or "-"
            elif not getattr(tool, "identity_ok", True):
                # e.g. the Python httpx CLI shadowing projectdiscovery httpx on PATH.
                status, detail = "[yellow]WRONG BINARY[/yellow]", tool.error or "unexpected binary"
            else:
                status, detail = "[green]Installed[/green]", tool.version or "-"
            table.add_row(tool.name, status, detail)

        console.print(table)
        console.print()


@main.group()
def findings():
    """Manage findings."""
    pass


@findings.command("list")
@click.argument("engagement_id", type=int)
@click.pass_context
def findings_list(ctx, engagement_id):
    """List findings for an engagement."""
    data_dir = ctx.obj.get("data_dir", DEFAULT_DATA_DIR)
    cfg = load_config(data_dir)

    async def _list():
        db = Database(str(cfg.db_path))
        await db.initialize()
        results = await db.get_findings(engagement_id)
        await db.close()
        return results

    results = asyncio.run(_list())

    if not results:
        console.print("[dim]No findings yet.[/dim]")
        return

    table = Table(title=f"Findings, ENG-{engagement_id:03d}")
    table.add_column("ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Status")

    severity_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
    for f in results:
        color = severity_colors.get(f["severity"], "white")
        table.add_row(
            str(f["id"]),
            f"[{color}]{f['severity'].upper()}[/{color}]",
            f["title"],
            f["status"],
        )

    console.print(table)


@main.group()
def report():
    """Generate reports."""
    pass


@report.command("generate")
@click.argument("finding_id", type=int)
@click.option("--platform", default="hackerone", help="Target platform for report format")
@click.option("--output", type=click.Path(), default=None, help="Output file path")
@click.option("--ai", "use_ai", is_flag=True, help="Rewrite the prose through the AI writer using this platform's voice brief")
@click.pass_context
def report_generate(ctx, finding_id, platform, use_ai, output):
    """Generate a report for a finding."""
    from redbreach.reporting.generator import ReportGenerator

    data_dir = ctx.obj.get("data_dir", DEFAULT_DATA_DIR)
    cfg = load_config(data_dir)
    # Bundled templates ship with the package; a user's own <platform>.md dropped
    # in <data-dir>/templates/ overrides them per file.
    user_templates_dir = Path(data_dir) / "templates"

    async def _generate():
        db = Database(str(cfg.db_path))
        await db.initialize()
        finding = await db.get_finding(finding_id)
        await db.close()
        return finding

    finding = asyncio.run(_generate())

    if not finding:
        console.print(f"[red]Finding {finding_id} not found.[/red]")
        return

    if use_ai:
        from redbreach.ai.client import AIClient
        from redbreach.reporting.writer import ReportWriter

        async def _write():
            writer = ReportWriter(AIClient.from_config(cfg))
            verification = {
                "confidence": finding.get("status", "unconfirmed"),
                "poc_command": finding.get("poc_text", ""),
                "replay_evidence": finding.get("steps_to_reproduce", ""),
            }
            return await writer.write(finding, verification, platform=platform)

        try:
            written = asyncio.run(_write())
        except Exception as e:
            console.print(f"[yellow]AI writer unavailable ({e}). Falling back to stored text.[/yellow]")
        else:
            for field in ("title", "summary", "description", "impact",
                          "steps_to_reproduce", "recommended_fix"):
                if written.get(field):
                    finding[field] = written[field]
            console.print(f"[dim]AI writer applied, voice brief: {platform}[/dim]")

    gen = ReportGenerator(user_templates_dir=user_templates_dir)

    # Check for workspace-based output
    from redbreach.workspace import EngagementWorkspace
    if not output:
        ws = EngagementWorkspace.find(cfg.engagements_dir, finding.get("engagement_id", 0))
        if ws:
            output = str(ws.reports_dir / f"finding-{finding_id}-{platform}.md")

    if output:
        gen.save(platform, finding, Path(output))
        console.print(f"[green]Report saved to {output}[/green]")
    else:
        report_text = gen.generate(platform, finding)
        console.print(report_text)


@main.group()
def ops():
    """Operational tools, dedup, wordlists, vulndb."""
    pass


@ops.command("dedup")
@click.argument("engagement_id", type=int)
@click.option("--threshold", default=0.85, help="Similarity threshold (0.0-1.0)")
@click.pass_context
def ops_dedup(ctx, engagement_id, threshold):
    """Report near-duplicate findings for an engagement. Read-only, deletes nothing."""
    from redbreach.ops.dedup import deduplicate_findings, similarity_score

    data_dir = ctx.obj.get("data_dir", DEFAULT_DATA_DIR)
    cfg = load_config(data_dir)

    async def _load():
        db = Database(str(cfg.db_path))
        await db.initialize()
        rows = await db.get_findings(engagement_id)
        await db.close()
        return rows

    findings = asyncio.run(_load())
    if not findings:
        console.print(f"[dim]No findings for engagement {engagement_id}.[/dim]")
        return

    kept = deduplicate_findings(findings, threshold=threshold)
    kept_ids = {f.get("id") for f in kept}
    dropped = [f for f in findings if f.get("id") not in kept_ids]

    console.print(
        f"\n[bold cyan]Dedup, ENG-{engagement_id:03d}[/bold cyan]  "
        f"threshold={threshold}"
    )
    console.print(f"{len(findings)} finding(s) in, {len(kept)} distinct, {len(dropped)} near-duplicate(s)\n")

    for dup in dropped:
        match = max(kept, key=lambda k: similarity_score(dup, k))
        console.print(f"  [yellow]DUPLICATE[/yellow] #{dup.get('id')} {str(dup.get('title'))[:56]}")
        console.print(
            f"            of #{match.get('id')} {str(match.get('title'))[:56]} "
            f"(score {similarity_score(dup, match):.2f})"
        )

    if dropped:
        console.print("\n[dim]Read-only. Nothing was deleted. Review these before removing any.[/dim]")


@ops.command("wordlists")
def ops_wordlists():
    """List available wordlists."""
    click.echo("Wordlist management, use subcommands")


@ops.command("vulndb")
@click.argument("action", type=click.Choice(["stats", "search"]))
@click.argument("query", required=False)
def ops_vulndb(action, query):
    """Vulnerability database cache operations. [DEPRECATED]"""
    console.print("[yellow]DEPRECATED:[/yellow] Use 'redbreach intel search' or 'redbreach intel stats' instead.")
    click.echo(f"VulnDB: {action}" + (f", {query}" if query else ""))


@main.command()
@click.argument("engagement_id", type=int)
@click.option("--finding-id", type=int, help="Verify a specific finding")
@click.pass_context
def verify(ctx, engagement_id, finding_id):
    """Verify findings, replay PoCs and assess confidence."""
    from redbreach.core.verify import VerificationEngine
    from redbreach.ai.client import AIClient
    from redbreach.workspace import EngagementWorkspace
    from redbreach.core.evidence import EvidenceManager

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)
    setup_logging(data_dir)

    try:
        ai_client = AIClient.from_config(cfg)
    except ValueError:
        ai_client = None
        console.print("[yellow]No AI provider configured, AI assessment disabled, replay only.[/yellow]")

    async def _verify():
        db = Database(str(cfg.db_path))
        await db.initialize()

        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return

        # Get findings to verify
        if finding_id:
            finding = await db.get_finding(finding_id)
            if not finding or finding["engagement_id"] != engagement_id:
                console.print(f"[red]Finding {finding_id} not found in engagement {engagement_id}.[/red]")
                await db.close()
                return
            targets = [finding]
        else:
            targets = await db.get_findings(engagement_id)
            targets = [f for f in targets if f["status"] in ("new", "unconfirmed")]

        if not targets:
            console.print("[dim]No findings to verify.[/dim]")
            await db.close()
            return

        console.print(f"[cyan]Verifying {len(targets)} finding(s) for ENG-{engagement_id:03d}...[/cyan]\n")

        engine = VerificationEngine(ai_client=ai_client, timeout=15) if ai_client else None

        # Workspace for evidence storage
        ws = EngagementWorkspace.find(cfg.engagements_dir, engagement_id)
        evidence_mgr = EvidenceManager(ws.evidence_dir) if ws else None

        severity_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
        confidence_colors = {"verified": "green", "likely": "yellow", "unconfirmed": "dim", "false_positive": "red"}

        for f in targets:
            console.print(f"[bold]Finding #{f['id']}:[/bold] {f['title']}")
            sev_color = severity_colors.get(f["severity"], "white")
            console.print(f"  Severity: [{sev_color}]{f['severity'].upper()}[/{sev_color}]")

            if not engine:
                console.print("  [dim]Skipping AI verification (no API key)[/dim]")
                continue

            result = await engine.verify(f)
            conf_color = confidence_colors.get(result.confidence, "white")
            console.print(f"  Confidence: [{conf_color}]{result.confidence.upper()}[/{conf_color}]")

            if result.replay_status_code is not None:
                console.print(f"  Replay HTTP: {result.replay_status_code}")
            if result.ai_assessment:
                console.print(f"  AI: {result.ai_assessment[:200]}")
            if result.poc_command:
                console.print(f"  PoC: [dim]{result.poc_command}[/dim]")

            # Update finding status in DB
            new_status = result.confidence
            await db.update_finding(f["id"], status=new_status)

            # Save evidence
            if evidence_mgr and result.replay_evidence:
                evidence_text = f"Replay status: {result.replay_status_code}\n\n{result.replay_evidence}"
                epath = evidence_mgr.save_tool_output(
                    tool_name=f"verify-finding-{f['id']}",
                    stdout=evidence_text, stderr=""
                )
                await db.create_evidence(
                    finding_id=f["id"], evidence_type="verification",
                    file_path=str(epath), description=f"PoC replay, {result.confidence}",
                )

            console.print()

        await db.close()
        console.print("[green]Verification complete.[/green]")

    asyncio.run(_verify())


@main.command()
@click.argument("engagement_id", type=int)
@click.option("--confidence", type=click.Choice(["verified", "likely", "all"]), default="verified")
@click.pass_context
def review(ctx, engagement_id, confidence):
    """Review verified findings, approve/reject before reporting."""
    from rich.panel import Panel
    from rich.prompt import Prompt

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)
    setup_logging(data_dir)

    async def _review():
        db = Database(str(cfg.db_path))
        await db.initialize()

        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return

        all_findings = await db.get_findings(engagement_id)

        # Filter by confidence level (status field holds verification result)
        if confidence == "verified":
            findings = [f for f in all_findings if f["status"] == "verified"]
        elif confidence == "likely":
            findings = [f for f in all_findings if f["status"] in ("verified", "likely")]
        else:
            findings = [f for f in all_findings if f["status"] != "false_positive"]

        if not findings:
            console.print(f"[dim]No findings match filter '{confidence}'. Run 'redbreach verify {engagement_id}' first.[/dim]")
            await db.close()
            return

        console.print(f"\n[bold cyan]Review, ENG-{engagement_id:03d}[/bold cyan]")
        console.print(f"Showing {len(findings)} finding(s) (filter: {confidence})\n")

        severity_colors = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}
        approved = []
        rejected = []

        for f in findings:
            sev_color = severity_colors.get(f["severity"], "white")
            panel_text = (
                f"[bold]Title:[/bold] {f['title']}\n"
                f"[bold]Severity:[/bold] [{sev_color}]{f['severity'].upper()}[/{sev_color}]\n"
                f"[bold]Category:[/bold] {f.get('category', 'N/A')}\n"
                f"[bold]Status:[/bold] {f['status']}\n"
                f"[bold]Description:[/bold] {(f.get('description') or 'N/A')[:300]}\n"
            )
            if f.get("poc_text"):
                panel_text += f"\n[bold]PoC:[/bold]\n[dim]{f['poc_text'][:500]}[/dim]\n"
            if f.get("impact"):
                panel_text += f"\n[bold]Impact:[/bold] {f['impact'][:200]}\n"

            # Show evidence if available
            evidence = await db.get_evidence(f["id"])
            if evidence:
                panel_text += f"\n[bold]Evidence files:[/bold] {len(evidence)}"

            console.print(Panel(panel_text, title=f"Finding #{f['id']}", border_style="cyan"))

            if f.get("poc_text"):
                console.print("[yellow]^ Run the PoC above yourself to double-verify before approving.[/yellow]")

            choice = Prompt.ask(
                "Action",
                choices=["approve", "reject", "skip", "quit"],
                default="skip",
            )

            if choice == "approve":
                await db.update_finding(f["id"], status="approved")
                approved.append(f["id"])
                console.print(f"[green]Finding #{f['id']} approved.[/green]\n")
            elif choice == "reject":
                await db.update_finding(f["id"], status="rejected")
                rejected.append(f["id"])
                console.print(f"[red]Finding #{f['id']} rejected.[/red]\n")
            elif choice == "quit":
                console.print("[dim]Review stopped.[/dim]")
                break
            else:
                console.print(f"[dim]Skipped finding #{f['id']}.[/dim]\n")

        console.print(f"\n[bold]Review summary:[/bold] {len(approved)} approved, {len(rejected)} rejected")
        if approved:
            console.print(f"[green]Ready for report:[/green] redbreach report generate <FINDING_ID> --platform {eng.get('platform', 'hackerone')}")

        await db.close()

    asyncio.run(_review())


@main.group()
def auth():
    """Manage authentication profiles for authenticated scanning."""
    pass


@auth.command("create")
@click.argument("engagement_id", type=int)
@click.argument("profile_name")
@click.option("--type", "auth_type", type=click.Choice(["bearer", "cookie", "api_key", "custom"]),
              required=True, help="Authentication type")
@click.option("--token", default=None, help="Bearer token, API key, or custom value")
@click.option("--header", default="Authorization", help="Header name (for api_key/custom)")
@click.option("--cookie", multiple=True, help="Cookie in name=value format (repeatable)")
@click.option("--login-url", default=None, help="Login endpoint URL")
@click.option("--extra-header", multiple=True, help="Extra header in name:value format (repeatable)")
@click.pass_context
def auth_create(ctx, engagement_id, profile_name, auth_type, token, header, cookie, login_url, extra_header):
    """Create an auth profile for an engagement."""
    import json as _json
    from redbreach.workspace import EngagementWorkspace

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    ws = EngagementWorkspace.find(cfg.engagements_dir, engagement_id)
    if not ws:
        console.print(f"[red]Workspace not found for ENG-{engagement_id:03d}.[/red]")
        return

    # Parse cookies
    cookies = {}
    for c in cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()

    # Parse extra headers
    custom_headers = {}
    for h in extra_header:
        if ":" in h:
            k, v = h.split(":", 1)
            custom_headers[k.strip()] = v.strip()

    profile = {
        "name": profile_name,
        "auth_type": auth_type,
        "token": token,
        "header_name": header,
        "cookies": cookies,
        "custom_headers": custom_headers,
        "login_url": login_url,
    }

    # Load or create auth config file
    auth_path = ws.root / "auth.json"
    if auth_path.exists():
        profiles = _json.loads(auth_path.read_text())
    else:
        profiles = []

    # Update existing or add new
    updated = False
    for i, p in enumerate(profiles):
        if p.get("name") == profile_name:
            profiles[i] = profile
            updated = True
            break
    if not updated:
        profiles.append(profile)

    auth_path.write_text(_json.dumps(profiles, indent=2))
    action = "Updated" if updated else "Created"
    console.print(f"[green]{action} auth profile '{profile_name}' for ENG-{engagement_id:03d}[/green]")
    console.print(f"  Type: {auth_type}")
    if cookies:
        console.print(f"  Cookies: {len(cookies)}")
    console.print(f"\n[cyan]Use with scan:[/cyan] redbreach scan {engagement_id} --auth-file {auth_path}")


@auth.command("list")
@click.argument("engagement_id", type=int)
@click.pass_context
def auth_list(ctx, engagement_id):
    """List auth profiles for an engagement."""
    import json as _json
    from redbreach.workspace import EngagementWorkspace

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    ws = EngagementWorkspace.find(cfg.engagements_dir, engagement_id)
    if not ws:
        console.print(f"[red]Workspace not found for ENG-{engagement_id:03d}.[/red]")
        return

    auth_path = ws.root / "auth.json"
    if not auth_path.exists():
        console.print("[dim]No auth profiles configured. Use 'redbreach auth create' to add one.[/dim]")
        return

    profiles = _json.loads(auth_path.read_text())
    table = Table(title=f"Auth Profiles, ENG-{engagement_id:03d}")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Token")
    table.add_column("Cookies")
    table.add_column("Headers")

    for p in profiles:
        token_display = f"{p.get('token', '')[:20]}..." if p.get("token") else "-"
        table.add_row(
            p["name"],
            p.get("auth_type", "none"),
            token_display,
            str(len(p.get("cookies", {}))),
            str(len(p.get("custom_headers", {}))),
        )

    console.print(table)


@auth.command("test")
@click.argument("engagement_id", type=int)
@click.argument("profile_name")
@click.argument("url")
@click.pass_context
def auth_test(ctx, engagement_id, profile_name, url):
    """Test an auth profile by making an authenticated request."""
    import json as _json
    from redbreach.core.auth import AuthSession, AuthConfig
    from redbreach.workspace import EngagementWorkspace

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    ws = EngagementWorkspace.find(cfg.engagements_dir, engagement_id)
    if not ws:
        console.print(f"[red]Workspace not found.[/red]")
        return

    auth_path = ws.root / "auth.json"
    if not auth_path.exists():
        console.print("[red]No auth profiles found.[/red]")
        return

    profiles = _json.loads(auth_path.read_text())
    target = None
    for p in profiles:
        if p["name"] == profile_name:
            target = p
            break

    if not target:
        console.print(f"[red]Profile '{profile_name}' not found.[/red]")
        return

    async def _test():
        session = AuthSession()
        session.add_profile(profile_name, AuthConfig.from_dict(target))

        async with await session.create_client(profile_name) as client:
            resp = await client.get(url)
            console.print(f"[bold]Status:[/bold] {resp.status_code}")
            console.print(f"[bold]Headers:[/bold]")
            for k, v in list(resp.headers.items())[:10]:
                console.print(f"  {k}: {v}")
            console.print(f"[bold]Body preview:[/bold]")
            console.print(resp.text[:500])

    asyncio.run(_test())


@main.group()
def burp():
    """Burp Suite integration, export scope/targets, import findings."""
    pass


@burp.command("export")
@click.argument("engagement_id", type=int)
@click.option("--what", type=click.Choice(["scope", "urls", "findings", "params", "all"]),
              default="all", help="What to export")
@click.pass_context
def burp_export(ctx, engagement_id, what):
    """Export engagement data for Burp Suite."""
    from redbreach.core.burp_bridge import (
        export_scope, export_target_urls, export_findings_for_retest, export_param_targets,
    )
    from redbreach.workspace import EngagementWorkspace

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _export():
        db = Database(str(cfg.db_path))
        await db.initialize()

        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return

        ws = EngagementWorkspace.find(cfg.engagements_dir, engagement_id)
        if not ws:
            console.print(f"[red]Workspace not found for ENG-{engagement_id:03d}.[/red]")
            await db.close()
            return

        burp_dir = ws.root / "burp"
        burp_dir.mkdir(exist_ok=True)

        assets = await db.get_assets(engagement_id)
        findings = await db.get_findings(engagement_id)
        target = eng["target"]

        exported = []

        if what in ("scope", "all"):
            path = export_scope(assets, target, burp_dir / "scope.json")
            exported.append(f"Scope: {path}")

        if what in ("urls", "all"):
            path = export_target_urls(assets, burp_dir / "target_urls.txt")
            exported.append(f"URLs: {path}")

        if what in ("findings", "all") and findings:
            path = export_findings_for_retest(findings, burp_dir / "findings_retest.json")
            exported.append(f"Findings: {path}")

        if what in ("params", "all"):
            param_assets = [a for a in assets if a.get("type") == "parameters"]
            if param_assets:
                path = export_param_targets(param_assets, burp_dir / "param_targets.json")
                exported.append(f"Params: {path}")

        await db.close()

        if exported:
            console.print(f"[bold green]Exported for ENG-{engagement_id:03d}:[/bold green]")
            for e in exported:
                console.print(f"  {e}")
            console.print(f"\n[cyan]Import scope in Burp:[/cyan] Target → Scope settings → Load → {burp_dir / 'scope.json'}")
            console.print(f"[cyan]Paste URLs into Burp:[/cyan] Target → Site map → right-click → Add to scope")
        else:
            console.print("[dim]Nothing to export.[/dim]")

    asyncio.run(_export())


@burp.command("import")
@click.argument("engagement_id", type=int)
@click.argument("xml_file", type=click.Path(exists=True))
@click.pass_context
def burp_import(ctx, engagement_id, xml_file):
    """Import Burp Suite XML export (issues or HTTP history) into redbreach."""
    from redbreach.core.burp_bridge import import_burp_xml

    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    items = import_burp_xml(Path(xml_file))
    if not items:
        console.print("[red]No items parsed from Burp XML.[/red]")
        return

    findings = [i for i in items if i.get("type") == "finding"]
    http_items = [i for i in items if i.get("type") == "http_history"]

    async def _import():
        db = Database(str(cfg.db_path))
        await db.initialize()

        eng = await db.get_engagement(engagement_id)
        if not eng:
            console.print(f"[red]Engagement {engagement_id} not found.[/red]")
            await db.close()
            return

        imported_count = 0
        for f in findings:
            await db.create_finding(
                engagement_id=engagement_id,
                title=f"[Burp] {f['title']}",
                severity=f.get("severity", "info"),
                category=f.get("category", "burp"),
                description=f.get("description", ""),
                poc_text=f.get("request", ""),
                impact=f.get("background", ""),
            )
            imported_count += 1

        await db.close()
        return imported_count

    count = asyncio.run(_import())

    console.print(f"[bold green]Imported from Burp XML:[/bold green]")
    console.print(f"  Findings: {len(findings)}")
    console.print(f"  HTTP history items: {len(http_items)}")
    if findings:
        console.print(f"\n[cyan]Next:[/cyan] redbreach verify {engagement_id}")


@main.group()
def intel():
    """Intelligence engine, sync, search, brief."""
    pass


@intel.command("sync")
@click.option("--source", default=None, help="Sync single source (cisa_kev|nvd|exploitdb|nuclei|github_advisory)")
@click.pass_context
def intel_sync(ctx, source):
    """Sync vulnerability intelligence feeds."""
    from redbreach.intel.sync import SyncOrchestrator
    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _sync():
        db = Database(str(cfg.db_path))
        await db.initialize()
        orch = SyncOrchestrator(db, nvd_api_key=cfg.nvd_api_key)
        if source:
            count = await orch.sync_source(source)
            console.print(f"[green]{source}: {count} entries synced[/green]")
        else:
            results = await orch.sync_all()
            for name, count in results.items():
                if name in ("total", "synced_at"):
                    continue
                status = f"[green]{count}[/green]" if isinstance(count, int) else f"[red]{count}[/red]"
                console.print(f"  {name}: {status}")
            console.print(f"\n[bold green]Total: {results['total']} entries synced[/bold green]")
        await db.close()

    asyncio.run(_sync())


@intel.command("stats")
@click.pass_context
def intel_stats(ctx):
    """Show intelligence data freshness and counts."""
    from redbreach.intel.sync import SyncOrchestrator
    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _stats():
        db = Database(str(cfg.db_path))
        await db.initialize()
        orch = SyncOrchestrator(db)
        stats = await orch.get_stats()
        await db.close()
        return stats

    stats = asyncio.run(_stats())
    table = Table(title="Intelligence Stats")
    table.add_column("Metric", style="cyan")
    table.add_column("Value")
    table.add_row("Last Sync", stats.get("last_sync_at", "never") or "never")
    table.add_row("Sync Generation", str(stats.get("sync_generation", 0)))
    table.add_row("CVEs Cached", str(stats.get("cve_count", 0)))
    table.add_row("Exploits Indexed", str(stats.get("exploit_count", 0)))
    table.add_row("Tech Mappings", str(stats.get("tech_mapping_count", 0)))
    console.print(table)


@intel.command("search")
@click.argument("keyword")
@click.option("--type", "search_type", type=click.Choice(["cve", "exploit", "finding"]), default="cve")
@click.pass_context
def intel_search(ctx, keyword, search_type):
    """Search intelligence data by keyword."""
    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _search():
        db = Database(str(cfg.db_path))
        await db.initialize()
        if search_type == "cve":
            results = await db.search_cves(keyword)
        elif search_type == "exploit":
            async with db._conn.execute(
                "SELECT * FROM exploits WHERE title LIKE ? ORDER BY synced_at DESC LIMIT 50",
                (f"%{keyword}%",),
            ) as cur:
                rows = await cur.fetchall()
            results = [dict(r) for r in rows]
        else:
            results = []
        await db.close()
        return results

    results = asyncio.run(_search())
    if not results:
        console.print(f"[dim]No {search_type} results for '{keyword}'[/dim]")
        return
    table = Table(title=f"Search: {keyword} ({search_type})")
    if search_type == "cve":
        table.add_column("CVE ID", style="cyan")
        table.add_column("CVSS")
        table.add_column("KEV")
        table.add_column("Description")
        for r in results[:30]:
            kev = "[red]YES[/red]" if r.get("kev_known_exploited") else "-"
            table.add_row(r["cve_id"], str(r.get("cvss_score", "-")), kev, (r.get("description") or "")[:80])
    elif search_type == "exploit":
        table.add_column("Source", style="cyan")
        table.add_column("ID")
        table.add_column("CVE")
        table.add_column("Title")
        for r in results[:30]:
            table.add_row(r["source"], r["source_id"], r.get("cve_id", "-"), (r.get("title") or "")[:60])
    console.print(table)


@intel.command("brief")
@click.argument("engagement_id", type=int)
@click.option("--refresh", is_flag=True, help="Force regenerate even if cached")
@click.pass_context
def intel_brief(ctx, engagement_id, refresh):
    """Generate or show intelligence brief for an engagement."""
    from redbreach.intel.brief import BriefGenerator
    data_dir = ctx.obj["data_dir"]
    cfg = load_config(data_dir)

    async def _brief():
        db = Database(str(cfg.db_path))
        await db.initialize()
        gen = BriefGenerator(db)
        if not refresh:
            stored = await db.get_intel_brief(engagement_id)
            if stored and not await gen.is_stale(engagement_id):
                import json as _json
                brief = _json.loads(stored["brief_json"])
                await db.close()
                return brief
        brief = await gen.generate(engagement_id, save=True)
        await db.close()
        return brief

    brief = asyncio.run(_brief())
    if not brief:
        console.print("[red]Could not generate brief.[/red]")
        return
    from redbreach.core.pipeline import display_brief
    display_brief(brief)


if __name__ == "__main__":
    main()
