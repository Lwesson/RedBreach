import re

from rich.console import Console
from rich.panel import Panel

console = Console()

ENGAGEMENT_TYPES = {"bounty", "pentest", "private"}
PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "synack", "immunefi"}
ATTACK_SURFACES = {"web", "api", "cloud", "mobile", "network", "web3", "ai_llm"}

# Numbered menus used by the interactive wizard
_ENGAGEMENT_MENU = {
    "1": "bounty",
    "2": "pentest",
    "3": "private",
}

_PLATFORM_MENU = {
    "1": "hackerone",
    "2": "bugcrowd",
    "3": "intigriti",
    "4": "yeswehack",
    "5": "synack",
    "6": "immunefi",
}

_SURFACE_MENU = {
    "1": "web",
    "2": "api",
    "3": "cloud",
    "4": "mobile",
    "5": "network",
    "6": "web3",
    "7": "ai_llm",
}

_DEPTH_MENU = {
    "1": "quick",
    "2": "standard",
    "3": "deep",
}


def validate_target(target: str) -> bool:
    """Validate that target is a non-empty domain, IP, or URL."""
    target = target.strip()
    if not target:
        return False
    domain_re = r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$"
    ip_re = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    url_re = r"^https?://"
    return bool(re.match(domain_re, target) or re.match(ip_re, target) or re.match(url_re, target))


def _prompt_choice(prompt: str, options: dict[str, str], allow_skip: bool = False) -> str | None:
    """Prompt user to pick from numbered options."""
    while True:
        choice = input(prompt).strip()
        if allow_skip and choice.lower() in ("", "n", "no", "skip"):
            return None
        if choice in options:
            return choice
        console.print(f"[red]Invalid choice: {choice}. Try again.[/red]")


def build_engagement_params() -> dict:
    """Interactive wizard to collect engagement parameters."""
    console.print(Panel("REDBREACH New Engagement", style="bold cyan"))

    # Engagement type
    console.print("\n[bold]Engagement type:[/bold]")
    console.print("  (1) Bug Bounty, platform rules, scope-aware, platform report templates")
    console.print("  (2) Pentest, client engagement, full exploitation, professional deliverables")
    console.print("  (3) Private, unrestricted, custom scope, no platform constraints")
    type_key = _prompt_choice("[?] > ", _ENGAGEMENT_MENU)
    eng_type = _ENGAGEMENT_MENU[type_key]

    # Platform (bug bounty only)
    platform = None
    if eng_type == "bounty":
        console.print("\n[bold]Platform:[/bold]")
        for k, v in _PLATFORM_MENU.items():
            console.print(f"  ({k}) {v.title()}")
        platform_key = _prompt_choice("[?] > ", _PLATFORM_MENU)
        platform = _PLATFORM_MENU[platform_key]

    # Target
    while True:
        target = input("\n[?] Target (domain, IP, or URL): ").strip()
        if validate_target(target):
            break
        console.print("[red]Invalid target. Enter a domain, IP, or URL.[/red]")

    # Scope import
    scope_json = "{}"
    import_scope = input("\n[?] Import scope from platform URL? (y/n): ").strip().lower()
    if import_scope == "y":
        scope_url = input("[?] Program URL: ").strip()
        console.print("[yellow]Scope import not yet implemented, using manual scope.[/yellow]")

    # Attack surfaces
    console.print("\n[bold]Attack surfaces to test:[/bold]")
    for k, v in _SURFACE_MENU.items():
        console.print(f"  ({k}) {v}")
    surface_input = input("[?] Select (comma-separated, e.g. 1,2,3): ").strip()
    surfaces = []
    for key in surface_input.split(","):
        key = key.strip()
        if key in _SURFACE_MENU:
            surfaces.append(_SURFACE_MENU[key])
    if not surfaces:
        surfaces = ["web"]

    # Depth
    console.print("\n[bold]Scan depth:[/bold]")
    console.print("  (1) Quick, phases 1-4, automated only")
    console.print("  (2) Standard, full pipeline, AI-assisted manual suggestions")
    console.print("  (3) Deep dive, exhaustive, all modules, extended fuzzing")
    depth_key = _prompt_choice("[?] > ", _DEPTH_MENU)
    depth = _DEPTH_MENU[depth_key]

    # Proxy
    proxy = input("\n[?] Enable proxy/anonymization? (y/n): ").strip().lower() == "y"

    return {
        "type": eng_type,
        "platform": platform,
        "target": target,
        "scope_json": scope_json,
        "surfaces": surfaces,
        "depth": depth,
        "proxy": proxy,
    }
