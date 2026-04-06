"""
cli.py — Entry point for VulnMind.

Command structure:
  vulnmind analyze <files> [--enrich] [--report pdf]
  vulnmind config set-key <api-key>
  vulnmind config set-license <license-key>
  vulnmind config show
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from vulnmind import __version__
from vulnmind.config import Config

console = Console()


# ---------------------------------------------------------------------------
# Main CLI group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(version=__version__, prog_name="VulnMind")
def cli():
    """
    VulnMind — Security scan analyzer.

    Parse and analyze output from nmap, nikto, and other security tools.
    Get structured findings, CVE matches, priority rankings, and reports.

    \b
    Quick start:
      nmap -oX scan.xml 192.168.1.0/24
      vulnmind analyze scan.xml
    """
    pass


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument(
    "files",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, readable=True, path_type=Path),
)
@click.option(
    "--report",
    type=click.Choice(["pdf"]),
    default=None,
    help="Generate a PDF report (Pro required).",
)
@click.option(
    "--enrich",
    is_flag=True,
    default=False,
    help="Deep analysis: explanations, exploit commands, Metasploit modules.",
)
def analyze(files: tuple, report: str | None, enrich: bool):
    """
    Analyze one or more scanner output files.

    \b
    Supported formats:
      nmap -oX scan.xml    (recommended)
      nmap -oN scan.nmap   (text output)
      nikto -o scan.txt    (nikto output)

    \b
    Examples:
      vulnmind analyze scan.xml
      vulnmind analyze scan.xml nikto.txt
      vulnmind analyze scan.xml --enrich
      vulnmind analyze scan.xml --enrich --report pdf
    """
    cfg = Config.load()

    # Only check for API key if --enrich was requested
    if enrich and not cfg.groq_api_key:
        console.print(Panel(
            "No API key configured.\n\n"
            "Get a free key at [bold]console.groq.com[/bold] then run:\n\n"
            "  [bold]vulnmind config set-key <your-key>[/bold]",
            title="[bold red]Setup Required[/bold red]",
            border_style="red",
        ))
        sys.exit(1)

    from vulnmind.parsers import load_files
    from vulnmind.license import get_tier, partition_findings
    from vulnmind.matcher import match_findings

    # --- Parse ---
    all_findings = []
    for file_path in files:
        try:
            findings = load_files([file_path])
            all_findings.extend(findings)
        except Exception as e:
            console.print(f"[red]Error parsing {file_path.name}:[/red] {e}")
            sys.exit(1)

    if not all_findings:
        console.print(Panel(
            "No findings were extracted from the provided file(s).\n\n"
            "This could mean:\n"
            "  - The scan found no open ports or vulnerabilities\n"
            "  - The file format wasn't recognised\n"
            "  - The scan was incomplete or empty",
            title="[yellow]No Findings[/yellow]",
            border_style="yellow",
        ))
        return

    # --- Knowledge base match (always runs, offline) ---
    all_findings = match_findings(all_findings)

    # --- License gate ---
    tier = get_tier(cfg)
    free_findings, locked_findings = partition_findings(all_findings, tier)

    # --- Deep enrich if requested ---
    if enrich:
        from vulnmind.ai import enrich_findings
        free_findings = enrich_findings(free_findings, cfg)

    # --- Display ---
    display_results(free_findings, locked_findings, tier, all_findings)

    # --- PDF ---
    if report == "pdf":
        if tier != "pro":
            console.print(Panel(
                "PDF reports require a Pro license.\n\n"
                "Run [bold]vulnmind config set-license <key>[/bold] to unlock.",
                title="Pro Required",
                border_style="yellow",
            ))
        else:
            from vulnmind.report import generate_pdf
            output_path = "vulnmind_report.pdf"
            generate_pdf(all_findings, output_path)
            console.print(f"\n[green]Report saved:[/green] {output_path}")


# ---------------------------------------------------------------------------
# config command group
# ---------------------------------------------------------------------------

@cli.group()
def config():
    """Manage VulnMind configuration."""
    pass


@config.command("set-key")
@click.argument("api_key")
def config_set_key(api_key: str):
    """Save your API key for deep analysis.

    \b
    Usage: vulnmind config set-key gsk_...
    """
    cfg = Config.load()
    cfg.set("groq_api_key", api_key)
    cfg.save()
    console.print(f"[green]Key saved.[/green] ({api_key[:8]}...)")


@config.command("set-license")
@click.argument("license_key")
def config_set_license(license_key: str):
    """Activate a Pro license key.

    \b
    Usage: vulnmind config set-license <key>
    """
    from vulnmind.license import validate_key
    if not validate_key(license_key):
        console.print("[red]Invalid license key.[/red] Check your key and try again.")
        sys.exit(1)

    cfg = Config.load()
    cfg.set("license_key", license_key)
    cfg.save()
    console.print("[green]Pro license activated.[/green] All features unlocked.")


@config.command("show")
def config_show():
    """Show current configuration."""
    cfg = Config.load()
    display = cfg.display_dict()
    if not display:
        console.print("[dim]No configuration set.[/dim]")
        return
    for key, value in display.items():
        console.print(f"  [cyan]{key}[/cyan]: {value}")


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def display_results(free_findings, locked_findings, tier, all_findings):
    total = len(all_findings)
    critical = sum(1 for f in all_findings if f.priority == "critical")
    high     = sum(1 for f in all_findings if f.priority == "high")
    medium   = sum(1 for f in all_findings if f.priority == "medium")
    low      = sum(1 for f in all_findings if f.priority == "low")
    unknown  = total - critical - high - medium - low

    tier_badge = "[green]PRO[/green]" if tier == "pro" else "[dim]FREE[/dim]"
    header = (
        f"[bold]VulnMind[/bold] {tier_badge}  ·  "
        f"[red]{critical} critical[/red]  "
        f"[orange1]{high} high[/orange1]  "
        f"[yellow]{medium} medium[/yellow]  "
        f"[green]{low} low[/green]  "
        f"[dim]{unknown} unrated[/dim]  "
        f"[dim]({total} total)[/dim]"
    )
    console.print(Panel(header, border_style="blue", padding=(0, 1)))
    console.print()

    for finding in free_findings:
        display_finding_panel(finding)

    if locked_findings:
        display_locked_table(locked_findings)


def display_finding_panel(finding):
    priority_colors = {
        "critical": "bold red",
        "high":     "orange1",
        "medium":   "yellow",
        "low":      "green",
    }
    priority = finding.priority or "unrated"
    color = priority_colors.get(priority, "dim")
    priority_badge = f"[{color}]{priority.upper()}[/{color}]"

    lines = []

    port_str    = f":{finding.port}" if finding.port else ""
    service_str = f"  [{finding.service}]" if finding.service else ""
    lines.append(f"[dim]Target:[/dim] [bold]{finding.host}{port_str}[/bold]{service_str}")

    if finding.cve_ids:
        lines.append(f"[dim]CVEs:[/dim]   [cyan]{', '.join(finding.cve_ids)}[/cyan]")

    lines.append("")

    if finding.ai_explanation:
        lines.append(finding.ai_explanation)
    else:
        lines.append(f"[dim]{finding.description}[/dim]")

    if finding.suggested_commands:
        lines.append("")
        lines.append("[bold]Next steps:[/bold]")
        for cmd in finding.suggested_commands:
            lines.append(f"  [green]$[/green] [white]{cmd}[/white]")

    if finding.metasploit_modules:
        lines.append("")
        lines.append("[bold]Metasploit:[/bold]")
        for mod in finding.metasploit_modules:
            lines.append(f"  [red]msf[/red] [dim]>[/dim] use {mod}")

    if finding.false_positive_likelihood in ("medium", "high"):
        lines.append("")
        fp_color = "yellow" if finding.false_positive_likelihood == "medium" else "orange1"
        lines.append(f"[{fp_color}]! False positive likelihood: {finding.false_positive_likelihood}[/{fp_color}]")
        if finding.false_positive_reason:
            lines.append(f"[dim]  {finding.false_positive_reason}[/dim]")

    console.print(Panel(
        "\n".join(lines),
        title=f"{priority_badge}  [bold]{finding.title}[/bold]",
        border_style=color,
        padding=(1, 2),
    ))
    console.print()


def display_locked_table(locked_findings):
    from rich.table import Table
    from rich import box

    table = Table(
        title="[dim]Additional Findings — Pro Required[/dim]",
        box=box.SIMPLE,
        show_header=True,
        header_style="dim",
        border_style="dim",
    )
    table.add_column("Host",     style="dim", no_wrap=True)
    table.add_column("Port",     style="dim", no_wrap=True)
    table.add_column("Finding",  style="dim")
    table.add_column("Priority", style="dim", no_wrap=True)
    table.add_column("",         no_wrap=True)

    priority_colors = {"critical": "red", "high": "orange1", "medium": "yellow", "low": "green"}

    for finding in locked_findings:
        priority = finding.priority or "?"
        p_color  = priority_colors.get(priority, "dim")
        title    = finding.title[:45] + "…" if len(finding.title) > 45 else finding.title
        table.add_row(
            finding.host,
            str(finding.port) if finding.port else "-",
            f"[dim]{title}[/dim]",
            f"[{p_color}]{priority}[/{p_color}]",
            "[yellow bold][PRO][/yellow bold]",
        )

    console.print(table)
    console.print(Panel(
        "Unlock deep analysis, exploit commands, Metasploit modules, and PDF reports.\n\n"
        "Run: [bold]vulnmind config set-license <your-key>[/bold]",
        title="[bold yellow]Upgrade to Pro[/bold yellow]",
        border_style="yellow",
        padding=(0, 2),
    ))
