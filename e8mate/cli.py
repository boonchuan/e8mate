"""E8Mate CLI — Essential Eight Compliance Scanner.

Usage:
    e8mate scan --local
    e8mate scan --local --controls patch-os,mfa
    e8mate scan --local --output report.json --format json
    e8mate score --from-report scan.json
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from e8mate import __version__
from e8mate.evidence.models import ControlOutcome, MaturityLevel

app = typer.Typer(
    name="e8mate",
    help="🛡️  E8Mate — Open Source Essential Eight Compliance Scanner",
    no_args_is_help=True,
)
console = Console()


def version_callback(value: bool):
    if value:
        console.print(f"E8Mate v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit."
    ),
):
    """🛡️  E8Mate — Open Source Essential Eight Compliance Scanner.

    Assess your organisation's cybersecurity posture against the Australian
    Signals Directorate's Essential Eight Maturity Model.
    """
    pass


@app.command()
def scan(
    target: Optional[str] = typer.Option(
        None, "--target", "-t",
        help="Remote Windows host to scan via WinRM (e.g., 192.168.1.100)."
    ),
    user: Optional[str] = typer.Option(
        None, "--user", "-u",
        help="WinRM username for remote scanning."
    ),
    password: Optional[str] = typer.Option(
        None, "--password", "-p",
        help="WinRM password. INSECURE: visible in process list. Prefer E8MATE_WINRM_PASSWORD env var.",
        hidden=True,  # Hidden from --help to discourage use
    ),
    mock: Optional[str] = typer.Option(
        None, "--mock",
        help="Run with simulated data: 'compliant', 'partial', or 'noncompliant'. Great for dev/demo on Linux."
    ),
    controls: Optional[str] = typer.Option(
        None, "--controls", "-c",
        help="Comma-separated list of controls to scan (e.g., patch-os,mfa,admin)."
    ),
    maturity_level: int = typer.Option(
        1, "--maturity-level", "-m",
        help="Target maturity level to assess (1, 2, or 3).",
        min=1, max=3,
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file path (default: stdout summary + e8mate-scan-<timestamp>.json)."
    ),
    format: str = typer.Option(
        "json", "--format", "-f",
        help="Output format: json, html, csv."
    ),
):
    """Run an Essential Eight compliance scan.

    Three modes of operation:

    1. MOCK MODE (for development/demos on Ubuntu):
       e8mate scan --mock compliant
       e8mate scan --mock noncompliant
       e8mate scan --mock partial

    2. REMOTE MODE (scan a Windows target from Ubuntu via WinRM):
       e8mate scan --target 192.168.1.100 --user admin

    3. LOCAL MODE (on a Windows machine):
       e8mate scan
    """
    import os

    console.print()
    console.print(Panel.fit(
        "[bold cyan]E8Mate[/bold cyan] — Essential Eight Compliance Scanner",
        subtitle=f"v{__version__}",
    ))
    console.print()

    # --- Resolve transport ---

    transport = None

    # 1. Mock mode (dev/demo on Ubuntu)
    if mock:
        from e8mate.transports.mock import MockTransport
        if mock not in ("compliant", "partial", "noncompliant"):
            console.print("[red]--mock must be: compliant, partial, or noncompliant[/red]")
            raise typer.Exit(1)
        transport = MockTransport(scenario=mock)
        console.print(f"[yellow]🧪 Mock mode:[/yellow] Simulating a [bold]{mock}[/bold] Windows environment")
        console.print()

    # 2. Remote mode (scan Windows target from Ubuntu via WinRM)
    elif target:
        from e8mate.transports.winrm_transport import WinRMTransport
        winrm_pass = password or os.environ.get("E8MATE_WINRM_PASSWORD")
        if not user:
            console.print("[red]--user is required for remote scanning.[/red]")
            raise typer.Exit(1)
        if not winrm_pass:
            import getpass
            winrm_pass = getpass.getpass(f"WinRM password for {user}@{target}: ")

        console.print(f"[cyan]🔗 Connecting to {target} via WinRM...[/cyan]")
        try:
            from e8mate.utils.security import validate_target_host
            validated_host = validate_target_host(target)
            transport = WinRMTransport(host=validated_host, username=user, password=winrm_pass)
            console.print(f"[green]✅ Connected to {target}[/green]")
        except Exception as e:
            console.print(f"[red]❌ WinRM connection failed: {e}[/red]")
            console.print()
            console.print("[dim]Troubleshooting:[/dim]")
            console.print("[dim]  • Ensure WinRM is enabled on the target: winrm quickconfig[/dim]")
            console.print("[dim]  • Check firewall allows port 5985 (HTTP) or 5986 (HTTPS)[/dim]")
            console.print("[dim]  • Try: pip install pywinrm[/dim]")
            raise typer.Exit(1)

    # 3. Local mode (running on a Windows machine directly)
    else:
        from e8mate.transports.local import LocalTransport
        transport = LocalTransport()

        if not transport.has_powershell:
            console.print("[yellow]⚠ PowerShell not detected on this system.[/yellow]")
            console.print()
            console.print("[dim]You're on Linux — here's how to use E8Mate:[/dim]")
            console.print()
            console.print("  [cyan]Development/demo:[/cyan]  e8mate scan --mock partial")
            console.print("  [cyan]Scan a Windows PC:[/cyan] e8mate scan --target 192.168.1.100 --user admin")
            console.print()
            console.print("[dim]Or install PowerShell Core for local checks: https://aka.ms/install-powershell[/dim]")
            console.print()

            # Auto-fallback to mock partial
            console.print("[yellow]Falling back to --mock partial for now...[/yellow]")
            console.print()
            from e8mate.transports.mock import MockTransport
            transport = MockTransport(scenario="partial")

    # --- Run the scan ---

    control_list = controls.split(",") if controls else None

    from e8mate.scanner import E8Scanner
    target_ml = MaturityLevel(maturity_level)

    with console.status("[cyan]Scanning...[/cyan]", spinner="dots"):
        scanner = E8Scanner(
            transport=transport,
            target_maturity=target_ml,
            controls=control_list,
        )
        result = scanner.scan()

    # Display results
    _display_summary(result)

    # Save report
    from pathlib import Path
    from e8mate.utils.security import set_report_permissions, validate_output_path

    if format == "json":
        from e8mate.reporters.json_reporter import generate_json_report
        out_path = output or f"e8mate-scan-{result.scan_id}.json"
        try:
            safe_path = validate_output_path(out_path)
        except ValueError as e:
            console.print(f"[red]Invalid output path: {e}[/red]")
            raise typer.Exit(1)
        report_path = generate_json_report(result, safe_path)
        set_report_permissions(report_path)
        console.print(f"\n[green]📄 JSON report saved to:[/green] {report_path} [dim](owner-only)[/dim]")

    elif format == "html":
        from e8mate.reporters.html_reporter import generate_html_report
        out_path = output or f"e8mate-report-{result.scan_id}.html"
        try:
            safe_path = validate_output_path(out_path)
        except ValueError as e:
            console.print(f"[red]Invalid output path: {e}[/red]")
            raise typer.Exit(1)
        report_path = generate_html_report(result, safe_path)
        set_report_permissions(report_path)
        console.print(f"\n[green]📄 HTML report saved to:[/green] {report_path} [dim](owner-only)[/dim]")

    # Always save JSON alongside for data portability
    if format != "json":
        from e8mate.reporters.json_reporter import generate_json_report
        json_path = validate_output_path(f"e8mate-scan-{result.scan_id}.json")
        generate_json_report(result, json_path)
        set_report_permissions(json_path)

    console.print()


@app.command()
def demo():
    """Run a quick demo with all three scenarios to see what E8Mate output looks like.

    Perfect for Linux development — no Windows target needed.
    """
    from e8mate.transports.mock import MockTransport, SCENARIOS
    from e8mate.scanner import E8Scanner

    for scenario, desc in SCENARIOS.items():
        console.print()
        console.print(Panel(
            f"[bold]{desc}[/bold]",
            title=f"Scenario: {scenario}",
            border_style="cyan",
        ))

        transport = MockTransport(scenario=scenario)
        scanner = E8Scanner(transport=transport, target_maturity=MaturityLevel.ML1)
        result = scanner.scan()
        _display_summary(result)

        console.print("[dim]─" * 60 + "[/dim]")


@app.command()
def score(
    from_report: str = typer.Option(..., "--from-report", help="Path to a previous scan JSON report."),
):
    """Display the score summary from a previous scan report."""
    from e8mate.reporters.json_reporter import load_scan_result
    result = load_scan_result(from_report)
    _display_summary(result)


@app.command()
def diff(
    earlier: str = typer.Argument(..., help="Path to the earlier (baseline) scan JSON report."),
    later: str = typer.Argument(..., help="Path to the later (current) scan JSON report."),
):
    """Compare two scan reports and show what changed.

    Shows regressed and improved controls, highlights checks whose outcome
    flipped, and surfaces overall maturity changes between the two scans.

    Example:
        e8mate diff scan-2026-04-20.json scan-2026-04-26.json
    """
    from e8mate.reporters.json_reporter import load_scan_result
    from e8mate.diff import diff_scans, render_diff

    earlier_path = Path(earlier)
    later_path = Path(later)

    if not earlier_path.exists():
        console.print(f"[red]❌ Earlier scan file not found: {earlier}[/red]")
        raise typer.Exit(code=1)
    if not later_path.exists():
        console.print(f"[red]❌ Later scan file not found: {later}[/red]")
        raise typer.Exit(code=1)

    try:
        earlier_result = load_scan_result(str(earlier_path))
    except Exception as e:
        console.print(f"[red]❌ Failed to parse earlier scan: {e}[/red]")
        raise typer.Exit(code=1)

    try:
        later_result = load_scan_result(str(later_path))
    except Exception as e:
        console.print(f"[red]❌ Failed to parse later scan: {e}[/red]")
        raise typer.Exit(code=1)

    diff_result = diff_scans(earlier_result, later_result)
    console.print()
    console.print(render_diff(diff_result))
    console.print()


def _display_summary(result):
    """Render a rich summary table of scan results."""
    console.print()

    # System info
    si = result.system_info
    console.print(f"[dim]Host:[/dim] {si.hostname}  |  [dim]OS:[/dim] {si.os_name} {si.os_version}")
    console.print(f"[dim]Scan:[/dim] {result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}  |  [dim]Duration:[/dim] {result.scan_duration_seconds}s")
    console.print()

    # Overall maturity
    ml = result.overall_maturity.value
    ml_color = {0: "red", 1: "yellow", 2: "cyan", 3: "green"}.get(ml, "white")
    console.print(Panel(
        f"[bold {ml_color}]Maturity Level {ml}[/bold {ml_color}]",
        title="Overall Essential Eight Maturity",
        border_style=ml_color,
    ))

    # Per-control table
    table = Table(title="Control Results", show_lines=True)
    table.add_column("Control", style="bold", min_width=30)
    table.add_column("Achieved", justify="center", min_width=10)
    table.add_column("Target", justify="center", min_width=8)
    table.add_column("Pass Rate", justify="center", min_width=10)
    table.add_column("Status", justify="center", min_width=8)

    for cr in result.control_results:
        achieved = cr.achieved_maturity.value
        target = cr.target_maturity.value
        pass_rate = f"{cr.pass_rate:.0%}"

        if achieved >= target:
            status = "[green]✅ PASS[/green]"
            achieved_str = f"[green]ML{achieved}[/green]"
        elif achieved > 0:
            status = "[yellow]⚠ PARTIAL[/yellow]"
            achieved_str = f"[yellow]ML{achieved}[/yellow]"
        else:
            status = "[red]❌ FAIL[/red]"
            achieved_str = f"[red]ML{achieved}[/red]"

        table.add_row(cr.display_name, achieved_str, f"ML{target}", pass_rate, status)

    # Add rows for controls not included in this scan
    all_controls = {
        "Application Control", "Patch Applications", "Configure Microsoft Office Macros",
        "User Application Hardening", "Restrict Administrative Privileges",
        "Patch Operating Systems", "Multi-Factor Authentication", "Regular Backups",
    }
    scanned_names = {cr.display_name for cr in result.control_results}
    for missing in sorted(all_controls - scanned_names):
        table.add_row(
            f"[dim]{missing}[/dim]",
            "[dim]—[/dim]",
            "[dim]ML1[/dim]",
            "[dim]—[/dim]",
            "[dim]⊘ Not scanned[/dim]",
        )

    console.print(table)

    # Findings detail
    for cr in result.control_results:
        if cr.findings:
            console.print(f"\n[bold]{cr.display_name}[/bold]")
            for f in cr.findings:
                icon = {
                    ControlOutcome.EFFECTIVE: "[green]✅[/green]",
                    ControlOutcome.ALTERNATE_CONTROL: "[green]🔄[/green]",
                    ControlOutcome.INEFFECTIVE: "[red]❌[/red]",
                    ControlOutcome.NOT_IMPLEMENTED: "[red]⬜[/red]",
                    ControlOutcome.NO_VISIBILITY: "[yellow]👁[/yellow]",
                    ControlOutcome.NOT_APPLICABLE: "[dim]N/A[/dim]",
                    ControlOutcome.NOT_ASSESSED: "[dim]—[/dim]",
                }.get(f.outcome, "❓")
                console.print(f"  {icon} [{f.check_id}] {f.title}")
                if f.outcome == ControlOutcome.INEFFECTIVE and f.remediation:
                    console.print(f"    [dim]→ {f.remediation}[/dim]")


if __name__ == "__main__":
    app()
