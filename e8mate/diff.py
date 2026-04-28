"""Compare two scan results and identify what changed.

Pure logic module — no CLI, no I/O, no formatting. Takes two ScanResult
objects and produces a structured DiffResult describing per-check and
per-control changes.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from e8mate.evidence.models import (
    ControlOutcome,
    MaturityLevel,
    ScanResult,
)


class CheckDelta(BaseModel):
    """A single check's outcome change between two scans."""

    check_id: str
    control: str
    title: str
    earlier_outcome: Optional[ControlOutcome] = None
    later_outcome: Optional[ControlOutcome] = None
    change_type: str  # "regressed", "improved", "unchanged", "new", "removed"


class ControlDelta(BaseModel):
    """A single control's maturity change between two scans."""

    control: str
    display_name: str
    earlier_maturity: Optional[MaturityLevel] = None
    later_maturity: Optional[MaturityLevel] = None
    change_type: str  # "regressed", "improved", "unchanged", "new", "removed"


class DiffResult(BaseModel):
    """Complete diff between two scan results."""

    earlier_scan_id: str
    later_scan_id: str
    earlier_scan_date: str
    later_scan_date: str

    earlier_hostname: str
    later_hostname: str
    same_host: bool

    earlier_overall_maturity: Optional[MaturityLevel] = None
    later_overall_maturity: Optional[MaturityLevel] = None
    overall_change: str  # "regressed", "improved", "unchanged"

    control_deltas: list[ControlDelta] = Field(default_factory=list)
    check_deltas: list[CheckDelta] = Field(default_factory=list)

    @property
    def regressed_controls(self) -> list[ControlDelta]:
        return [c for c in self.control_deltas if c.change_type == "regressed"]

    @property
    def improved_controls(self) -> list[ControlDelta]:
        return [c for c in self.control_deltas if c.change_type == "improved"]

    @property
    def unchanged_controls(self) -> list[ControlDelta]:
        return [c for c in self.control_deltas if c.change_type == "unchanged"]

    @property
    def regressed_checks(self) -> list[CheckDelta]:
        return [c for c in self.check_deltas if c.change_type == "regressed"]

    @property
    def improved_checks(self) -> list[CheckDelta]:
        return [c for c in self.check_deltas if c.change_type == "improved"]

    @property
    def new_checks(self) -> list[CheckDelta]:
        return [c for c in self.check_deltas if c.change_type == "new"]

    @property
    def removed_checks(self) -> list[CheckDelta]:
        return [c for c in self.check_deltas if c.change_type == "removed"]


# Outcome severity ordering for regression/improvement detection.
# Higher value = "more compliant" (better). A drop in this value is a regression.
_OUTCOME_SCORE = {
    # Higher = "more compliant". Used to detect regression/improvement
    # for outcomes other than NOT_APPLICABLE (which is treated as a
    # scope change, not a posture change — see _classify_outcome_change).
    ControlOutcome.EFFECTIVE: 4,
    ControlOutcome.ALTERNATE_CONTROL: 4,
    ControlOutcome.NO_VISIBILITY: 3,
    ControlOutcome.NOT_ASSESSED: 3,
    ControlOutcome.NOT_APPLICABLE: 3,
    ControlOutcome.INEFFECTIVE: 1,
    ControlOutcome.NOT_IMPLEMENTED: 1,
}


def _classify_outcome_change(
    earlier: Optional[ControlOutcome],
    later: Optional[ControlOutcome],
) -> str:
    """Classify the direction of an outcome change."""
    if earlier is None and later is not None:
        return "new"
    if earlier is not None and later is None:
        return "removed"
    if earlier == later:
        return "unchanged"

    # Transitions to/from NOT_APPLICABLE are scope changes, not compliance
    # changes. The host's environment changed (e.g. joined/left a domain),
    # not its security posture. Don't flag as regression or improvement.
    if (earlier == ControlOutcome.NOT_APPLICABLE
            or later == ControlOutcome.NOT_APPLICABLE):
        return "unchanged"

    earlier_score = _OUTCOME_SCORE.get(earlier, 0)
    later_score = _OUTCOME_SCORE.get(later, 0)

    if later_score > earlier_score:
        return "improved"
    if later_score < earlier_score:
        return "regressed"
    # Same score, different outcome (e.g. NO_VISIBILITY -> NOT_APPLICABLE).
    # Treat as unchanged for compliance-review purposes.
    return "unchanged"


def _classify_maturity_change(
    earlier: Optional[MaturityLevel],
    later: Optional[MaturityLevel],
) -> str:
    """Classify the direction of a maturity-level change."""
    if earlier is None and later is not None:
        return "new"
    if earlier is not None and later is None:
        return "removed"
    if earlier == later:
        return "unchanged"

    earlier_int = earlier.value if earlier else 0
    later_int = later.value if later else 0

    if later_int > earlier_int:
        return "improved"
    if later_int < earlier_int:
        return "regressed"
    return "unchanged"


def diff_scans(earlier: ScanResult, later: ScanResult) -> DiffResult:
    """Compute the diff between two scan results.

    Args:
        earlier: The baseline scan (the "before" state).
        later: The current scan (the "after" state).

    Returns:
        A DiffResult describing every check and control change.
    """
    # Index findings by check_id for fast lookup
    earlier_findings = {
        f.check_id: f
        for cr in earlier.control_results
        for f in cr.findings
    }
    later_findings = {
        f.check_id: f
        for cr in later.control_results
        for f in cr.findings
    }

    all_check_ids = sorted(set(earlier_findings) | set(later_findings))

    check_deltas = []
    for check_id in all_check_ids:
        e_finding = earlier_findings.get(check_id)
        l_finding = later_findings.get(check_id)

        e_outcome = e_finding.outcome if e_finding else None
        l_outcome = l_finding.outcome if l_finding else None

        change_type = _classify_outcome_change(e_outcome, l_outcome)

        # Prefer the later finding's metadata (for title/control name)
        # since that's the "current" view; fall back to earlier if the
        # check was removed.
        ref_finding = l_finding or e_finding
        check_deltas.append(CheckDelta(
            check_id=check_id,
            control=ref_finding.control.value,
            title=ref_finding.title,
            earlier_outcome=e_outcome,
            later_outcome=l_outcome,
            change_type=change_type,
        ))

    # Index control results
    earlier_controls = {cr.control: cr for cr in earlier.control_results}
    later_controls = {cr.control: cr for cr in later.control_results}

    all_controls = sorted(
        set(earlier_controls) | set(later_controls),
        key=lambda c: c.value,
    )

    control_deltas = []
    for control in all_controls:
        e_cr = earlier_controls.get(control)
        l_cr = later_controls.get(control)

        e_maturity = e_cr.achieved_maturity if e_cr else None
        l_maturity = l_cr.achieved_maturity if l_cr else None

        change_type = _classify_maturity_change(e_maturity, l_maturity)
        ref_cr = l_cr or e_cr
        control_deltas.append(ControlDelta(
            control=control.value,
            display_name=ref_cr.display_name,
            earlier_maturity=e_maturity,
            later_maturity=l_maturity,
            change_type=change_type,
        ))

    overall_change = _classify_maturity_change(
        earlier.overall_maturity,
        later.overall_maturity,
    )

    return DiffResult(
        earlier_scan_id=earlier.scan_id,
        later_scan_id=later.scan_id,
        earlier_scan_date=earlier.scan_date.isoformat()
            if hasattr(earlier.scan_date, "isoformat")
            else str(earlier.scan_date),
        later_scan_date=later.scan_date.isoformat()
            if hasattr(later.scan_date, "isoformat")
            else str(later.scan_date),
        earlier_hostname=earlier.system_info.hostname,
        later_hostname=later.system_info.hostname,
        same_host=earlier.system_info.hostname == later.system_info.hostname,
        earlier_overall_maturity=earlier.overall_maturity,
        later_overall_maturity=later.overall_maturity,
        overall_change=overall_change,
        control_deltas=control_deltas,
        check_deltas=check_deltas,
    )



# ============================================================================
# Renderer — produces a rich-renderable report for the diff result
# ============================================================================

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


_OUTCOME_ICONS = {
    ControlOutcome.EFFECTIVE: "[green]✅[/green]",
    ControlOutcome.ALTERNATE_CONTROL: "[green]🔄[/green]",
    ControlOutcome.INEFFECTIVE: "[red]❌[/red]",
    ControlOutcome.NOT_IMPLEMENTED: "[red]⬜[/red]",
    ControlOutcome.NO_VISIBILITY: "[yellow]👁[/yellow]",
    ControlOutcome.NOT_APPLICABLE: "[dim]N/A[/dim]",
    ControlOutcome.NOT_ASSESSED: "[dim]—[/dim]",
}


def _outcome_label(outcome: Optional[ControlOutcome]) -> str:
    """Render an outcome as 'icon name' (or '—' if missing)."""
    if outcome is None:
        return "[dim]—[/dim]"
    icon = _OUTCOME_ICONS.get(outcome, "❓")
    return f"{icon} {outcome.value}"


def _maturity_label(level: Optional[MaturityLevel]) -> str:
    """Render a maturity level with its corresponding color."""
    if level is None:
        return "[dim]—[/dim]"
    color = {0: "red", 1: "yellow", 2: "cyan", 3: "green"}.get(level.value, "white")
    return f"[{color}]ML{level.value}[/{color}]"


def _summary_panel(diff: DiffResult) -> Panel:
    """Render the headline summary panel."""
    lines = []

    overall = (
        f"Overall maturity:    "
        f"{_maturity_label(diff.earlier_overall_maturity)} → "
        f"{_maturity_label(diff.later_overall_maturity)}"
    )
    if diff.overall_change == "regressed":
        overall += "  [red]⬇ regressed[/red]"
    elif diff.overall_change == "improved":
        overall += "  [green]⬆ improved[/green]"
    else:
        overall += "  [dim]= unchanged[/dim]"
    lines.append(overall)

    lines.append(f"Controls regressed:  [red]{len(diff.regressed_controls)}[/red]")
    lines.append(f"Controls improved:   [green]{len(diff.improved_controls)}[/green]")
    lines.append(f"Controls unchanged:  [dim]{len(diff.unchanged_controls)}[/dim]")

    # Count checks present in each scan separately for honesty
    earlier_count = sum(
        1 for c in diff.check_deltas
        if c.change_type != "new"  # excludes checks only in later
    )
    later_count = sum(
        1 for c in diff.check_deltas
        if c.change_type != "removed"  # excludes checks only in earlier
    )
    if diff.new_checks or diff.removed_checks:
        schema_note = (
            f"Checks:              {earlier_count} earlier, {later_count} later "
            f"([cyan]+{len(diff.new_checks)} new[/cyan], "
            f"[dim]-{len(diff.removed_checks)} removed[/dim])"
        )
    else:
        schema_note = (
            f"Checks evaluated:    {later_count}"
        )
    lines.append(schema_note)

    return Panel(
        "\n".join(lines),
        title="Summary",
        border_style="cyan",
    )


def _changes_table(
    title: str,
    title_style: str,
    control_deltas: list[ControlDelta],
    check_deltas: list[CheckDelta],
) -> Optional[Group]:
    """Render a section of changes (regressed or improved)."""
    if not control_deltas and not check_deltas:
        return None

    # Group check deltas by control
    by_control: dict[str, list[CheckDelta]] = {}
    for cd in check_deltas:
        by_control.setdefault(cd.control, []).append(cd)

    sections = [Text(title, style=title_style)]

    for control_delta in control_deltas:
        header = (
            f"\n[bold]{control_delta.display_name}[/bold]"
            f"        {_maturity_label(control_delta.earlier_maturity)} → "
            f"{_maturity_label(control_delta.later_maturity)}"
        )
        sections.append(Text.from_markup(header))

        for chk in by_control.get(control_delta.control, []):
            line = (
                f"  {_OUTCOME_ICONS.get(chk.later_outcome, '?')} "
                f"[bold]{chk.check_id}[/bold]  {chk.title}"
            )
            sections.append(Text.from_markup(line))
            sections.append(Text.from_markup(
                f"       [dim]was:[/dim] {_outcome_label(chk.earlier_outcome)}"
            ))
            sections.append(Text.from_markup(
                f"       [dim]now:[/dim] {_outcome_label(chk.later_outcome)}"
            ))

    return Group(*sections)


def _format_date(iso_date: str) -> str:
    """Convert an ISO datetime to a friendlier YYYY-MM-DD HH:MM display."""
    # Drop microseconds and replace T with space; keep timezone info if any
    try:
        clean = iso_date.split(".")[0].replace("T", " ")
        return clean
    except (AttributeError, ValueError):
        return iso_date


def render_diff(diff: DiffResult) -> Group:
    """Render a DiffResult as a rich-renderable report.

    Returns a Group that the caller can pass to console.print().
    """
    sections = []

    # Header — scan metadata
    header = Text()
    header.append("Compliance Diff Report\n", style="bold cyan")
    header.append("=" * 40 + "\n\n", style="dim")

    if not diff.same_host:
        header.append(
            "⚠ Comparing scans from different hosts:\n",
            style="yellow",
        )

    header.append(f"  Earlier: {_format_date(diff.earlier_scan_date)}  ", style="dim")
    header.append(f"{diff.earlier_hostname}\n")
    header.append(f"  Later:   {_format_date(diff.later_scan_date)}  ", style="dim")
    header.append(f"{diff.later_hostname}\n")
    sections.append(header)

    # Summary panel
    sections.append(_summary_panel(diff))

    # Regressed section
    regressed = _changes_table(
        "\n⬇ REGRESSED",
        "bold red",
        diff.regressed_controls,
        diff.regressed_checks,
    )
    if regressed:
        sections.append(regressed)

    # Improved section
    improved = _changes_table(
        "\n⬆ IMPROVED",
        "bold green",
        diff.improved_controls,
        diff.improved_checks,
    )
    if improved:
        sections.append(improved)

    # New / removed checks footer
    if diff.new_checks or diff.removed_checks:
        footer_lines = []
        if diff.new_checks:
            footer_lines.append(f"\n[cyan]+ {len(diff.new_checks)} new check(s) added since the earlier scan:[/cyan]")
            for chk in diff.new_checks:
                footer_lines.append(f"  [cyan]+[/cyan] {chk.check_id}  {chk.title}")
        if diff.removed_checks:
            footer_lines.append(f"\n[dim]- {len(diff.removed_checks)} check(s) removed since the earlier scan:[/dim]")
            for chk in diff.removed_checks:
                footer_lines.append(f"  [dim]-[/dim] {chk.check_id}  {chk.title}")
        sections.append(Text.from_markup("\n".join(footer_lines)))

    # Quiet success case
    if (not diff.regressed_controls and not diff.improved_controls
            and not diff.regressed_checks and not diff.improved_checks
            and not diff.new_checks and not diff.removed_checks):
        sections.append(Text("\nNo changes between the two scans.", style="dim italic"))

    return Group(*sections)
