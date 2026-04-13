"""Maturity scoring engine for Essential Eight controls.

Per ASD assessment process guide:
- ALL controls within a strategy must be 'effective' or 'alternate_control'
  to claim that maturity level.
- Overall maturity = minimum maturity level across all 8 controls.
"""

from __future__ import annotations

from e8mate.evidence.models import (
    ControlOutcome,
    ControlResult,
    Finding,
    MaturityLevel,
    ScanResult,
)


def calculate_control_maturity(result: ControlResult) -> MaturityLevel:
    """Calculate achieved maturity level for a single control.

    ASD rule: ALL checks for a maturity level must be effective.
    We assess from ML1 upward — if ML1 checks fail, maturity is ML0.
    """
    if not result.findings:
        return MaturityLevel.ML0

    # Group findings by maturity level
    by_level: dict[int, list[Finding]] = {}
    for finding in result.findings:
        level = finding.maturity_level.value
        by_level.setdefault(level, []).append(finding)

    achieved = MaturityLevel.ML0

    # Check each level in order — must pass all checks at a level to claim it
    for level in [1, 2, 3]:
        level_findings = by_level.get(level, [])
        if not level_findings:
            # No checks defined for this level — can't assess it
            break

        all_effective = all(
            f.outcome in (ControlOutcome.EFFECTIVE, ControlOutcome.ALTERNATE_CONTROL, ControlOutcome.NOT_APPLICABLE)
            for f in level_findings
        )

        if all_effective:
            achieved = MaturityLevel(level)
        else:
            # Failed at this level — can't claim higher
            break

    return achieved


def calculate_overall_maturity(scan_result: ScanResult) -> MaturityLevel:
    """Calculate overall Essential Eight maturity.

    Per ASD: overall maturity = minimum across all 8 controls.
    If any control is ML0, overall is ML0.
    """
    if not scan_result.control_results:
        return MaturityLevel.ML0

    return MaturityLevel(
        min(cr.achieved_maturity.value for cr in scan_result.control_results)
    )


def generate_remediation_priority(scan_result: ScanResult) -> list[dict]:
    """Generate a prioritised remediation list.

    Priority order:
    1. Controls at ML0 (biggest gaps first)
    2. Within each control, critical findings before high/medium/low
    3. Quick wins (low effort fixes) highlighted
    """
    remediation_items = []

    for cr in scan_result.control_results:
        for finding in cr.findings:
            if finding.outcome == ControlOutcome.INEFFECTIVE:
                remediation_items.append({
                    "control": cr.display_name,
                    "check_id": finding.check_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "remediation": finding.remediation or "See ASD guidance.",
                    "asd_reference": finding.asd_reference,
                    "maturity_level": finding.maturity_level.value,
                })

    # Sort: critical first, then by maturity level (ML1 fixes before ML2)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    remediation_items.sort(
        key=lambda x: (x["maturity_level"], severity_order.get(x["severity"], 5))
    )

    return remediation_items
