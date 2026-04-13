"""HTML report generator for E8Mate scan results.

Produces a self-contained, print-friendly HTML report suitable for
handing to clients, auditors, or board members. Includes executive
summary, maturity heatmap, per-control findings, and remediation roadmap.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from e8mate.evidence.models import ScanResult
from e8mate.scoring.maturity import generate_remediation_priority
from e8mate.utils.security import sanitize_html, set_report_permissions


TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(result: ScanResult, output_path: str | Path) -> Path:
    """Generate an audit-ready HTML report from scan results.

    Args:
        result: Complete scan result.
        output_path: Path to write the HTML file.

    Returns:
        Path to the generated report.
    """
    path = Path(output_path)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )

    # Register custom filters
    env.filters["upper"] = str.upper

    template = env.get_template("report.html.j2")

    # Calculate summary stats
    total_checks = sum(cr.total_checks for cr in result.control_results)
    effective_checks = sum(cr.effective_checks for cr in result.control_results)
    ineffective_checks = sum(cr.ineffective_checks for cr in result.control_results)
    pass_rate = f"{(effective_checks / total_checks * 100):.0f}" if total_checks > 0 else "0"

    # Generate remediation roadmap
    remediation_items = generate_remediation_priority(result)

    # Render
    html = template.render(
        scan_id=result.scan_id,
        scan_date=result.scan_date.strftime("%Y-%m-%d %H:%M:%S"),
        scanner_version=result.scanner_version,
        target_maturity=result.target_maturity.value,
        overall_maturity=result.overall_maturity.value,
        system_info=result.system_info,
        control_results=result.control_results,
        remediation_items=remediation_items,
        scan_duration=result.scan_duration_seconds,
        total_checks=total_checks,
        effective_checks=effective_checks,
        ineffective_checks=ineffective_checks,
        pass_rate=pass_rate,
    )

    path.write_text(html, encoding="utf-8")
    set_report_permissions(path)

    return path
