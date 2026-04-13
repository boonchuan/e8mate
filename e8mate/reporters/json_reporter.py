"""JSON reporter for E8Mate scan results."""

from __future__ import annotations

import json
from pathlib import Path

from e8mate.evidence.models import ScanResult


def generate_json_report(result: ScanResult, output_path: str | Path) -> Path:
    """Generate a JSON report from scan results.

    Args:
        result: Complete scan result.
        output_path: Path to write the JSON file.

    Returns:
        Path to the generated report.
    """
    path = Path(output_path)
    data = result.model_dump(mode="json")
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


def load_scan_result(input_path: str | Path) -> ScanResult:
    """Load a scan result from a JSON file."""
    path = Path(input_path)
    data = json.loads(path.read_text())
    return ScanResult.model_validate(data)
