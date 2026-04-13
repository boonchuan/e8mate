"""Base collector class for Essential Eight control checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from e8mate.evidence.models import (
    ControlResult,
    E8Control,
    Evidence,
    Finding,
    MaturityLevel,
)


class BaseCollector(ABC):
    """Abstract base class for all E8 control collectors.

    Each collector is responsible for assessing one Essential Eight control
    at a given maturity level. It runs checks, collects evidence, and
    produces findings that feed into the maturity scorer.
    """

    # Subclasses must set these
    control: E8Control
    display_name: str

    def __init__(self, transport, target_maturity: MaturityLevel = MaturityLevel.ML1):
        """
        Args:
            transport: Transport instance for executing commands (local/winrm/api).
            target_maturity: The maturity level to assess against.
        """
        self.transport = transport
        self.target_maturity = target_maturity
        self.findings: list[Finding] = []

    @abstractmethod
    def collect(self) -> ControlResult:
        """Run all checks for this control and return the result.

        Subclasses implement this to:
        1. Execute checks via self.transport
        2. Create Finding objects with evidence
        3. Return a ControlResult with all findings
        """
        ...

    def run_powershell(self, script: str, description: str = "") -> Optional[str]:
        """Execute a PowerShell command via the transport layer.

        Args:
            script: PowerShell script/command to execute.
            description: Human-readable description of what this check does.

        Returns:
            Command output as string, or None on failure.
        """
        return self.transport.execute_powershell(script)

    def run_cmd(self, command: str) -> Optional[str]:
        """Execute a shell command via the transport layer."""
        return self.transport.execute_cmd(command)

    def create_evidence(self, source: str, raw_output: str, command: str = "") -> Evidence:
        """Create an Evidence object from collected data.

        Output is sanitized to strip control characters and
        truncated to prevent resource exhaustion.
        """
        from e8mate.utils.security import sanitize_evidence
        return Evidence(
            source=source,
            command=command,
            raw_output=sanitize_evidence(raw_output),
        )

    def build_result(self) -> ControlResult:
        """Build a ControlResult from accumulated findings."""
        from e8mate.scoring.maturity import calculate_control_maturity

        result = ControlResult(
            control=self.control,
            display_name=self.display_name,
            target_maturity=self.target_maturity,
            findings=self.findings,
        )
        result.achieved_maturity = calculate_control_maturity(result)
        result.summary = self._generate_summary(result)
        return result

    def _generate_summary(self, result: ControlResult) -> str:
        """Generate a human-readable summary for the control result."""
        effective = result.effective_checks
        total = result.total_checks
        ml = result.achieved_maturity.value

        if effective == total and total > 0:
            return (
                f"All {total} checks passed. "
                f"Maturity Level {ml} achieved for {self.display_name}."
            )
        elif effective == 0:
            return (
                f"No checks passed ({total} assessed). "
                f"{self.display_name} is at Maturity Level 0."
            )
        else:
            return (
                f"{effective}/{total} checks passed. "
                f"{self.display_name} achieved Maturity Level {ml}."
            )
