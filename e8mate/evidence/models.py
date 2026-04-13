"""Data models for E8Mate scan results, findings, and scoring."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class MaturityLevel(int, Enum):
    """ASD Essential Eight Maturity Levels."""
    ML0 = 0
    ML1 = 1
    ML2 = 2
    ML3 = 3


class ControlOutcome(str, Enum):
    """ASD-standard assessment outcomes."""
    NOT_ASSESSED = "not_assessed"
    EFFECTIVE = "effective"
    ALTERNATE_CONTROL = "alternate_control"
    INEFFECTIVE = "ineffective"
    NO_VISIBILITY = "no_visibility"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class E8Control(str, Enum):
    """The eight Essential Eight controls."""
    APP_CONTROL = "application_control"
    PATCH_APPS = "patch_applications"
    MACRO_SETTINGS = "macro_settings"
    APP_HARDENING = "user_application_hardening"
    ADMIN_PRIVILEGES = "restrict_admin_privileges"
    PATCH_OS = "patch_operating_systems"
    MFA = "multi_factor_authentication"
    BACKUPS = "regular_backups"


class Evidence(BaseModel):
    """Raw evidence collected during a scan."""
    source: str = Field(description="Where this evidence came from (e.g., 'registry', 'powershell', 'api')")
    command: Optional[str] = Field(default=None, description="Command or query that produced this evidence")
    raw_output: str = Field(description="Raw output from the collection")
    timestamp: datetime = Field(default_factory=datetime.now)


class Finding(BaseModel):
    """A single check result within a control."""
    check_id: str = Field(description="Unique check identifier (e.g., 'PO-ML1-001')")
    control: E8Control
    title: str
    description: str
    outcome: ControlOutcome = ControlOutcome.NOT_ASSESSED
    severity: Severity = Severity.MEDIUM
    maturity_level: MaturityLevel = MaturityLevel.ML1
    evidence: list[Evidence] = Field(default_factory=list)
    remediation: Optional[str] = Field(default=None, description="Steps to fix if ineffective")
    asd_reference: Optional[str] = Field(default=None, description="Link to relevant ASD guidance")


class ControlResult(BaseModel):
    """Aggregated result for one Essential Eight control."""
    control: E8Control
    display_name: str
    achieved_maturity: MaturityLevel = MaturityLevel.ML0
    target_maturity: MaturityLevel = MaturityLevel.ML1
    findings: list[Finding] = Field(default_factory=list)
    summary: str = ""

    @property
    def total_checks(self) -> int:
        return len(self.findings)

    @property
    def effective_checks(self) -> int:
        return len([f for f in self.findings if f.outcome in (
            ControlOutcome.EFFECTIVE, ControlOutcome.ALTERNATE_CONTROL
        )])

    @property
    def ineffective_checks(self) -> int:
        return len([f for f in self.findings if f.outcome == ControlOutcome.INEFFECTIVE])

    @property
    def pass_rate(self) -> float:
        if self.total_checks == 0:
            return 0.0
        return self.effective_checks / self.total_checks


class SystemInfo(BaseModel):
    """Information about the scanned system."""
    hostname: str = "unknown"
    os_name: str = "unknown"
    os_version: str = "unknown"
    os_build: str = "unknown"
    domain: Optional[str] = None
    is_domain_joined: bool = False
    scan_type: str = "local"  # local, winrm, cloud
    target: str = "localhost"


class ScanResult(BaseModel):
    """Complete scan result containing all control assessments."""
    scan_id: str = Field(default_factory=lambda: datetime.now().strftime("%Y%m%d-%H%M%S"))
    scan_date: datetime = Field(default_factory=datetime.now)
    scanner_version: str = "0.1.0"
    target_maturity: MaturityLevel = MaturityLevel.ML1
    system_info: SystemInfo = Field(default_factory=SystemInfo)
    control_results: list[ControlResult] = Field(default_factory=list)
    overall_maturity: MaturityLevel = MaturityLevel.ML0
    scan_duration_seconds: float = 0.0

    def calculate_overall_maturity(self) -> MaturityLevel:
        """Per ASD: overall maturity = minimum across all controls."""
        if not self.control_results:
            return MaturityLevel.ML0
        self.overall_maturity = MaturityLevel(
            min(cr.achieved_maturity.value for cr in self.control_results)
        )
        return self.overall_maturity
