"""Collector for Control 8: Regular Backups.

Essential Eight Maturity Level 1 requirements:
- Backups of important data, software and configuration settings are performed
  and retained in a coordinated and resilient manner.
- Backups are performed at a frequency aligned with the RPO.
- Backups are stored offline or in a separate location.
- Backup access is restricted to break-glass accounts.
- Unprivileged accounts cannot modify or delete backups.
"""

from __future__ import annotations

import json

from e8mate.collectors.base import BaseCollector
from e8mate.evidence.models import (
    ControlOutcome,
    ControlResult,
    E8Control,
    Finding,
    MaturityLevel,
    Severity,
)


class BackupsCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for regular backups."""

    control = E8Control.BACKUPS
    display_name = "Regular Backups"

    def collect(self) -> ControlResult:
        """Run all backup checks."""
        self._check_vss_enabled()
        self._check_backup_exists()
        self._check_backup_recent()
        return self.build_result()

    def _check_vss_enabled(self):
        """BK-ML1-001: Volume Shadow Copy service is available."""
        script = "Get-Service VSS | Select-Object Status, StartType, DisplayName | ConvertTo-Json"
        output = self.run_powershell(script)

        finding = Finding(
            check_id="BK-ML1-001",
            control=self.control,
            title="Volume Shadow Copy service is available",
            description="VSS must be available for backup and restore operations.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Ensure the Volume Shadow Copy service (VSS) is set to Manual or Automatic.",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "VSS service"))

            try:
                data = json.loads(output)
                status = data.get("Status")
                start_type = data.get("StartType")

                if start_type == 4 or str(start_type).lower() == "disabled":
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Volume Shadow Copy service is disabled."
                else:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Volume Shadow Copy service is available."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_backup_exists(self):
        """BK-ML1-002: Backups are being performed."""
        script = """
        $wbResult = $null
        try {
            $wbResult = Get-WBSummary -ErrorAction Stop
        } catch {}

        $vssResult = vssadmin list shadows 2>$null

        @{
            WindowsBackup = if ($wbResult) {
                @{
                    LastSuccess = $wbResult.LastSuccessfulBackupTime
                    Versions = $wbResult.NumberOfVersions
                }
            } else { $null }
            VSShadows = if ($vssResult -match "shadow copy") { $true } else { $false }
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="BK-ML1-002",
            control=self.control,
            title="Backups are being performed",
            description="Regular backups of important data must be performed.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Configure Windows Server Backup, a third-party backup solution, "
                "or cloud backup. Ensure backups include system state and critical data."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Backup status"))

            try:
                data = json.loads(output)
                has_wb = data.get("WindowsBackup") is not None
                has_vss = data.get("VSShadows", False)

                if has_wb:
                    versions = data["WindowsBackup"].get("Versions", 0)
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        f"Windows Backup is configured with {versions} backup version(s)."
                    )
                elif has_vss:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Volume shadow copies detected. Backups are being created."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "No Windows Backup or shadow copies detected."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_backup_recent(self):
        """BK-ML1-003: Most recent backup is within acceptable timeframe."""
        script = """
        try {
            $wb = Get-WBSummary -ErrorAction Stop
            @{
                LastSuccess = $wb.LastSuccessfulBackupTime.ToString("yyyy-MM-ddTHH:mm:ss")
                LastAttempt = $wb.LastBackupTime.ToString("yyyy-MM-ddTHH:mm:ss")
            } | ConvertTo-Json
        } catch {
            @{ "not_available" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="BK-ML1-003",
            control=self.control,
            title="Backups are recent",
            description="The most recent successful backup should be within the last 7 days.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Investigate why backups are not running. Check backup schedules and storage space.",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Last backup time"))

            try:
                data = json.loads(output)

                if data.get("not_available"):
                    finding.outcome = ControlOutcome.NO_VISIBILITY
                    finding.description = "Windows Backup not available to check recency."
                else:
                    last_success = data.get("LastSuccess", "")
                    if last_success:
                        from datetime import datetime
                        try:
                            backup_dt = datetime.fromisoformat(last_success)
                            days_ago = (datetime.now() - backup_dt).days
                            if days_ago <= 7:
                                finding.outcome = ControlOutcome.EFFECTIVE
                                finding.description = f"Last successful backup was {days_ago} day(s) ago."
                            else:
                                finding.outcome = ControlOutcome.INEFFECTIVE
                                finding.description = f"Last backup was {days_ago} days ago. Exceeds 7-day threshold."
                        except ValueError:
                            finding.outcome = ControlOutcome.NO_VISIBILITY
                    else:
                        finding.outcome = ControlOutcome.NO_VISIBILITY

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)
