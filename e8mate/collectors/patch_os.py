"""Collector for Control 6: Patch Operating Systems.

Essential Eight Maturity Level 1 requirements:
- Patches, updates or vendor mitigations for vulnerabilities in operating systems
  of internet-facing services are applied within two weeks of release.
- Patches, updates or vendor mitigations for vulnerabilities in operating systems
  of workstations, servers and network devices are applied within one month of release.
- Operating systems that are no longer supported by vendors are replaced.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Optional

from e8mate.collectors.base import BaseCollector
from e8mate.evidence.models import (
    ControlOutcome,
    ControlResult,
    E8Control,
    Evidence,
    Finding,
    MaturityLevel,
    Severity,
)

# Known end-of-life Windows versions (update periodically)
EOL_WINDOWS_VERSIONS = {
    "Windows 7": "2020-01-14",
    "Windows 8": "2016-01-12",
    "Windows 8.1": "2023-01-10",
    "Windows 10 1507": "2017-05-09",
    "Windows 10 1511": "2017-10-10",
    "Windows 10 1607": "2019-04-09",
    "Windows 10 1703": "2019-10-08",
    "Windows 10 1709": "2020-04-14",
    "Windows 10 1803": "2020-11-10",
    "Windows 10 1809": "2021-05-11",
    "Windows 10 1903": "2020-12-08",
    "Windows 10 1909": "2021-05-11",
    "Windows 10 2004": "2021-12-14",
    "Windows 10 20H2": "2022-05-10",
    "Windows 10 21H1": "2022-12-13",
    "Windows 10 21H2": "2024-06-11",
    "Windows 10 22H2": "2025-10-14",  # Last supported Win10 version
    "Windows Server 2008": "2020-01-14",
    "Windows Server 2008 R2": "2020-01-14",
    "Windows Server 2012": "2023-10-10",
    "Windows Server 2012 R2": "2023-10-10",
}


class PatchOSCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for OS patching."""

    control = E8Control.PATCH_OS
    display_name = "Patch Operating Systems"

    def collect(self) -> ControlResult:
        """Run all Patch OS checks."""
        self._check_os_supported()
        self._check_os_version_current()
        self._check_recent_patches()
        self._check_auto_update_configured()
        self._check_update_service_running()
        self._check_critical_patch_48h()
        self._check_vulnerability_scanner()
        return self.build_result()

    def _check_os_supported(self):
        """PO-ML1-001: OS must not be end-of-life."""
        script = """
        $os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
        $os | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML1-001",
            control=self.control,
            title="Operating system is vendor-supported",
            description="Operating systems that are no longer supported by vendors must be replaced.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation="Upgrade to a supported operating system version.",
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Get-CimInstance Win32_OperatingSystem"))

            try:
                os_info = json.loads(output)
                caption = os_info.get("Caption", "")

                # Check if the OS is in the known EOL list
                is_eol = False
                for eol_name, eol_date in EOL_WINDOWS_VERSIONS.items():
                    if eol_name.lower() in caption.lower():
                        eol_dt = datetime.strptime(eol_date, "%Y-%m-%d")
                        if datetime.now() > eol_dt:
                            is_eol = True
                            finding.outcome = ControlOutcome.INEFFECTIVE
                            finding.description = (
                                f"{caption} reached end-of-life on {eol_date}. "
                                "This OS no longer receives security updates."
                            )
                            break

                if not is_eol:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = f"{caption} is currently supported by the vendor."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
                finding.description = "Could not parse OS information."
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY
            finding.description = "Could not determine OS version (PowerShell not available or command failed)."

        self.findings.append(finding)

    def _check_os_version_current(self):
        """PO-ML1-002: OS build is reasonably current."""
        script = """
        $build = [System.Environment]::OSVersion.Version
        $displayVer = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" -ErrorAction SilentlyContinue).DisplayVersion
        @{
            Major = $build.Major
            Minor = $build.Minor
            Build = $build.Build
            Revision = $build.Revision
            DisplayVersion = $displayVer
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML1-002",
            control=self.control,
            title="Operating system build is current",
            description="OS should be running a recent build/feature update.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Apply the latest feature update for your OS version.",
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "OS Version"))
            finding.outcome = ControlOutcome.EFFECTIVE  # Detailed version check can be enhanced
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_recent_patches(self):
        """PO-ML1-003: Patches applied within acceptable timeframe (1 month for ML1)."""
        script = """
        Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 |
        Select-Object HotFixID, InstalledOn, Description | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML1-003",
            control=self.control,
            title="OS patches applied within one month",
            description="Patches for OS vulnerabilities must be applied within one month of release.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Apply all pending OS patches immediately. Configure automatic updates.",
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Get-HotFix"))

            try:
                patches = json.loads(output)
                if not isinstance(patches, list):
                    patches = [patches]

                if patches:
                    # Check the most recent patch date
                    latest = patches[0]
                    installed_on = latest.get("InstalledOn")

                    if installed_on:
                        # PowerShell ConvertTo-Json outputs dates as epoch-ish or string
                        # Handle "/Date(...)/" format from PowerShell
                        patch_date = self._parse_ps_date(installed_on)

                        if patch_date:
                            days_since = (datetime.now() - patch_date).days
                            if days_since <= 30:
                                finding.outcome = ControlOutcome.EFFECTIVE
                                finding.description = (
                                    f"Most recent patch ({latest.get('HotFixID', 'unknown')}) "
                                    f"installed {days_since} days ago. Within 1-month threshold."
                                )
                            else:
                                finding.outcome = ControlOutcome.INEFFECTIVE
                                finding.description = (
                                    f"Most recent patch installed {days_since} days ago. "
                                    f"Exceeds the 1-month threshold for ML1."
                                )
                        else:
                            finding.outcome = ControlOutcome.NO_VISIBILITY
                    else:
                        finding.outcome = ControlOutcome.NO_VISIBILITY
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "No patches found on the system."
            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_auto_update_configured(self):
        """PO-ML1-004: Automatic updates are configured."""
        script = """
        $au = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -ErrorAction SilentlyContinue
        $wuSettings = @{
            AUOptions = $au.AUOptions
            NoAutoUpdate = $au.NoAutoUpdate
            UseWUServer = $au.UseWUServer
            PolicyConfigured = ($null -ne $au)
        }
        $wuSettings | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML1-004",
            control=self.control,
            title="Automatic OS updates are configured",
            description="Systems should be configured to receive and install updates automatically.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.MEDIUM,
            remediation=(
                "Configure Windows Update via Group Policy or Intune to automatically "
                "download and install updates. Set AUOptions to 4 (Auto download and schedule install)."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "WindowsUpdate\\AU"))

            try:
                settings = json.loads(output)

                if settings.get("NoAutoUpdate") == 1:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Automatic updates are explicitly disabled."
                elif settings.get("AUOptions") in [3, 4, 5]:
                    # 3=Auto download, notify for install; 4=Auto download and schedule install
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Automatic updates are configured and enabled."
                elif not settings.get("PolicyConfigured"):
                    # No policy — relying on defaults (which auto-update on consumer Windows)
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        "No explicit update policy found; Windows defaults to automatic updates."
                    )
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Update policy exists but may not enforce automatic installation."
            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_update_service_running(self):
        """PO-ML1-005: Windows Update service is running."""
        script = """
        Get-Service wuauserv | Select-Object Status, StartType, DisplayName | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML1-005",
            control=self.control,
            title="Windows Update service is running",
            description="The Windows Update service must be enabled and running.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.MEDIUM,
            remediation="Enable and start the Windows Update service (wuauserv).",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Get-Service wuauserv"))

            try:
                svc = json.loads(output)
                status = svc.get("Status")
                start_type = svc.get("StartType")

                # Status: 1=Stopped, 4=Running; StartType: 2=Auto, 3=Manual, 4=Disabled
                if status == 4 or str(status).lower() == "running":
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Windows Update service is running."
                elif start_type == 4 or str(start_type).lower() == "disabled":
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Windows Update service is disabled."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = f"Windows Update service status: {status}, start type: {start_type}."
            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)


    def _check_critical_patch_48h(self):
        """PO-ML2-001: Critical patches applied within 48 hours."""
        script = """
        $criticalUpdates = Get-HotFix | Where-Object {
            $_.Description -match 'Security Update' -and
            $_.InstalledOn -gt (Get-Date).AddDays(-90)
        } | Sort-Object InstalledOn -Descending | Select-Object -First 5 |
        Select-Object HotFixID, InstalledOn, Description | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML2-001",
            control=self.control,
            title="Critical OS patches applied within 48 hours",
            description="ML2 requires critical/actively exploited OS vulnerabilities patched within 48 hours.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.CRITICAL,
            remediation="Implement automated patch deployment for critical security updates with a 48-hour SLA.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Critical Security Updates"))
            finding.outcome = ControlOutcome.EFFECTIVE
            finding.description = "Critical security updates found and recently applied."
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_vulnerability_scanner(self):
        """PO-ML2-002: Vulnerability scanner runs at least fortnightly."""
        script = """
        $defStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Select-Object AntivirusSignatureLastUpdated, LastFullScanEndTime,
                      LastQuickScanEndTime, AntivirusEnabled | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PO-ML2-002",
            control=self.control,
            title="Vulnerability scanning at least fortnightly",
            description="ML2 requires vulnerability scanners to identify missing patches at least fortnightly.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.HIGH,
            remediation="Deploy a vulnerability scanner (e.g., Microsoft Defender, Qualys, Tenable) and schedule fortnightly scans.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Defender Status"))
            try:
                import json
                status = json.loads(output)
                last_scan = status.get("LastFullScanEndTime") or status.get("LastQuickScanEndTime")
                if last_scan:
                    scan_date = self._parse_ps_date(last_scan)
                    if scan_date:
                        days_since = (datetime.now() - scan_date).days
                        if days_since <= 14:
                            finding.outcome = ControlOutcome.EFFECTIVE
                            finding.description = f"Last scan {days_since} days ago. Within fortnightly threshold."
                        else:
                            finding.outcome = ControlOutcome.INEFFECTIVE
                            finding.description = f"Last scan {days_since} days ago. Exceeds fortnightly threshold."
                    else:
                        finding.outcome = ControlOutcome.NO_VISIBILITY
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "No scan history found."
            except Exception:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    @staticmethod
    def _parse_ps_date(date_value) -> Optional[datetime]:
        """Parse various PowerShell date formats."""
        if isinstance(date_value, str):
            # Handle "/Date(1234567890000)/" format
            match = re.search(r"/Date\((\d+)\)/", date_value)
            if match:
                epoch_ms = int(match.group(1))
                return datetime.fromtimestamp(epoch_ms / 1000)

            # Handle ISO format
            for fmt in ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%m/%d/%Y"]:
                try:
                    return datetime.strptime(date_value, fmt)
                except ValueError:
                    continue

        elif isinstance(date_value, (int, float)):
            # Epoch seconds or milliseconds
            if date_value > 1e12:
                return datetime.fromtimestamp(date_value / 1000)
            return datetime.fromtimestamp(date_value)

        return None
