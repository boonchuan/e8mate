"""Collector for Control 4: User Application Hardening.

Essential Eight Maturity Level 1 requirements:
- Web browsers do not process Java from the internet.
- Web browsers do not process web advertisements from the internet.
- Internet Explorer 11 does not process content from the internet.
- Web browsers are configured to block or disable support for Flash content.
- Microsoft Office is blocked from creating child processes.
- Microsoft Office is configured to prevent activation of OLE packages.
- PowerShell script block logging is enabled.
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


class AppHardeningCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for user application hardening."""

    control = E8Control.APP_HARDENING
    display_name = "User Application Hardening"

    def collect(self) -> ControlResult:
        """Run all application hardening checks."""
        self._check_ie11_disabled()
        self._check_powershell_logging()
        self._check_powershell_language_mode()
        self._check_dotnet_legacy()
        self._check_powershell_logging()
        self._check_cmd_process_logging()

    def _check_powershell_logging(self):
        """AH-ML2-001: PowerShell script block logging is enabled."""
        script = """
        $psLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
        @{
            EnableScriptBlockLogging = $psLogging.EnableScriptBlockLogging
            EnableScriptBlockInvocationLogging = $psLogging.EnableScriptBlockInvocationLogging
            PolicyConfigured = ($null -ne $psLogging)
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AH-ML2-001",
            control=self.control,
            title="PowerShell script block logging enabled",
            description="ML2 requires PowerShell script block logging to detect malicious script execution.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.HIGH,
            remediation="Enable PowerShell Script Block Logging via Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "PowerShell ScriptBlockLogging"))
            try:
                import json
                settings = json.loads(output)
                if settings.get("EnableScriptBlockLogging") == 1:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "PowerShell script block logging is enabled."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "PowerShell script block logging is not enabled."
            except Exception:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_cmd_process_logging(self):
        """AH-ML2-002: Command line process creation events are logged."""
        script = """
        $cmdLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue
        @{
            ProcessCreationIncludeCmdLine = $cmdLogging.ProcessCreationIncludeCmdLine_Enabled
            PolicyConfigured = ($null -ne $cmdLogging)
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AH-ML2-002",
            control=self.control,
            title="Command line process creation logging enabled",
            description="ML2 requires command line process creation events to be logged.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.HIGH,
            remediation="Enable 'Include command line in process creation events' via Group Policy: Computer Configuration > Administrative Templates > System > Audit Process Creation.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "Process Creation Audit"))
            try:
                import json
                settings = json.loads(output)
                if settings.get("ProcessCreationIncludeCmdLine") == 1:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Command line process creation logging is enabled."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Command line process creation logging is not enabled."
            except Exception:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)


        return self.build_result()

    def _check_ie11_disabled(self):
        """AH-ML1-001: Internet Explorer 11 is disabled."""
        script = """
        $ie = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Internet Explorer\\Main" -Name NotifyDisableIEOptions -ErrorAction SilentlyContinue
        $featureDisable = Get-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -ErrorAction SilentlyContinue
        @{
            PolicySet = if ($ie) { $true } else { $false }
            FeatureState = if ($featureDisable) { $featureDisable.State } else { "Unknown" }
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AH-ML1-001",
            control=self.control,
            title="Internet Explorer 11 is disabled",
            description="IE11 should not process content from the internet.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Disable IE11 via Windows Features or Group Policy. "
                "On Windows 11, IE11 is already removed."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "IE11 status"))

            try:
                data = json.loads(output)
                state = str(data.get("FeatureState", "")).lower()

                if state in ("disabled", "disabledwithpayloadremoved", "unknown"):
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "IE11 is disabled or not present on this system."
                elif state == "enabled":
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "IE11 is enabled. It should be disabled to reduce attack surface."
                else:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = f"IE11 feature state: {state}."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_powershell_logging(self):
        """AH-ML1-002: PowerShell script block logging is enabled."""
        script = """
        $logging = Get-ItemProperty -Path "HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -ErrorAction SilentlyContinue
        @{
            EnableScriptBlockLogging = if ($logging) { $logging.EnableScriptBlockLogging } else { $null }
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AH-ML1-002",
            control=self.control,
            title="PowerShell script block logging is enabled",
            description="Script block logging provides visibility into PowerShell activity for incident detection.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Enable via Group Policy: Computer Configuration → Administrative Templates → "
                "Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "ScriptBlockLogging"))

            try:
                data = json.loads(output)
                val = data.get("EnableScriptBlockLogging")

                if val == 1:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "PowerShell script block logging is enabled."
                elif val == 0:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "PowerShell script block logging is explicitly disabled."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "PowerShell script block logging is not configured."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_powershell_language_mode(self):
        """AH-ML1-003: PowerShell is in Constrained Language Mode."""
        script = "$ExecutionContext.SessionState.LanguageMode"
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AH-ML1-003",
            control=self.control,
            title="PowerShell Constrained Language Mode",
            description="PowerShell should run in Constrained Language Mode to limit attack capability.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.MEDIUM,
            remediation=(
                "Configure Constrained Language Mode via WDAC or AppLocker. "
                "This restricts PowerShell to core cmdlets and prevents .NET access."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "LanguageMode"))

            mode = output.strip().lower()
            if "constrained" in mode:
                finding.outcome = ControlOutcome.EFFECTIVE
                finding.description = "PowerShell is in Constrained Language Mode."
            elif "full" in mode:
                finding.outcome = ControlOutcome.INEFFECTIVE
                finding.description = (
                    "PowerShell is in Full Language Mode. "
                    "This allows unrestricted .NET and COM access."
                )
            else:
                finding.outcome = ControlOutcome.EFFECTIVE
                finding.description = f"PowerShell language mode: {output.strip()}."
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_dotnet_legacy(self):
        """AH-ML1-004: Legacy .NET Framework 3.5 is disabled."""
        script = """
        $feature = Get-WindowsOptionalFeature -Online -FeatureName NetFx3 -ErrorAction SilentlyContinue
        @{
            State = if ($feature) { $feature.State } else { "NotFound" }
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AH-ML1-004",
            control=self.control,
            title=".NET Framework 3.5 is disabled",
            description="Legacy .NET Framework (2.0/3.0/3.5) should be disabled to reduce attack surface.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.MEDIUM,
            remediation="Disable .NET Framework 3.5 via Windows Features if not required by applications.",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "NetFx3 feature"))

            try:
                data = json.loads(output)
                state = str(data.get("State", "")).lower()

                if state in ("disabled", "disabledwithpayloadremoved", "notfound"):
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = ".NET Framework 3.5 is disabled or not installed."
                elif state == "enabled":
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = ".NET Framework 3.5 is enabled. Disable if not required."
                else:
                    finding.outcome = ControlOutcome.NO_VISIBILITY

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)
