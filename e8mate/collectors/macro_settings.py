"""Collector for Control 3: Configure Microsoft Office Macro Settings.

Essential Eight Maturity Level 1 requirements:
- Microsoft Office macros are disabled for users that do not have a
  demonstrated business requirement.
- Microsoft Office macros in files originating from the internet are blocked.
- Microsoft Office macro antivirus scanning is enabled.
- Microsoft Office macro security settings cannot be changed by users.
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

# VBAWarnings values:
# 1 = Enable all macros
# 2 = Disable with notification
# 3 = Disable except digitally signed
# 4 = Disable all macros without notification
MACRO_SETTINGS = {1: "Enable all", 2: "Disable with notification", 3: "Signed only", 4: "Disable all"}
OFFICE_APPS = ["Word", "Excel", "PowerPoint"]


class MacroSettingsCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for Office macro settings."""

    control = E8Control.MACRO_SETTINGS
    display_name = "Configure Microsoft Office Macros"

    def collect(self) -> ControlResult:
        """Run all macro settings checks."""
        self._check_macros_disabled()
        self._check_internet_macros_blocked()
        self._check_macro_av_scanning()
        return self.build_result()

    def _check_macros_disabled(self):
        """MS-ML1-001: Macros disabled for standard users."""
        script = """
        $results = @{}
        foreach ($app in @("Word", "Excel", "PowerPoint")) {
            $path = "HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\$app\\Security"
            $val = Get-ItemProperty -Path $path -Name VBAWarnings -ErrorAction SilentlyContinue
            $results[$app] = if ($val) { $val.VBAWarnings } else { $null }
        }
        $results | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="MS-ML1-001",
            control=self.control,
            title="Macros disabled for standard users",
            description="Office macros should be disabled for users without a business requirement.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Configure Group Policy: User Configuration → Administrative Templates → "
                "Microsoft Office → Security → VBA Macro Notification Settings → "
                "set to 'Disable all without notification' (VBAWarnings = 4)."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "registry", output, "VBAWarnings"
            ))

            try:
                data = json.loads(output)
                all_disabled = True
                details = []

                for app in OFFICE_APPS:
                    val = data.get(app)
                    setting = MACRO_SETTINGS.get(val, "Not configured")
                    details.append(f"{app}: {setting}")
                    if val not in (3, 4):
                        all_disabled = False

                if all_disabled:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        f"Macros are restricted across Office apps. {'; '.join(details)}."
                    )
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = (
                        f"Macros not fully restricted. {'; '.join(details)}. "
                        "Set VBAWarnings to 3 (signed only) or 4 (disable all)."
                    )

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_internet_macros_blocked(self):
        """MS-ML1-002: Macros from the internet are blocked."""
        script = """
        $results = @{}
        foreach ($app in @("Word", "Excel", "PowerPoint")) {
            $path = "HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\$app\\Security"
            $val = Get-ItemProperty -Path $path -Name blockcontentexecutionfrominternet -ErrorAction SilentlyContinue
            $results[$app] = if ($val) { $val.blockcontentexecutionfrominternet } else { $null }
        }
        $results | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="MS-ML1-002",
            control=self.control,
            title="Macros from the internet are blocked",
            description="Office should block macros in files downloaded from the internet.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Configure Group Policy: 'Block macros from running in Office files "
                "from the internet' → Enabled for Word, Excel, and PowerPoint."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "registry", output, "blockcontentexecutionfrominternet"
            ))

            try:
                data = json.loads(output)
                all_blocked = True

                for app in OFFICE_APPS:
                    val = data.get(app)
                    if val != 1:
                        all_blocked = False

                if all_blocked:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Internet macros are blocked across all Office apps."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = (
                        "Internet macro blocking is not fully configured. "
                        "Files from the internet may execute macros."
                    )

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_macro_av_scanning(self):
        """MS-ML1-003: Macro antivirus scanning is enabled."""
        script = """
        $path = "HKCU:\\Software\\Policies\\Microsoft\\Office\\Common\\Security"
        $val = Get-ItemProperty -Path $path -Name MacroRuntimeScanScope -ErrorAction SilentlyContinue
        if ($val) {
            @{ MacroRuntimeScanScope = $val.MacroRuntimeScanScope } | ConvertTo-Json
        } else {
            @{ MacroRuntimeScanScope = $null } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="MS-ML1-003",
            control=self.control,
            title="Macro antivirus scanning is enabled",
            description="Office should scan macros with antivirus at runtime.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Enable 'Macro Runtime Scan Scope' via Group Policy or registry. "
                "Ensure Windows Defender or equivalent AV is configured to scan macros."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "registry", output, "MacroRuntimeScanScope"
            ))

            try:
                data = json.loads(output)
                val = data.get("MacroRuntimeScanScope")

                if val is not None and val > 0:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Macro antivirus scanning is enabled."
                elif val == 0:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Macro antivirus scanning is explicitly disabled."
                else:
                    # Not configured — Windows Defender scans macros by default
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        "Macro scan policy not explicitly set. "
                        "Windows Defender scans macros by default."
                    )

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)
