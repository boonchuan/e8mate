"""Collector for Control 2: Patch Applications.

Essential Eight Maturity Level 1 requirements:
- Patches for internet-facing applications are applied within two weeks of release.
- Patches for other applications are applied within one month of release.
- Applications no longer supported by vendors are removed.
- A vulnerability scanner is used at least fortnightly.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from e8mate.collectors.base import BaseCollector
from e8mate.evidence.models import (
    ControlOutcome,
    ControlResult,
    E8Control,
    Finding,
    MaturityLevel,
    Severity,
)

# Known EOL applications to flag
EOL_APPS = {
    "adobe flash player", "internet explorer",
    "microsoft silverlight", "java 6", "java 7",
    "python 2", "windows media player",
}


class PatchAppsCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for application patching."""

    control = E8Control.PATCH_APPS
    display_name = "Patch Applications"

    def collect(self) -> ControlResult:
        """Run all application patching checks."""
        self._check_installed_apps()
        self._check_browser_versions()
        self._check_office_version()
        return self.build_result()

    def _check_installed_apps(self):
        """PA-ML1-001: Enumerate installed applications and flag EOL software."""
        script = """
        Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
        Where-Object { $_.DisplayName -ne $null } |
        Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
        ConvertTo-Json -Compress
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PA-ML1-001",
            control=self.control,
            title="Unsupported applications are removed",
            description="Applications no longer supported by vendors must be removed.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation="Remove end-of-life applications that no longer receive security updates.",
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "registry", output, "Installed applications"
            ))

            try:
                apps = json.loads(output)
                if not isinstance(apps, list):
                    apps = [apps]

                eol_found = []
                for app in apps:
                    name = (app.get("DisplayName") or "").lower()
                    for eol in EOL_APPS:
                        if eol in name:
                            eol_found.append(app.get("DisplayName", "unknown"))
                            break

                if eol_found:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = (
                        f"Found {len(eol_found)} end-of-life application(s): "
                        f"{', '.join(eol_found[:5])}."
                    )
                else:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        f"Scanned {len(apps)} installed applications. "
                        "No known end-of-life software detected."
                    )

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_browser_versions(self):
        """PA-ML1-002: Web browsers are up to date."""
        script = """
        $browsers = @{}
        $chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
        $edgePath = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
        $firefoxPath = "C:\\Program Files\\Mozilla Firefox\\firefox.exe"

        if (Test-Path $chromePath) {
            $browsers["Chrome"] = (Get-Item $chromePath).VersionInfo.ProductVersion
        }
        if (Test-Path $edgePath) {
            $browsers["Edge"] = (Get-Item $edgePath).VersionInfo.ProductVersion
        }
        if (Test-Path $firefoxPath) {
            $browsers["Firefox"] = (Get-Item $firefoxPath).VersionInfo.ProductVersion
        }
        $browsers | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PA-ML1-002",
            control=self.control,
            title="Web browsers are current",
            description="Internet-facing applications (browsers) must be patched within 2 weeks.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Update all web browsers to the latest version. Enable automatic updates.",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "powershell", output, "Browser versions"
            ))

            try:
                data = json.loads(output)
                if data:
                    versions = [f"{k}: {v}" for k, v in data.items()]
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        f"Detected browsers: {'; '.join(versions)}. "
                        "Verify these are the latest versions from vendor sites."
                    )
                else:
                    finding.outcome = ControlOutcome.NO_VISIBILITY
                    finding.description = "No browsers detected at standard paths."
            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_office_version(self):
        """PA-ML1-003: Microsoft Office is up to date."""
        script = """
        $office = Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration" -ErrorAction SilentlyContinue
        if ($office) {
            @{
                VersionToReport = $office.VersionToReport
                Channel = $office.CDNBaseUrl
                UpdatesEnabled = $office.UpdatesEnabled
                Platform = $office.Platform
            } | ConvertTo-Json
        } else {
            @{ "not_installed" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="PA-ML1-003",
            control=self.control,
            title="Microsoft Office is up to date",
            description="Office should be on a supported version with updates enabled.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Update Microsoft Office and ensure automatic updates are enabled.",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "Office version"))

            try:
                data = json.loads(output)
                if data.get("not_installed"):
                    finding.outcome = ControlOutcome.NOT_APPLICABLE
                    finding.description = "Microsoft Office (Click-to-Run) not detected."
                else:
                    version = data.get("VersionToReport", "unknown")
                    updates = data.get("UpdatesEnabled", "unknown")
                    if str(updates).lower() == "true":
                        finding.outcome = ControlOutcome.EFFECTIVE
                        finding.description = f"Office version {version}, auto-updates enabled."
                    else:
                        finding.outcome = ControlOutcome.INEFFECTIVE
                        finding.description = f"Office version {version}, auto-updates disabled."
            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)
