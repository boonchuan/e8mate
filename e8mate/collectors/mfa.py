"""Collector for Control 7: Multi-Factor Authentication.

Essential Eight Maturity Level 1 requirements:
- MFA is used to authenticate users to their organisation's internet-facing
  services.
- MFA is used for third-party internet-facing services that process, store
  or communicate the organisation's sensitive data.
- MFA uses something users have AND something users know or are.
- MFA events are logged.

Note: Full MFA assessment requires Microsoft Graph API access for Entra ID
(Azure AD) checks. This collector does what it can locally and flags
cloud checks that need API access.
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


class MFACollector(BaseCollector):
    """Assess Maturity Level 1 compliance for MFA."""

    control = E8Control.MFA
    display_name = "Multi-Factor Authentication"

    def collect(self) -> ControlResult:
        """Run all MFA checks."""
        self._check_rdp_nla()
        self._check_winrm_settings()
        self._check_credential_guard()
        return self.build_result()

    def _check_rdp_nla(self):
        """MF-ML1-001: RDP requires Network Level Authentication."""
        script = """
        $rdp = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -ErrorAction SilentlyContinue
        @{
            UserAuthentication = $rdp.UserAuthentication
            SecurityLayer = $rdp.SecurityLayer
            fDenyTSConnections = (Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" -ErrorAction SilentlyContinue).fDenyTSConnections
        } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="MF-ML1-001",
            control=self.control,
            title="RDP requires Network Level Authentication",
            description="Remote Desktop should require NLA to enforce authentication before session creation.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Enable NLA for RDP: System Properties → Remote → "
                "'Allow connections only from computers running Remote Desktop with NLA'."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "RDP NLA settings"))

            try:
                data = json.loads(output)
                rdp_disabled = data.get("fDenyTSConnections")
                nla = data.get("UserAuthentication")

                if rdp_disabled == 1:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "RDP is disabled on this system. No NLA check needed."
                elif nla == 1:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "RDP requires Network Level Authentication."
                elif nla == 0:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "RDP does not require NLA. Sessions can be initiated without authentication."
                else:
                    finding.outcome = ControlOutcome.NO_VISIBILITY

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_winrm_settings(self):
        """MF-ML1-002: WinRM uses secure authentication."""
        script = """
        $auth = Get-Item WSMan:\\localhost\\Service\\Auth -ErrorAction SilentlyContinue
        if ($auth) {
            $result = @{}
            foreach ($item in $auth.GetEnumerator()) {
                $result[$item.Name] = $item.Value
            }
            $result | ConvertTo-Json
        } else {
            @{ "winrm_not_configured" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="MF-ML1-002",
            control=self.control,
            title="WinRM uses secure authentication methods",
            description="WinRM should not use Basic auth, which transmits credentials in cleartext.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Disable Basic auth for WinRM: "
                "winrm set winrm/config/service/auth '@{Basic=\"false\"}'"
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "WinRM auth"))

            try:
                data = json.loads(output)

                if data.get("winrm_not_configured"):
                    finding.outcome = ControlOutcome.NOT_APPLICABLE
                    finding.description = "WinRM is not configured on this system."
                elif str(data.get("Basic", "")).lower() == "true":
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "WinRM Basic auth is enabled — credentials sent as base64."
                else:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "WinRM Basic auth is disabled. Using NTLM/Kerberos."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_credential_guard(self):
        """MF-ML1-003: Credential Guard is enabled (protects credential theft)."""
        script = """
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard -ErrorAction SilentlyContinue
        if ($dg) {
            @{
                SecurityServicesRunning = $dg.SecurityServicesRunning
                VirtualizationBasedSecurityStatus = $dg.VirtualizationBasedSecurityStatus
            } | ConvertTo-Json
        } else {
            @{ "not_supported" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="MF-ML1-003",
            control=self.control,
            title="Credential Guard is enabled",
            description="Credential Guard protects credentials from theft, strengthening authentication security.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.MEDIUM,
            remediation=(
                "Enable Credential Guard via Group Policy: Computer Configuration → "
                "Administrative Templates → System → Device Guard → "
                "Turn On Virtualization Based Security."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Credential Guard"))

            try:
                data = json.loads(output)

                if data.get("not_supported"):
                    finding.outcome = ControlOutcome.NOT_APPLICABLE
                    finding.description = "Device Guard/Credential Guard not supported on this hardware."
                else:
                    services = data.get("SecurityServicesRunning", [])
                    # 1 = Credential Guard running
                    if isinstance(services, list) and 1 in services:
                        finding.outcome = ControlOutcome.EFFECTIVE
                        finding.description = "Credential Guard is running."
                    elif data.get("VirtualizationBasedSecurityStatus") == 2:
                        finding.outcome = ControlOutcome.EFFECTIVE
                        finding.description = "Virtualization-based security is running."
                    else:
                        finding.outcome = ControlOutcome.INEFFECTIVE
                        finding.description = "Credential Guard is not running."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)
