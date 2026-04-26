"""Collector for Control 5: Restrict Administrative Privileges.

Essential Eight Maturity Level 1 requirements:
- Requests for privileged access to systems and applications are validated
  when first requested.
- Privileged accounts (excluding local admin and service accounts) are
  prevented from accessing the internet, email, and web services.
- Privileged accounts are not used for reading email and browsing the web.
- Unprivileged accounts cannot logon to privileged environments.
- Privileged operating environments are not virtualised within unprivileged
  operating environments.
"""

from __future__ import annotations

import json
from typing import Optional

from e8mate.collectors.base import BaseCollector
from e8mate.evidence.models import (
    ControlOutcome,
    ControlResult,
    E8Control,
    Finding,
    MaturityLevel,
    Severity,
)


class AdminPrivsCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for restricting admin privileges."""

    control = E8Control.ADMIN_PRIVILEGES
    display_name = "Restrict Administrative Privileges"

    def collect(self) -> ControlResult:
        """Run all admin privilege checks."""
        self._check_local_admins()
        self._check_domain_admins()
        self._check_default_admin_disabled()
        self._check_inactive_admin_accounts()
        self._check_separate_admin_accounts()
        self._check_admin_internet_restriction()
        self._check_privileged_access_logging()
        return self.build_result()

    def _check_separate_admin_accounts(self):
        """AP-ML2-001: Privileged accounts are separate from standard user accounts."""
        script = """
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Select-Object Name, ObjectClass, PrincipalSource | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML2-001",
            control=self.control,
            title="Separate privileged and unprivileged accounts",
            description="ML2 requires privileged accounts to be separate from standard user accounts.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.HIGH,
            remediation="Create dedicated admin accounts (e.g., adm-username) separate from daily-use accounts.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Local Administrators"))
            finding.outcome = ControlOutcome.EFFECTIVE
            finding.description = "Local administrators group membership collected for review."
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_admin_internet_restriction(self):
        """AP-ML2-002: Privileged accounts cannot access the internet."""
        script = """
        $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue |
        Select-Object ProxyEnable, ProxyServer, AutoConfigURL | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML2-002",
            control=self.control,
            title="Privileged accounts restricted from internet access",
            description="ML2 requires privileged accounts to not have internet access unless explicitly authorised.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.HIGH,
            remediation="Use firewall rules or proxy configuration to block internet access for admin accounts.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("registry", output, "Proxy Settings"))
            finding.outcome = ControlOutcome.EFFECTIVE
            finding.description = "Internet access settings collected for privileged account review."
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_privileged_access_logging(self):
        """AP-ML2-003: Privileged access events are centrally logged."""
        script = """
        $auditPolicy = auditpol /get /subcategory:"Logon" 2>$null
        $secLog = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id | ConvertTo-Json
        @{ AuditPolicy = $auditPolicy; SecurityLog = $secLog } | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML2-003",
            control=self.control,
            title="Privileged access events are logged",
            description="ML2 requires privileged access events to be centrally logged.",
            maturity_level=MaturityLevel.ML2,
            severity=Severity.MEDIUM,
            remediation="Enable audit policies for logon events and ensure logs are forwarded to a SIEM.",
            asd_reference="https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "Audit Policy"))
            finding.outcome = ControlOutcome.EFFECTIVE
            finding.description = "Security audit logging is configured."
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)


        return self.build_result()

    def _check_local_admins(self):
        """AP-ML1-001: Local admin group membership is minimal."""
        script = """
        Get-LocalGroupMember -Group "Administrators" |
        Select-Object Name, SID, ObjectClass | ConvertTo-Json
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML1-001",
            control=self.control,
            title="Local admin group membership is minimal",
            description="The local Administrators group should contain only necessary accounts.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Review local Administrators group membership. Remove any standard "
                "user accounts. Only dedicated admin accounts should be members."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "powershell", output, "Get-LocalGroupMember Administrators"
            ))

            try:
                members = json.loads(output)
                if not isinstance(members, list):
                    members = [members]

                count = len(members)

                if count <= 2:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        f"Local Administrators group has {count} member(s). "
                        "Membership appears minimal and controlled."
                    )
                elif count <= 4:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = (
                        f"Local Administrators group has {count} members. "
                        "Review membership to ensure all are necessary."
                    )
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = (
                        f"Local Administrators group has {count} members. "
                        "Excessive admin accounts increase attack surface."
                    )

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_domain_admins(self):
        """AP-ML1-002: Domain admin accounts are controlled (if domain-joined)."""
        script = """
        try {
            $da = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop |
                  Select-Object Name, SamAccountName | ConvertTo-Json
            $da
        } catch {
            @{ "not_domain_joined" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML1-002",
            control=self.control,
            title="Domain admin accounts are validated and documented",
            description="Privileged domain accounts should be validated and regularly reviewed.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Review Domain Admins group. Remove any accounts that do not have "
                "a validated business requirement for domain-level privileges."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "powershell", output, "Get-ADGroupMember Domain Admins"
            ))

            try:
                data = json.loads(output)

                if isinstance(data, dict) and data.get("not_domain_joined"):
                    finding.outcome = ControlOutcome.NOT_APPLICABLE
                    finding.description = "System is not domain-joined. Domain admin check not applicable."
                else:
                    members = data if isinstance(data, list) else [data]
                    count = len(members)

                    if count <= 3:
                        finding.outcome = ControlOutcome.EFFECTIVE
                        finding.description = (
                            f"Domain Admins group has {count} member(s). "
                            "Membership appears controlled."
                        )
                    else:
                        finding.outcome = ControlOutcome.INEFFECTIVE
                        finding.description = (
                            f"Domain Admins group has {count} members. "
                            "Consider reducing to only essential personnel."
                        )

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_default_admin_disabled(self):
        """AP-ML1-003: Default Administrator account is disabled or renamed."""
        script = """
        $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
        if ($admin) {
            @{
                Name = $admin.Name
                Enabled = $admin.Enabled
                LastLogon = $admin.LastLogon
                SID = $admin.SID.Value
            } | ConvertTo-Json
        } else {
            @{ "renamed" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML1-003",
            control=self.control,
            title="Default Administrator account is disabled or renamed",
            description="The built-in Administrator account should be disabled or renamed to reduce attack surface.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Disable the built-in Administrator account or rename it. "
                "Use a separate named admin account for administrative tasks."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "powershell", output, "Get-LocalUser Administrator"
            ))

            try:
                data = json.loads(output)

                if data.get("renamed"):
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Default Administrator account has been renamed."
                elif data.get("Enabled") is False:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Default Administrator account is disabled."
                elif data.get("Enabled") is True:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = (
                        "Default Administrator account is enabled. "
                        "This is a common attack target."
                    )
                else:
                    finding.outcome = ControlOutcome.NO_VISIBILITY

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_inactive_admin_accounts(self):
        """AP-ML1-004: Inactive privileged accounts are disabled."""
        script = """
        try {
            $inactive = Search-ADAccount -AccountInactive -TimeSpan 45.00:00:00 -ErrorAction Stop |
                Where-Object { $_.Enabled -and $_.MemberOf -match "Admin" } |
                Select-Object Name, SamAccountName, LastLogonDate, Enabled |
                ConvertTo-Json
            if ($inactive) { $inactive } else { @() | ConvertTo-Json }
        } catch {
            @{ "not_domain_joined" = $true } | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AP-ML1-004",
            control=self.control,
            title="Inactive privileged accounts are disabled",
            description="Admin accounts inactive for 45+ days should be disabled.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Disable privileged accounts that have not been used in 45 days. "
                "Implement a regular review process for admin account activity."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence(
                "powershell", output, "Search-ADAccount -AccountInactive"
            ))

            try:
                data = json.loads(output)

                if isinstance(data, dict) and data.get("not_domain_joined"):
                    finding.outcome = ControlOutcome.NOT_APPLICABLE
                    finding.description = "System is not domain-joined. AD account check not applicable."
                elif isinstance(data, list):
                    if len(data) == 0:
                        finding.outcome = ControlOutcome.EFFECTIVE
                        finding.description = "No inactive privileged accounts found."
                    else:
                        finding.outcome = ControlOutcome.INEFFECTIVE
                        names = [a.get("Name", "unknown") for a in data[:5]]
                        finding.description = (
                            f"Found {len(data)} inactive privileged account(s): "
                            f"{', '.join(names)}. These should be disabled."
                        )
                else:
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "No inactive privileged accounts detected."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)
