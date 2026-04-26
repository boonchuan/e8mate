"""Collector for Control 1: Application Control.

Essential Eight Maturity Level 1 requirements:
- Application control is implemented on workstations.
- Application control restricts execution of executables, software libraries,
  scripts, installers, compiled HTML, HTML applications and control panel
  applets to an organisation-approved set.
- Microsoft's recommended application blocklist is implemented.
- Microsoft's recommended driver blocklist is implemented.
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


class AppControlCollector(BaseCollector):
    """Assess Maturity Level 1 compliance for application control."""

    control = E8Control.APP_CONTROL
    display_name = "Application Control"

    def collect(self) -> ControlResult:
        """Run all application control checks."""
        self._check_applocker_or_wdac()
        self._check_applocker_service()
        self._check_applocker_enforcement()
        self._check_applocker_has_custom_rules()
        return self.build_result()

    def _check_applocker_or_wdac(self):
        """AC-ML1-001: AppLocker or WDAC is configured with at least one rule."""
        script = r"""
        $result = @{}

        # AppLocker probe — handle both "module not installed" and
        # "module installed but no policy" as distinct from "policy exists".
        $al = $null
        try {
            $al = Get-AppLockerPolicy -Effective -ErrorAction Stop
        } catch [System.Management.Automation.CommandNotFoundException] {
            $result["AppLockerAvailable"] = $false
        } catch {
            $result["AppLockerAvailable"] = $false
            $result["AppLockerError"] = $_.Exception.Message
        }

        if ($al) {
            $result["AppLockerAvailable"] = $true
            $totalRules = 0
            $collectionInfo = @()
            foreach ($rc in $al.RuleCollections) {
                $count = @($rc).Count
                $totalRules += $count
                $collectionInfo += @{
                    Type = "$($rc.RuleCollectionType)"
                    Mode = "$($rc.EnforcementMode)"
                    RuleCount = $count
                }
            }
            $result["AppLockerRuleCount"] = $totalRules
            $result["AppLockerCollections"] = $collectionInfo
        }

        # WDAC probe via Win32_DeviceGuard
        try {
            $wdac = Get-CimInstance -ClassName Win32_DeviceGuard `
                -Namespace root\Microsoft\Windows\DeviceGuard `
                -ErrorAction Stop
            $result["WDACAvailable"] = $true
            $result["WDACEnforcementStatus"] = [int]$wdac.CodeIntegrityPolicyEnforcementStatus
        } catch {
            $result["WDACAvailable"] = $false
        }

        $result | ConvertTo-Json -Depth 4
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AC-ML1-001",
            control=self.control,
            title="Application control is implemented",
            description="AppLocker or WDAC must be configured to restrict application execution.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.CRITICAL,
            remediation=(
                "Implement AppLocker via Group Policy (Pro/Enterprise) or WDAC via "
                "ConfigCI / Intune. Start with audit mode, then enforce after testing."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if not output or output.startswith("[ERROR]"):
            finding.outcome = ControlOutcome.NO_VISIBILITY
            finding.description = "Unable to query AppLocker or WDAC status."
            self.findings.append(finding)
            return

        finding.evidence.append(self.create_evidence(
            "powershell", output, "AppLocker/WDAC status"
        ))

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            finding.outcome = ControlOutcome.NO_VISIBILITY
            self.findings.append(finding)
            return

        if not isinstance(data, dict):
            finding.outcome = ControlOutcome.NO_VISIBILITY
            self.findings.append(finding)
            return

        applocker_available = bool(data.get("AppLockerAvailable"))
        applocker_rules = int(data.get("AppLockerRuleCount", 0) or 0)
        wdac_available = bool(data.get("WDACAvailable"))
        wdac_status = int(data.get("WDACEnforcementStatus", 0) or 0)

        # AppLocker counts as configured only if rules actually exist
        applocker_configured = applocker_available and applocker_rules > 0
        # WDAC: 0 = off, 1 = audit, 2 = enforce. Anything > 0 is "configured".
        wdac_configured = wdac_available and wdac_status > 0

        if applocker_configured:
            finding.outcome = ControlOutcome.EFFECTIVE
            finding.description = (
                f"Application control is active via AppLocker "
                f"({applocker_rules} rule(s) deployed)."
            )
        elif wdac_configured:
            mode = "enforce" if wdac_status >= 2 else "audit"
            finding.outcome = ControlOutcome.EFFECTIVE
            finding.description = (
                f"Application control is active via WDAC ({mode} mode)."
            )
        elif not applocker_available and not wdac_available:
            # Cannot query either mechanism on this host (likely Home SKU
            # or restricted PowerShell). We have no basis to claim either
            # presence or absence.
            finding.outcome = ControlOutcome.NO_VISIBILITY
            finding.description = (
                "Cannot query AppLocker or WDAC on this host. Application "
                "control status is unknown; verify manually."
            )
        else:
            # We could query at least one mechanism, but neither has
            # active configuration.
            finding.outcome = ControlOutcome.INEFFECTIVE
            finding.description = (
                "Neither AppLocker nor WDAC is configured. No application "
                "control restrictions are in effect."
            )

        self.findings.append(finding)

    def _check_applocker_service(self):
        """AC-ML1-002: AppLocker service (AppIDSvc) is running."""
        script = "Get-Service AppIDSvc | Select-Object Status, StartType | ConvertTo-Json"
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AC-ML1-002",
            control=self.control,
            title="Application Identity service is running",
            description="The AppIDSvc service must be running for AppLocker to function.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation="Set Application Identity service (AppIDSvc) to Automatic and start it.",
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "AppIDSvc"))

            try:
                data = json.loads(output)
                status = data.get("Status")
                start_type = data.get("StartType")

                if status == 4 or str(status).lower() == "running":
                    finding.outcome = ControlOutcome.EFFECTIVE
                    finding.description = "Application Identity service is running."
                elif start_type == 4 or str(start_type).lower() == "disabled":
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "Application Identity service is disabled."
                else:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = f"Application Identity service is not running (status: {status})."

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_applocker_enforcement(self):
        """AC-ML1-003: AppLocker rules are in enforce mode (not audit-only)."""
        script = """
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if ($policy) {
            $policy.RuleCollections | ForEach-Object {
                @{ Type = $_.RuleCollectionType; Mode = $_.EnforcementMode }
            } | ConvertTo-Json
        } else {
            @() | ConvertTo-Json
        }
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AC-ML1-003",
            control=self.control,
            title="Application control rules are enforced (not audit-only)",
            description="AppLocker rules should be in Enforce mode, not just Audit.",
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Change AppLocker rule collections from AuditOnly to Enabled "
                "after validating in audit mode."
            ),
        )

        if output and not output.startswith("[ERROR]"):
            finding.evidence.append(self.create_evidence("powershell", output, "AppLocker enforcement"))

            try:
                data = json.loads(output)
                if not isinstance(data, list):
                    data = [data]

                if not data:
                    finding.outcome = ControlOutcome.INEFFECTIVE
                    finding.description = "No AppLocker rule collections found."
                else:
                    enforced = [r for r in data if str(r.get("Mode", "")).lower() in ("enabled", "1")]
                    audit_only = [r for r in data if str(r.get("Mode", "")).lower() in ("auditonly", "0")]

                    if enforced and not audit_only:
                        finding.outcome = ControlOutcome.EFFECTIVE
                        finding.description = f"All {len(enforced)} rule collection(s) are in enforce mode."
                    elif audit_only:
                        finding.outcome = ControlOutcome.INEFFECTIVE
                        types = [r.get("Type", "?") for r in audit_only]
                        finding.description = (
                            f"Rule collections in audit-only mode: {', '.join(types)}. "
                            "Switch to enforce mode."
                        )
                    else:
                        finding.outcome = ControlOutcome.NO_VISIBILITY

            except json.JSONDecodeError:
                finding.outcome = ControlOutcome.NO_VISIBILITY
        else:
            finding.outcome = ControlOutcome.NO_VISIBILITY

        self.findings.append(finding)

    def _check_applocker_has_custom_rules(self):
        """AC-ML1-004: AppLocker policy contains rules beyond Microsoft defaults."""
        script = """
        $policy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
        if (-not $policy) {
            @{ "not_available" = $true } | ConvertTo-Json
            return
        }

        $collections = @()
        foreach ($rc in $policy.RuleCollections) {
            $rules = @($rc)
            $total = $rules.Count
            $defaults = 0
            $custom = 0
            $denies = 0

            foreach ($rule in $rules) {
                $name = if ($rule.Name) { $rule.Name } else { "" }
                $action = if ($rule.Action) { "$($rule.Action)" } else { "" }

                if ($action -eq "Deny") {
                    $denies++
                } elseif ($name.StartsWith("(Default Rule)")) {
                    $defaults++
                } else {
                    $custom++
                }
            }

            $collections += @{
                Type = "$($rc.RuleCollectionType)"
                Mode = "$($rc.EnforcementMode)"
                TotalRules = $total
                DefaultRules = $defaults
                CustomAllowRules = $custom
                DenyRules = $denies
            }
        }

        @{ Collections = $collections } | ConvertTo-Json -Depth 4
        """
        output = self.run_powershell(script)

        finding = Finding(
            check_id="AC-ML1-004",
            control=self.control,
            title="Application control policy contains meaningful rules",
            description=(
                "The AppLocker policy must contain deny rules or custom allow rules "
                "beyond Microsoft's default allow-all-of-Program-Files defaults. "
                "An enforced policy with only default rules does not actually "
                "restrict what can run."
            ),
            maturity_level=MaturityLevel.ML1,
            severity=Severity.HIGH,
            remediation=(
                "Add explicit deny rules for known LOLBins (e.g. mshta.exe, "
                "regsvr32.exe, wscript.exe) or replace the default allow-all rules "
                "with a curated allowlist of approved applications. Consider "
                "deploying Microsoft's recommended block rules via WDAC."
            ),
            asd_reference="https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
        )

        if not output or output.startswith("[ERROR]"):
            finding.outcome = ControlOutcome.NO_VISIBILITY
            finding.description = "Unable to query AppLocker policy contents."
            self.findings.append(finding)
            return

        finding.evidence.append(self.create_evidence("powershell", output, "AppLocker rule inventory"))

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            finding.outcome = ControlOutcome.NO_VISIBILITY
            self.findings.append(finding)
            return

        # ConvertTo-Json may emit a top-level array in some edge cases
        # (e.g. mock-transport sentinels, or a single-collection policy
        # rendered by PowerShell as a single-element array). If we get
        # anything other than a dict, we cannot evaluate the policy shape.
        if not isinstance(data, dict):
            finding.outcome = ControlOutcome.NO_VISIBILITY
            finding.description = (
                "AppLocker policy returned in an unexpected shape; "
                "unable to evaluate rule composition."
            )
            self.findings.append(finding)
            return

        if data.get("not_available"):
            finding.outcome = ControlOutcome.NO_VISIBILITY
            finding.description = (
                "AppLocker is not available on this host (likely Windows Home SKU "
                "or no policy configured). If WDAC is in use, verify meaningful "
                "rules are deployed manually."
            )
            self.findings.append(finding)
            return

        collections = data.get("Collections")
        # JSON may encode a single collection as a dict rather than a list.
        if isinstance(collections, dict):
            collections = [collections]
        elif collections is None:
            collections = []

        if not collections:
            finding.outcome = ControlOutcome.INEFFECTIVE
            finding.description = (
                "AppLocker policy has no rule collections. No applications are "
                "being restricted."
            )
            self.findings.append(finding)
            return

        total_custom = sum(int(c.get("CustomAllowRules", 0) or 0) for c in collections)
        total_denies = sum(int(c.get("DenyRules", 0) or 0) for c in collections)
        total_defaults = sum(int(c.get("DefaultRules", 0) or 0) for c in collections)

        if total_denies > 0 or total_custom > 0:
            finding.outcome = ControlOutcome.EFFECTIVE
            parts = []
            if total_denies > 0:
                parts.append(f"{total_denies} deny rule(s)")
            if total_custom > 0:
                parts.append(f"{total_custom} custom allow rule(s)")
            finding.description = (
                f"AppLocker policy contains {' and '.join(parts)} across "
                f"{len(collections)} rule collection(s)."
            )
        else:
            finding.outcome = ControlOutcome.INEFFECTIVE
            finding.description = (
                f"AppLocker policy contains only {total_defaults} Microsoft default "
                "rule(s) and no custom or deny rules. An enforced policy of defaults "
                "does not meaningfully restrict application execution."
            )

        self.findings.append(finding)
