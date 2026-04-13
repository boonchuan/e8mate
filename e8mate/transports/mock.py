"""Mock transport for development and testing on non-Windows systems.

Simulates a Windows environment with configurable compliance states
so collectors can be developed and tested on Ubuntu/macOS without
needing a live Windows target.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Optional


# Predefined mock scenarios
SCENARIOS = {
    "compliant": "A well-configured Windows 11 workstation at ML1",
    "partial": "A partially patched Windows 10 machine with some gaps",
    "noncompliant": "An outdated Windows 10 machine with major issues",
}


class MockTransport:
    """Simulates PowerShell responses for development on Linux/macOS.

    Usage:
        transport = MockTransport(scenario="compliant")
        # or
        transport = MockTransport(scenario="noncompliant")
    """

    def __init__(self, scenario: str = "partial"):
        self.scenario = scenario
        self._responses = self._build_responses(scenario)

    @property
    def has_powershell(self) -> bool:
        return True  # Always "available" in mock mode

    def execute_powershell(self, script: str, timeout: int = 60) -> Optional[str]:
        """Return mock PowerShell output based on the script content."""
        script_lower = script.lower()

        # Match against longest keywords first (most specific match wins)
        for keyword in sorted(self._responses.keys(), key=len, reverse=True):
            if keyword in script_lower:
                return self._responses[keyword]

        return json.dumps({"mock": True, "note": "No mock data for this command"})

    def execute_cmd(self, command: str, timeout: int = 60) -> Optional[str]:
        """Return mock command output."""
        return "Mock command output"

    def get_system_info(self) -> dict:
        """Return mock system info based on scenario."""
        if self.scenario == "compliant":
            return {
                "hostname": "DESKTOP-E8MATE01",
                "os_name": "Microsoft Windows 11 Pro",
                "os_version": "10.0.22631",
                "os_build": "22631",
                "platform": "Windows-10-10.0.22631-SP0",
            }
        elif self.scenario == "noncompliant":
            return {
                "hostname": "OLDPC-FINANCE",
                "os_name": "Microsoft Windows 10 Pro",
                "os_version": "10.0.19041",
                "os_build": "19041",
                "platform": "Windows-10-10.0.19041-SP0",
            }
        else:  # partial
            return {
                "hostname": "WS-RECEPTION-03",
                "os_name": "Microsoft Windows 10 Pro",
                "os_version": "10.0.19045",
                "os_build": "19045",
                "platform": "Windows-10-10.0.19045-SP0",
            }

    def _build_responses(self, scenario: str) -> dict:
        """Build mock PowerShell responses for a given scenario."""
        now = datetime.now()

        if scenario == "compliant":
            return self._compliant_responses(now)
        elif scenario == "noncompliant":
            return self._noncompliant_responses(now)
        else:
            return self._partial_responses(now)

    def _compliant_responses(self, now: datetime) -> dict:
        """Well-configured Windows 11 at ML1."""
        recent_date = (now - timedelta(days=5)).strftime("/Date(%d)/" % int((now - timedelta(days=5)).timestamp() * 1000))

        return {
            # --- Control 1: Application Control ---
            # AC-ML1-001: combined check (script has $result["applocker"])
            'result["applocker"]': json.dumps({
                "AppLocker": True,
                "RuleCollections": [
                    {"Type": "Exe", "Mode": "Enabled"},
                    {"Type": "Script", "Mode": "Enabled"},
                ],
                "WDAC_CodeIntegrity": 2,
            }),
            # AC-ML1-002: service check
            "appidsvc": json.dumps({"Status": 4, "StartType": 2}),
            # AC-ML1-003: enforcement check (script has rulecollectiontype)
            "rulecollectiontype": json.dumps([
                {"Type": "Exe", "Mode": "Enabled"},
                {"Type": "Script", "Mode": "Enabled"},
            ]),

            # --- Control 2: Patch Applications ---
            "currentversion\\uninstall": json.dumps([
                {"DisplayName": "Google Chrome", "DisplayVersion": "124.0.6367.91", "Publisher": "Google LLC", "InstallDate": "20260401"},
                {"DisplayName": "Microsoft Edge", "DisplayVersion": "124.0.2478.51", "Publisher": "Microsoft", "InstallDate": "20260405"},
                {"DisplayName": "7-Zip", "DisplayVersion": "24.08", "Publisher": "Igor Pavlov", "InstallDate": "20260101"},
            ]),
            "chrome.exe": json.dumps({"Chrome": "124.0.6367.91"}),
            "msedge.exe": json.dumps({"Edge": "124.0.2478.51"}),
            "clicktorun": json.dumps({
                "VersionToReport": "16.0.17531.20140",
                "UpdatesEnabled": "True",
                "Platform": "x64",
            }),

            # --- Control 3: Macro Settings ---
            "vbawarnings": json.dumps({"VBAWarnings": 4, "Word": 4, "Excel": 4, "PowerPoint": 4}),
            "blockcontentexecutionfrominternet": json.dumps({"blockcontentexecutionfrominternet": 1, "Word": 1, "Excel": 1, "PowerPoint": 1}),
            "macroruntimescanscope": json.dumps({"MacroRuntimeScanScope": 2}),

            # --- Control 4: User Application Hardening ---
            "internet-explorer-optional": json.dumps({"PolicySet": True, "FeatureState": "DisabledWithPayloadRemoved"}),
            "scriptblocklogging": json.dumps({"EnableScriptBlockLogging": 1}),
            "languagemode": "ConstrainedLanguage",
            "netfx3": json.dumps({"State": "Disabled"}),

            # --- Control 5: Admin Privileges ---
            "get-localgroupmember": json.dumps([
                {"Name": "DESKTOP-E8MATE01\\Admin", "SID": "S-1-5-21-xxx-500", "ObjectClass": "User"},
            ]),
            "domain admins": json.dumps([
                {"Name": "svc-admin", "SamAccountName": "svc-admin"},
            ]),
            "get-localuser": json.dumps({"Name": "Administrator", "Enabled": False, "SID": "S-1-5-21-xxx-500"}),
            "search-adaccount": json.dumps([]),

            # --- Control 6: Patch Operating Systems ---
            "win32_operatingsystem": json.dumps({
                "Caption": "Microsoft Windows 11 Pro",
                "Version": "10.0.22631",
                "BuildNumber": "22631",
                "OSArchitecture": "64-bit",
            }),
            "osversion": json.dumps({
                "Major": 10, "Minor": 0, "Build": 22631,
                "Revision": 0, "DisplayVersion": "23H2",
            }),
            "get-hotfix": json.dumps([
                {"HotFixID": "KB5035853", "InstalledOn": recent_date, "Description": "Security Update"},
                {"HotFixID": "KB5034441", "InstalledOn": recent_date, "Description": "Security Update"},
            ]),
            "windowsupdate\\au": json.dumps({
                "AUOptions": 4, "NoAutoUpdate": 0, "UseWUServer": 0, "PolicyConfigured": True,
            }),
            "wuauserv": json.dumps({"Status": 4, "StartType": 2, "DisplayName": "Windows Update"}),

            # --- Control 7: MFA ---
            "rdp-tcp": json.dumps({"UserAuthentication": 1, "SecurityLayer": 2, "fDenyTSConnections": 0}),
            "wsman": json.dumps({"Basic": "false", "Kerberos": "true", "Negotiate": "true"}),
            "win32_deviceguard": json.dumps({
                "SecurityServicesRunning": [1, 2],
                "VirtualizationBasedSecurityStatus": 2,
                "not_supported": False,
            }),

            # --- Control 8: Backups ---
            "vss": json.dumps({"Status": 4, "StartType": 3, "DisplayName": "Volume Shadow Copy"}),
            # BK-ML1-002: combined check (script has $wbresult)
            "$wbresult": json.dumps({
                "WindowsBackup": {
                    "LastSuccess": now.strftime("%Y-%m-%dT%H:%M:%S"),
                    "Versions": 14,
                },
                "VSShadows": True,
            }),
            # BK-ML1-003: recency check (script has lastbackuptime)
            "lastbackuptime": json.dumps({
                "LastSuccess": now.strftime("%Y-%m-%dT%H:%M:%S"),
                "LastAttempt": now.strftime("%Y-%m-%dT%H:%M:%S"),
            }),
        }

    def _noncompliant_responses(self, now: datetime) -> dict:
        """Outdated Windows 10 with major issues."""
        old_date = (now - timedelta(days=120)).strftime("/Date(%d)/" % int((now - timedelta(days=120)).timestamp() * 1000))

        return {
            # --- Control 1: Application Control ---
            'result["applocker"]': json.dumps({
                "AppLocker": False,
                "RuleCollections": [],
                "WDAC_CodeIntegrity": 0,
            }),
            "appidsvc": json.dumps({"Status": 1, "StartType": 4}),
            "rulecollectiontype": json.dumps([]),

            # --- Control 2: Patch Applications ---
            "currentversion\\uninstall": json.dumps([
                {"DisplayName": "Google Chrome", "DisplayVersion": "109.0.5414.120", "Publisher": "Google LLC"},
                {"DisplayName": "Adobe Flash Player", "DisplayVersion": "32.0.0.465", "Publisher": "Adobe"},
                {"DisplayName": "Java 7 Update 80", "DisplayVersion": "7.0.800", "Publisher": "Oracle"},
            ]),
            "chrome.exe": json.dumps({"Chrome": "109.0.5414.120"}),
            "clicktorun": json.dumps({"not_installed": True}),

            # --- Control 3: Macro Settings ---
            "vbawarnings": json.dumps({"VBAWarnings": 1, "Word": 1, "Excel": 1, "PowerPoint": 1}),
            "blockcontentexecutionfrominternet": json.dumps({}),
            "macroruntimescanscope": json.dumps({"MacroRuntimeScanScope": 0}),

            # --- Control 4: User Application Hardening ---
            "internet-explorer-optional": json.dumps({"PolicySet": False, "FeatureState": "Enabled"}),
            "scriptblocklogging": "[ERROR] Property not found",
            "languagemode": "FullLanguage",
            "netfx3": json.dumps({"State": "Enabled"}),

            # --- Control 5: Admin Privileges ---
            "get-localgroupmember": json.dumps([
                {"Name": "OLDPC\\Administrator", "SID": "S-1-5-21-xxx-500", "ObjectClass": "User"},
                {"Name": "OLDPC\\john", "SID": "S-1-5-21-xxx-1001", "ObjectClass": "User"},
                {"Name": "OLDPC\\reception", "SID": "S-1-5-21-xxx-1002", "ObjectClass": "User"},
                {"Name": "OLDPC\\temp-contractor", "SID": "S-1-5-21-xxx-1003", "ObjectClass": "User"},
                {"Name": "OLDPC\\backup-svc", "SID": "S-1-5-21-xxx-1004", "ObjectClass": "User"},
                {"Name": "OLDPC\\dev-test", "SID": "S-1-5-21-xxx-1005", "ObjectClass": "User"},
            ]),
            "domain admins": json.dumps({"not_domain_joined": True}),
            "get-localuser": json.dumps({"Name": "Administrator", "Enabled": True, "SID": "S-1-5-21-xxx-500"}),
            "search-adaccount": json.dumps({"not_domain_joined": True}),

            # --- Control 6: Patch Operating Systems ---
            "win32_operatingsystem": json.dumps({
                "Caption": "Microsoft Windows 10 Pro",
                "Version": "10.0.19041",
                "BuildNumber": "19041",
                "OSArchitecture": "64-bit",
            }),
            "osversion": json.dumps({
                "Major": 10, "Minor": 0, "Build": 19041,
                "Revision": 0, "DisplayVersion": "2004",
            }),
            "get-hotfix": json.dumps([
                {"HotFixID": "KB5001330", "InstalledOn": old_date, "Description": "Security Update"},
            ]),
            "windowsupdate\\au": json.dumps({
                "AUOptions": 1, "NoAutoUpdate": 1, "UseWUServer": 0, "PolicyConfigured": True,
            }),
            "wuauserv": json.dumps({"Status": 1, "StartType": 4, "DisplayName": "Windows Update"}),

            # --- Control 7: MFA ---
            "rdp-tcp": json.dumps({"UserAuthentication": 0, "SecurityLayer": 0, "fDenyTSConnections": 0}),
            "wsman": json.dumps({"Basic": "true", "Kerberos": "false", "Negotiate": "true"}),
            "win32_deviceguard": json.dumps({
                "SecurityServicesRunning": [],
                "VirtualizationBasedSecurityStatus": 0,
                "not_supported": False,
            }),

            # --- Control 8: Backups ---
            "vss": json.dumps({"Status": 1, "StartType": 4, "DisplayName": "Volume Shadow Copy"}),
            "$wbresult": json.dumps({
                "WindowsBackup": None,
                "VSShadows": False,
            }),
            "lastbackuptime": json.dumps({"not_available": True}),
        }

    def _partial_responses(self, now: datetime) -> dict:
        """Partially configured — some things good, some gaps."""
        somewhat_old = (now - timedelta(days=40)).strftime("/Date(%d)/" % int((now - timedelta(days=40)).timestamp() * 1000))

        return {
            # --- Control 1: Application Control (audit only) ---
            'result["applocker"]': json.dumps({
                "AppLocker": True,
                "RuleCollections": [
                    {"Type": "Exe", "Mode": "AuditOnly"},
                ],
                "WDAC_CodeIntegrity": 0,
            }),
            "appidsvc": json.dumps({"Status": 4, "StartType": 3}),
            "rulecollectiontype": json.dumps([
                {"Type": "Exe", "Mode": "AuditOnly"},
            ]),

            # --- Control 2: Patch Applications ---
            "currentversion\\uninstall": json.dumps([
                {"DisplayName": "Google Chrome", "DisplayVersion": "123.0.6312.86", "Publisher": "Google LLC"},
                {"DisplayName": "Microsoft Edge", "DisplayVersion": "123.0.2420.65", "Publisher": "Microsoft"},
                {"DisplayName": "Notepad++", "DisplayVersion": "8.6.4", "Publisher": "Notepad++ Team"},
            ]),
            "chrome.exe": json.dumps({"Chrome": "123.0.6312.86"}),
            "clicktorun": json.dumps({
                "VersionToReport": "16.0.17328.20162",
                "UpdatesEnabled": "True",
                "Platform": "x64",
            }),

            # --- Control 3: Macro Settings (signed only, not fully disabled) ---
            "vbawarnings": json.dumps({"VBAWarnings": 3, "Word": 3, "Excel": 3, "PowerPoint": 3}),
            "blockcontentexecutionfrominternet": json.dumps({"blockcontentexecutionfrominternet": 1, "Word": 1, "Excel": 1, "PowerPoint": 1}),
            "macroruntimescanscope": json.dumps({"MacroRuntimeScanScope": None}),

            # --- Control 4: User Application Hardening ---
            "internet-explorer-optional": json.dumps({"PolicySet": True, "FeatureState": "Disabled"}),
            "scriptblocklogging": json.dumps({"EnableScriptBlockLogging": 1}),
            "languagemode": "FullLanguage",
            "netfx3": json.dumps({"State": "Enabled"}),

            # --- Control 5: Admin Privileges ---
            "get-localgroupmember": json.dumps([
                {"Name": "WS-REC\\Admin", "SID": "S-1-5-21-xxx-500", "ObjectClass": "User"},
                {"Name": "WS-REC\\helpdesk", "SID": "S-1-5-21-xxx-1001", "ObjectClass": "User"},
            ]),
            "domain admins": json.dumps({"not_domain_joined": True}),
            "get-localuser": json.dumps({"Name": "Administrator", "Enabled": True, "SID": "S-1-5-21-xxx-500"}),
            "search-adaccount": json.dumps({"not_domain_joined": True}),

            # --- Control 6: Patch Operating Systems ---
            "win32_operatingsystem": json.dumps({
                "Caption": "Microsoft Windows 10 Pro",
                "Version": "10.0.19045",
                "BuildNumber": "19045",
                "OSArchitecture": "64-bit",
            }),
            "osversion": json.dumps({
                "Major": 10, "Minor": 0, "Build": 19045,
                "Revision": 0, "DisplayVersion": "22H2",
            }),
            "get-hotfix": json.dumps([
                {"HotFixID": "KB5034763", "InstalledOn": somewhat_old, "Description": "Security Update"},
                {"HotFixID": "KB5034122", "InstalledOn": somewhat_old, "Description": "Update"},
            ]),
            "windowsupdate\\au": json.dumps({
                "AUOptions": 3, "NoAutoUpdate": 0, "UseWUServer": 1, "PolicyConfigured": True,
            }),
            "wuauserv": json.dumps({"Status": 4, "StartType": 2, "DisplayName": "Windows Update"}),

            # --- Control 7: MFA (RDP on but NLA enabled) ---
            "rdp-tcp": json.dumps({"UserAuthentication": 1, "SecurityLayer": 2, "fDenyTSConnections": 0}),
            "wsman": json.dumps({"Basic": "true", "Kerberos": "true", "Negotiate": "true"}),
            "win32_deviceguard": json.dumps({
                "SecurityServicesRunning": [],
                "VirtualizationBasedSecurityStatus": 0,
                "not_supported": False,
            }),

            # --- Control 8: Backups ---
            "vss": json.dumps({"Status": 4, "StartType": 3, "DisplayName": "Volume Shadow Copy"}),
            "$wbresult": json.dumps({
                "WindowsBackup": {
                    "LastSuccess": (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S"),
                    "Versions": 7,
                },
                "VSShadows": True,
            }),
            "lastbackuptime": json.dumps({
                "LastSuccess": (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S"),
                "LastAttempt": (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S"),
            }),
        }
