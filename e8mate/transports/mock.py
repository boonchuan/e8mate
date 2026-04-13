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

        # Match script content to mock responses
        for keyword, response in self._responses.items():
            if keyword in script_lower:
                return response

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
            # Patch OS checks
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
                "AUOptions": 4,
                "NoAutoUpdate": 0,
                "UseWUServer": 0,
                "PolicyConfigured": True,
            }),
            "wuauserv": json.dumps({
                "Status": 4, "StartType": 2, "DisplayName": "Windows Update",
            }),
            # Admin privileges
            "get-localgroupmember": json.dumps([
                {"Name": "DESKTOP-E8MATE01\\Admin", "SID": "S-1-5-21-xxx-500", "ObjectClass": "User"},
            ]),
            "domain admins": json.dumps([
                {"Name": "svc-admin", "SamAccountName": "svc-admin"},
            ]),
            # Macro settings
            "vbawarnings": json.dumps({"VBAWarnings": 4}),  # All macros disabled
            "blockcontentexecutionfrominternet": json.dumps({"blockcontentexecutionfrominternet": 1}),
            # AppLocker
            "applockerpolicy": json.dumps({
                "RuleCollections": [
                    {"RuleCollectionType": "Exe", "EnforcementMode": "Enabled"},
                    {"RuleCollectionType": "Script", "EnforcementMode": "Enabled"},
                ],
            }),
            "appidsvc": json.dumps({"Status": 4, "StartType": 2}),
            # Application hardening
            "scriptblocklogging": json.dumps({"EnableScriptBlockLogging": 1}),
            "languagemode": "ConstrainedLanguage",
            # Backups
            "vss": json.dumps({"Status": 4}),
            "vssadmin": "Contents of shadow copy set...\nShadow copy created: " + now.strftime("%Y-%m-%d"),
            "get-wbsummary": json.dumps({
                "LastSuccessfulBackupTime": now.strftime("%Y-%m-%dT%H:%M:%S"),
                "NumberOfVersions": 14,
            }),
        }

    def _noncompliant_responses(self, now: datetime) -> dict:
        """Outdated Windows 10 with major issues."""
        old_date = (now - timedelta(days=120)).strftime("/Date(%d)/" % int((now - timedelta(days=120)).timestamp() * 1000))

        return {
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
                "AUOptions": 1,
                "NoAutoUpdate": 1,
                "UseWUServer": 0,
                "PolicyConfigured": True,
            }),
            "wuauserv": json.dumps({
                "Status": 1, "StartType": 4, "DisplayName": "Windows Update",
            }),
            "get-localgroupmember": json.dumps([
                {"Name": "OLDPC\\Administrator", "SID": "S-1-5-21-xxx-500", "ObjectClass": "User"},
                {"Name": "OLDPC\\john", "SID": "S-1-5-21-xxx-1001", "ObjectClass": "User"},
                {"Name": "OLDPC\\reception", "SID": "S-1-5-21-xxx-1002", "ObjectClass": "User"},
            ]),
            "vbawarnings": json.dumps({"VBAWarnings": 1}),  # All macros enabled
            "blockcontentexecutionfrominternet": json.dumps({}),
            "applockerpolicy": json.dumps({"RuleCollections": []}),
            "appidsvc": json.dumps({"Status": 1, "StartType": 4}),
            "scriptblocklogging": "[ERROR] Property not found",
            "languagemode": "FullLanguage",
            "vss": json.dumps({"Status": 1}),
            "vssadmin": "No shadow copies found.",
            "get-wbsummary": "[ERROR] Feature not installed",
        }

    def _partial_responses(self, now: datetime) -> dict:
        """Partially configured — some things good, some gaps."""
        somewhat_old = (now - timedelta(days=40)).strftime("/Date(%d)/" % int((now - timedelta(days=40)).timestamp() * 1000))

        return {
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
                "AUOptions": 3,
                "NoAutoUpdate": 0,
                "UseWUServer": 1,
                "PolicyConfigured": True,
            }),
            "wuauserv": json.dumps({
                "Status": 4, "StartType": 2, "DisplayName": "Windows Update",
            }),
            "get-localgroupmember": json.dumps([
                {"Name": "WS-REC\\Admin", "SID": "S-1-5-21-xxx-500", "ObjectClass": "User"},
                {"Name": "WS-REC\\helpdesk", "SID": "S-1-5-21-xxx-1001", "ObjectClass": "User"},
            ]),
            "vbawarnings": json.dumps({"VBAWarnings": 3}),  # Signed only
            "blockcontentexecutionfrominternet": json.dumps({"blockcontentexecutionfrominternet": 1}),
            "applockerpolicy": json.dumps({
                "RuleCollections": [
                    {"RuleCollectionType": "Exe", "EnforcementMode": "AuditOnly"},
                ],
            }),
            "appidsvc": json.dumps({"Status": 4, "StartType": 3}),
            "scriptblocklogging": json.dumps({"EnableScriptBlockLogging": 1}),
            "languagemode": "FullLanguage",
            "vss": json.dumps({"Status": 4}),
            "vssadmin": "Contents of shadow copy set...\nShadow copy created: " + (now - timedelta(days=3)).strftime("%Y-%m-%d"),
            "get-wbsummary": json.dumps({
                "LastSuccessfulBackupTime": (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S"),
                "NumberOfVersions": 7,
            }),
        }
