"""Main scanner orchestrator — coordinates collectors, scoring, and reporting."""

from __future__ import annotations

import time
from typing import Optional

from e8mate.evidence.models import (
    E8Control,
    MaturityLevel,
    ScanResult,
    SystemInfo,
)
from e8mate.scoring.maturity import calculate_overall_maturity


# Registry of available collectors
COLLECTOR_REGISTRY = {
    E8Control.APP_CONTROL: "e8mate.collectors.app_control.AppControlCollector",
    E8Control.PATCH_APPS: "e8mate.collectors.patch_apps.PatchAppsCollector",
    E8Control.MACRO_SETTINGS: "e8mate.collectors.macro_settings.MacroSettingsCollector",
    E8Control.APP_HARDENING: "e8mate.collectors.app_hardening.AppHardeningCollector",
    E8Control.ADMIN_PRIVILEGES: "e8mate.collectors.admin_privs.AdminPrivsCollector",
    E8Control.PATCH_OS: "e8mate.collectors.patch_os.PatchOSCollector",
    E8Control.MFA: "e8mate.collectors.mfa.MFACollector",
    E8Control.BACKUPS: "e8mate.collectors.backups.BackupsCollector",
}


def _import_collector(dotted_path: str):
    """Dynamically import a collector class from its dotted path."""
    module_path, class_name = dotted_path.rsplit(".", 1)
    import importlib
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


class E8Scanner:
    """Orchestrates Essential Eight compliance scanning."""

    def __init__(
        self,
        transport,
        target_maturity: MaturityLevel = MaturityLevel.ML1,
        controls: Optional[list[str]] = None,
    ):
        """
        Args:
            transport: Transport instance for command execution.
            target_maturity: Target maturity level to assess.
            controls: Optional list of control names to scan (default: all available).
        """
        self.transport = transport
        self.target_maturity = target_maturity
        self.requested_controls = controls

    def scan(self) -> ScanResult:
        """Run the full scan and return results."""
        start_time = time.time()

        # Gather system info
        sys_info = self._gather_system_info()

        # Determine which controls to scan
        controls_to_scan = self._resolve_controls()

        # Run collectors
        results = []
        for control, collector_path in controls_to_scan.items():
            collector_cls = _import_collector(collector_path)
            collector = collector_cls(
                transport=self.transport,
                target_maturity=self.target_maturity,
            )
            result = collector.collect()
            results.append(result)

        # Build scan result
        scan_result = ScanResult(
            target_maturity=self.target_maturity,
            system_info=sys_info,
            control_results=results,
            scan_duration_seconds=round(time.time() - start_time, 2),
        )

        # Calculate overall maturity
        scan_result.overall_maturity = calculate_overall_maturity(scan_result)

        return scan_result

    def _gather_system_info(self) -> SystemInfo:
        """Collect system information via the transport."""
        info = self.transport.get_system_info()
        return SystemInfo(
            hostname=info.get("hostname", "unknown"),
            os_name=info.get("os_name", "unknown"),
            os_version=info.get("os_version", "unknown"),
            os_build=info.get("os_build", "unknown"),
            scan_type="local",
            target="localhost",
        )

    def _resolve_controls(self) -> dict:
        """Determine which controls to scan based on user input."""
        if self.requested_controls:
            # Map user-friendly names to E8Control enum
            name_map = {c.value: c for c in E8Control}
            # Also support short names
            short_map = {
                "patch-os": E8Control.PATCH_OS,
                "patch-apps": E8Control.PATCH_APPS,
                "macros": E8Control.MACRO_SETTINGS,
                "hardening": E8Control.APP_HARDENING,
                "admin": E8Control.ADMIN_PRIVILEGES,
                "app-control": E8Control.APP_CONTROL,
                "mfa": E8Control.MFA,
                "backups": E8Control.BACKUPS,
            }
            name_map.update(short_map)

            filtered = {}
            for name in self.requested_controls:
                control = name_map.get(name.lower().replace("_", "-"))
                if control and control in COLLECTOR_REGISTRY:
                    filtered[control] = COLLECTOR_REGISTRY[control]
            return filtered

        return COLLECTOR_REGISTRY
