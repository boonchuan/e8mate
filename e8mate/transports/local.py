"""Local transport — executes commands directly on the local machine."""

from __future__ import annotations

import platform
import shlex
import subprocess
from typing import Optional

from e8mate.utils.security import (
    MAX_POWERSHELL_OUTPUT_BYTES,
    sanitize_evidence,
    validate_powershell_script,
)


class LocalTransport:
    """Execute commands on the local system.

    On Windows: runs PowerShell natively.
    On Linux/Mac: runs PowerShell Core (pwsh) if available, otherwise
    falls back to mock transport for development.
    """

    def __init__(self):
        self.system = platform.system()
        self._ps_executable = self._detect_powershell()

    def _detect_powershell(self) -> Optional[str]:
        """Find available PowerShell executable."""
        candidates = ["powershell.exe", "pwsh.exe", "pwsh"]
        for candidate in candidates:
            try:
                result = subprocess.run(
                    [candidate, "-Command", "echo ok"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    return candidate
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return None

    @property
    def has_powershell(self) -> bool:
        return self._ps_executable is not None

    def execute_powershell(self, script: str, timeout: int = 60) -> Optional[str]:
        """Execute a PowerShell script and return its output.

        Scripts are validated against a blocklist of dangerous patterns
        before execution. Output is truncated to prevent resource exhaustion.
        """
        if not self._ps_executable:
            return None

        # Validate script before execution
        try:
            validate_powershell_script(script)
        except ValueError as e:
            return f"[ERROR] Script validation failed: {e}"

        try:
            result = subprocess.run(
                [self._ps_executable, "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                return sanitize_evidence(output, MAX_POWERSHELL_OUTPUT_BYTES)
            else:
                return f"[ERROR] {result.stderr.strip()}" if result.stderr else None
        except subprocess.TimeoutExpired:
            return "[ERROR] Command timed out"
        except OSError as e:
            return f"[ERROR] {str(e)}"

    def execute_cmd(self, command: str, timeout: int = 60) -> Optional[str]:
        """Execute a command and return its output.

        Uses shlex.split to avoid shell=True injection risk.
        Only accepts simple commands — no pipes, redirects, or chaining.
        """
        try:
            # Parse command safely — no shell interpretation
            args = shlex.split(command)
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                return sanitize_evidence(result.stdout.strip())
            return None
        except (subprocess.TimeoutExpired, ValueError, OSError):
            return None

    def get_system_info(self) -> dict:
        """Gather basic system information."""
        info = {
            "hostname": platform.node(),
            "os_name": platform.system(),
            "os_version": platform.version(),
            "os_build": platform.release(),
            "platform": platform.platform(),
        }

        if self.has_powershell and self.system == "Windows":
            os_info = self.execute_powershell(
                "(Get-CimInstance Win32_OperatingSystem | "
                "Select-Object Caption, Version, BuildNumber, OSArchitecture "
                "| ConvertTo-Json)"
            )
            if os_info and not os_info.startswith("[ERROR]"):
                import json
                try:
                    parsed = json.loads(os_info)
                    info.update({
                        "os_name": parsed.get("Caption", info["os_name"]),
                        "os_version": parsed.get("Version", info["os_version"]),
                        "os_build": parsed.get("BuildNumber", info["os_build"]),
                    })
                except json.JSONDecodeError:
                    pass

        return info
