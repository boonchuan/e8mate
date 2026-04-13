"""WinRM transport — scan remote Windows machines from Ubuntu.

This is the primary production transport. E8Mate runs on your Ubuntu
workstation and connects to Windows targets via WinRM to execute
PowerShell checks.

SECURITY NOTES:
    - Always prefer HTTPS (port 5986) over HTTP (port 5985)
    - Use NTLM or Kerberos auth — avoid Basic auth
    - Credentials are never logged or stored to disk
    - All PowerShell scripts are validated before execution

Prerequisites on the Windows target:
    winrm quickconfig -transport:https

Or for domain-joined machines with NTLM/Kerberos (recommended):
    winrm quickconfig

Prerequisites on Ubuntu:
    pip install pywinrm --break-system-packages
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from e8mate.utils.security import (
    MAX_POWERSHELL_OUTPUT_BYTES,
    sanitize_evidence,
    validate_powershell_script,
    validate_target_host,
    validate_port,
)

logger = logging.getLogger(__name__)


class WinRMTransport:
    """Execute PowerShell commands on remote Windows hosts via WinRM.

    Usage from Ubuntu:
        transport = WinRMTransport(
            host="192.168.1.100",
            username="admin",
            password=password,  # from getpass or env var — never hardcode
        )
        output = transport.execute_powershell("Get-Service wuauserv")
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 5985,
        transport: str = "ntlm",
        use_ssl: bool = False,
    ):
        """
        Args:
            host: Windows target hostname or IP (validated).
            username: Account with admin privileges on the target.
            password: Password — never stored to disk or logged.
            port: WinRM port (5985 for HTTP, 5986 for HTTPS).
            transport: Auth method — 'ntlm' (recommended), 'basic', or 'kerberos'.
            use_ssl: Use HTTPS (strongly recommended for production).
        """
        try:
            import winrm
        except ImportError:
            raise ImportError(
                "pywinrm is required for remote scanning. "
                "Install it with: pip install pywinrm --break-system-packages"
            )

        # Validate inputs
        host = validate_target_host(host)
        port = validate_port(port)

        if transport not in ("ntlm", "basic", "kerberos"):
            raise ValueError(f"Transport must be 'ntlm', 'basic', or 'kerberos'. Got: {transport}")

        if transport == "basic":
            logger.warning(
                "Basic auth transmits credentials in base64 (not encrypted). "
                "Use NTLM or Kerberos instead."
            )

        if not use_ssl and port != 5986:
            logger.warning(
                "WinRM over HTTP (port %d) is unencrypted. "
                "Use --ssl or port 5986 for production scans.",
                port,
            )

        self.host = host
        self.username = username
        # Password is NOT stored as an attribute — only passed to session

        scheme = "https" if use_ssl else "http"
        endpoint = f"{scheme}://{host}:{port}/wsman"

        self._session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport=transport,
            server_cert_validation="ignore" if use_ssl else "validate",
        )

        # Test connection — do NOT log the error output as it may contain auth details
        test = self._session.run_ps("$env:COMPUTERNAME")
        if test.status_code != 0:
            raise ConnectionError(
                f"WinRM connection to {host} failed. "
                "Check credentials, firewall, and WinRM service status."
            )
        self._hostname = test.std_out.decode("utf-8").strip()

    @property
    def has_powershell(self) -> bool:
        return True

    def execute_powershell(self, script: str, timeout: int = 60) -> Optional[str]:
        """Execute a PowerShell script on the remote target.

        Scripts are validated before execution. Output is sanitized
        and truncated to prevent resource exhaustion.
        """
        # Validate script before sending to remote host
        try:
            validate_powershell_script(script)
        except ValueError as e:
            return f"[ERROR] Script validation failed: {e}"

        try:
            result = self._session.run_ps(script)

            if result.status_code == 0:
                output = result.std_out.decode("utf-8", errors="replace").strip()
                return sanitize_evidence(output, MAX_POWERSHELL_OUTPUT_BYTES)
            else:
                stderr = result.std_err.decode("utf-8", errors="replace").strip()
                return f"[ERROR] {stderr}" if stderr else None

        except OSError as e:
            return f"[ERROR] {str(e)}"

    def execute_cmd(self, command: str, timeout: int = 60) -> Optional[str]:
        """Execute a cmd.exe command on the remote target."""
        try:
            result = self._session.run_cmd(command)
            if result.status_code == 0:
                output = result.std_out.decode("utf-8", errors="replace").strip()
                return sanitize_evidence(output)
            return None
        except OSError as e:
            return f"[ERROR] {str(e)}"

    def get_system_info(self) -> dict:
        """Gather system information from the remote target."""
        info = {
            "hostname": self._hostname,
            "os_name": "unknown",
            "os_version": "unknown",
            "os_build": "unknown",
            "platform": "Windows (remote)",
        }

        os_info = self.execute_powershell(
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture | "
            "ConvertTo-Json"
        )

        if os_info and not os_info.startswith("[ERROR]"):
            try:
                parsed = json.loads(os_info)
                info.update({
                    "os_name": parsed.get("Caption", "unknown"),
                    "os_version": parsed.get("Version", "unknown"),
                    "os_build": parsed.get("BuildNumber", "unknown"),
                })
            except json.JSONDecodeError:
                pass

        return info
