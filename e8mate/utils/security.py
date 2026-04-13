"""Security hardening utilities for E8Mate.

This module provides input validation, output sanitization, and
secure defaults used across the project. Every external input
and output path runs through these functions.
"""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from pathlib import Path
from typing import Optional


# --- Input Validation ---

# Max sizes to prevent resource exhaustion
MAX_POWERSHELL_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_POWERSHELL_SCRIPT_LENGTH = 50_000  # chars
MAX_HOSTNAME_LENGTH = 255
MAX_OUTPUT_PATH_LENGTH = 4096


def validate_target_host(host: str) -> str:
    """Validate and sanitize a target host string.

    Accepts:
        - IPv4 addresses (e.g., 192.168.1.100)
        - IPv6 addresses (e.g., ::1)
        - Hostnames (e.g., dc01.corp.local)

    Rejects:
        - URLs, schemes, paths
        - Shell metacharacters
        - Excessively long strings

    Raises:
        ValueError: If the host string is invalid.
    """
    if not host or len(host) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Host must be 1-{MAX_HOSTNAME_LENGTH} characters.")

    host = host.strip()

    # Reject anything that looks like a URL or contains a scheme
    if "://" in host or host.startswith(("http", "ftp", "file")):
        raise ValueError(f"Host must be an IP or hostname, not a URL: {host}")

    # Reject shell metacharacters
    dangerous_chars = set(";|&$`\\\"'{}()[]<>!\n\r\t")
    if dangerous_chars & set(host):
        raise ValueError(f"Host contains illegal characters: {host}")

    # Try parsing as IP address first
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    # Validate as hostname (RFC 1123)
    hostname_re = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    )
    if not hostname_re.match(host):
        raise ValueError(f"Invalid hostname format: {host}")

    return host


def validate_port(port: int) -> int:
    """Validate a network port number."""
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError(f"Port must be 1-65535, got: {port}")
    return port


def validate_output_path(path_str: str) -> Path:
    """Validate and resolve an output file path.

    Prevents:
        - Path traversal (../)
        - Writing to system directories
        - Symlink attacks

    Returns:
        Resolved, safe Path object.
    """
    if len(path_str) > MAX_OUTPUT_PATH_LENGTH:
        raise ValueError("Output path is too long.")

    path = Path(path_str).resolve()

    # Block writes to system directories
    blocked_prefixes = ["/etc", "/usr", "/bin", "/sbin", "/boot", "/sys", "/proc", "/dev"]
    for prefix in blocked_prefixes:
        if str(path).startswith(prefix):
            raise ValueError(f"Cannot write to system directory: {prefix}")

    # Block symlinks in the path
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError(f"Symlink detected in output path: {parent}")

    return path


def validate_maturity_level(level: int) -> int:
    """Validate maturity level is 1, 2, or 3."""
    if level not in (1, 2, 3):
        raise ValueError(f"Maturity level must be 1, 2, or 3. Got: {level}")
    return level


def validate_controls_list(controls_csv: str) -> list[str]:
    """Validate and parse a comma-separated controls list."""
    valid_controls = {
        "patch-os", "patch-apps", "macros", "hardening",
        "admin", "app-control", "mfa", "backups",
        "patch_os", "patch_apps", "macro_settings",
        "app_hardening", "admin_privileges", "app_control",
        "multi_factor_authentication", "regular_backups",
    }

    controls = [c.strip().lower() for c in controls_csv.split(",") if c.strip()]

    for ctrl in controls:
        if ctrl not in valid_controls:
            raise ValueError(
                f"Unknown control: '{ctrl}'. "
                f"Valid options: {', '.join(sorted(valid_controls))}"
            )

    return controls


# --- PowerShell Script Safety ---

# PowerShell commands that are explicitly allowed in collectors.
# Any script passed to a transport must only use cmdlets from this list
# or be explicitly marked as trusted.
ALLOWED_PS_CMDLETS = {
    # System info
    "get-ciminstance", "get-wmiobject",
    # Services
    "get-service",
    # Updates
    "get-hotfix", "get-windowsupdate",
    # Registry
    "get-itemproperty",
    # Users/Groups
    "get-localgroupmember", "get-adgroupmember", "search-adaccount",
    # AppLocker
    "get-applockerpolicy",
    # Files
    "get-item", "get-childitem", "test-path",
    # VSS/Backup
    "get-wbsummary", "get-wbpolicy",
    # General
    "select-object", "where-object", "sort-object",
    "convertto-json", "format-list",
    # Environment
    "$env:", "$executioncontext",
    # Comparison operators
    "-eq", "-ne", "-gt", "-lt",
}


def validate_powershell_script(script: str) -> str:
    """Basic validation of PowerShell scripts before execution.

    This is defence-in-depth — our scripts come from our own collectors,
    not user input. But we validate anyway to catch bugs and prevent
    accidental injection if the pattern is ever misused.

    Checks:
        - Script length within bounds
        - No obviously dangerous patterns (Invoke-WebRequest, download, etc.)
        - No encoded commands (bypass detection)
    """
    if len(script) > MAX_POWERSHELL_SCRIPT_LENGTH:
        raise ValueError(
            f"PowerShell script exceeds max length ({MAX_POWERSHELL_SCRIPT_LENGTH} chars)."
        )

    script_lower = script.lower()

    # Block patterns that should never appear in compliance checks
    blocked_patterns = [
        "invoke-webrequest",
        "invoke-restmethod",
        "downloadstring",
        "downloadfile",
        "start-bitstransfer",
        "new-object net.webclient",
        "system.net.webclient",
        "[net.servicepointmanager]",
        "invoke-expression",
        "iex ",
        "iex(",
        "-encodedcommand",
        "-enc ",
        "set-executionpolicy",
        "remove-item -recurse",
        "format-volume",
        "clear-disk",
        "stop-computer",
        "restart-computer",
        "new-psdrive",  # mounting network shares
    ]

    for pattern in blocked_patterns:
        if pattern in script_lower:
            raise ValueError(
                f"PowerShell script contains blocked pattern: '{pattern}'. "
                "E8Mate collectors should only read system state, never modify it."
            )

    return script


# --- Output Sanitization ---

def sanitize_evidence(raw_output: str, max_length: int = MAX_POWERSHELL_OUTPUT_BYTES) -> str:
    """Sanitize raw command output before storing as evidence.

    Truncates oversized output and strips control characters.
    """
    if len(raw_output) > max_length:
        raw_output = raw_output[:max_length] + f"\n[TRUNCATED — output exceeded {max_length} bytes]"

    # Strip ANSI escape codes
    ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    raw_output = ansi_re.sub("", raw_output)

    # Strip null bytes
    raw_output = raw_output.replace("\x00", "")

    return raw_output


def redact_sensitive_fields(data: dict, fields_to_redact: Optional[set] = None) -> dict:
    """Redact sensitive fields from a dictionary before output.

    Used when generating reports that might be shared externally.
    """
    if fields_to_redact is None:
        fields_to_redact = {
            "password", "secret", "token", "api_key", "apikey",
            "client_secret", "private_key", "credential",
        }

    redacted = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in fields_to_redact):
            redacted[key] = "[REDACTED]"
        elif isinstance(value, dict):
            redacted[key] = redact_sensitive_fields(value, fields_to_redact)
        elif isinstance(value, list):
            redacted[key] = [
                redact_sensitive_fields(item, fields_to_redact) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            redacted[key] = value

    return redacted


def sanitize_html(text: str) -> str:
    """Escape HTML special characters to prevent XSS in reports."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


# --- File Permissions ---

def set_report_permissions(filepath: Path) -> None:
    """Set restrictive permissions on report files.

    Reports contain compliance data that may reveal security weaknesses.
    Owner read/write only (0o600).
    """
    try:
        filepath.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass  # Best effort — may fail on some filesystems


def set_config_permissions(filepath: Path) -> None:
    """Set restrictive permissions on config files that may contain credentials.

    Owner read/write only (0o600).
    """
    try:
        filepath.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass
