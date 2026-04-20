#!/usr/bin/env python3
"""E8Mate External Scanner — network-side Essential Eight checks.

Scans a domain from outside to assess its internet-facing security
posture against Essential Eight controls. Used by the security8.work
web interface.

Usage:
    python3 external_scan.py example.com
    python3 external_scan.py example.com --json
"""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import re
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Check:
    id: str
    control: str
    title: str
    outcome: str = "not_assessed"  # pass, fail, warn, info, error
    detail: str = ""
    severity: str = "medium"  # critical, high, medium, low, info
    frameworks: dict = field(default_factory=dict)
    # frameworks maps to: { "e8": {...}, "sg": {...}, "global": {...} }


# Framework mapping for each check
FRAMEWORK_MAP = {
    "EXT-HTTPS-001": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "Encryption in Transit", "ref": "CIS Control 3.10"},
    },
    "EXT-SSL-001": {
        "e8": {"control": "Patch Applications", "ref": "ASD E8 Control 2"},
        "sg": {"control": "Software Updates", "ref": "CSA Cyber Essentials 4.3"},
        "global": {"control": "Data Protection", "ref": "CIS Control 3.9"},
    },
    "EXT-SSL-002": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "Encryption Standards", "ref": "CIS Control 3.10"},
    },
    "EXT-HDR-001": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "HTTP Security", "ref": "OWASP Secure Headers"},
    },
    "EXT-HDR-002": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "HTTP Security", "ref": "OWASP Secure Headers"},
    },
    "EXT-HDR-003": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "HTTP Security", "ref": "OWASP Secure Headers"},
    },
    "EXT-HDR-004": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "HTTP Security", "ref": "OWASP Secure Headers"},
    },
    "EXT-HDR-005": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Secure Configuration", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "Information Disclosure", "ref": "CIS Control 3.12"},
    },
    "EXT-EMAIL-001": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Email Protection", "ref": "CSA Cyber Essentials 4.5"},
        "global": {"control": "Email Security", "ref": "CIS Control 9.5"},
    },
    "EXT-EMAIL-002": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Email Protection", "ref": "CSA Cyber Essentials 4.5"},
        "global": {"control": "Email Security", "ref": "CIS Control 9.5"},
    },
    "EXT-SVC-001": {
        "e8": {"control": "Multi-Factor Authentication", "ref": "ASD E8 Control 7"},
        "sg": {"control": "Access Control", "ref": "CSA Cyber Essentials 4.2"},
        "global": {"control": "Network Security", "ref": "CIS Control 4.4"},
    },
    "EXT-SVC-002": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Network Security", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "Network Security", "ref": "CIS Control 4.4"},
    },
    "EXT-SVC-003": {
        "e8": {"control": "User Application Hardening", "ref": "ASD E8 Control 4"},
        "sg": {"control": "Network Security", "ref": "CSA Cyber Essentials 4.4"},
        "global": {"control": "Network Security", "ref": "CIS Control 4.1"},
    },
    "EXT-SVC-004": {
        "e8": {"control": "Multi-Factor Authentication", "ref": "ASD E8 Control 7"},
        "sg": {"control": "Access Control", "ref": "CSA Cyber Essentials 4.2"},
        "global": {"control": "Network Security", "ref": "CIS Control 4.4"},
    },
}

FRAMEWORK_INFO = {
    "e8": {
        "name": "Essential Eight",
        "full_name": "ASD Essential Eight Maturity Model",
        "country": "Australia",
        "flag": "🇦🇺",
        "description": "Australian Signals Directorate's baseline cybersecurity framework",
        "url": "https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model",
    },
    "sg": {
        "name": "Cyber Essentials",
        "full_name": "CSA Cyber Essentials (SS 712:2025)",
        "country": "Singapore",
        "flag": "🇸🇬",
        "description": "Cyber Security Agency of Singapore's certification for organisations",
        "url": "https://www.csa.gov.sg/our-programmes/support-for-enterprises/sg-cyber-safe-programme",
    },
    "global": {
        "name": "CIS Controls",
        "full_name": "CIS Critical Security Controls v8",
        "country": "Global",
        "flag": "🌏",
        "description": "Center for Internet Security's prioritised cybersecurity best practices",
        "url": "https://www.cisecurity.org/controls",
    },
}


@dataclass
class ExternalScanResult:
    domain: str
    scan_date: str = ""
    scan_duration: float = 0.0
    ip_address: str = ""
    score: int = 0
    max_score: int = 0
    grade: str = "F"
    checks: list = field(default_factory=list)

    def calculate_score(self):
        weights = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
        self.max_score = sum(weights.get(c["severity"], 5) for c in self.checks if c["outcome"] != "error")
        self.score = sum(
            weights.get(c["severity"], 5)
            for c in self.checks
            if c["outcome"] == "pass"
        )
        if self.max_score == 0:
            self.grade = "?"
            return
        pct = (self.score / self.max_score) * 100
        if pct >= 90: self.grade = "A"
        elif pct >= 75: self.grade = "B"
        elif pct >= 60: self.grade = "C"
        elif pct >= 40: self.grade = "D"
        else: self.grade = "F"


def resolve_domain(domain: str) -> Optional[str]:
    """Resolve domain to IP address."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def check_ssl(domain: str) -> list[Check]:
    """Check SSL/TLS configuration."""
    checks = []

    # SSL certificate validity
    c = Check(id="EXT-SSL-001", control="patch_applications", title="SSL certificate is valid",
              severity="critical")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()

            # Check expiry
            not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - datetime.now()).days

            if days_left < 0:
                c.outcome = "fail"
                c.detail = f"Certificate expired {abs(days_left)} days ago."
            elif days_left < 30:
                c.outcome = "warn"
                c.detail = f"Certificate expires in {days_left} days."
            else:
                c.outcome = "pass"
                c.detail = f"Certificate valid for {days_left} more days. Expires {not_after.strftime('%Y-%m-%d')}."
    except ssl.SSLCertVerificationError as e:
        c.outcome = "fail"
        c.detail = f"Certificate verification failed: {str(e)[:100]}"
    except (socket.timeout, ConnectionRefusedError, OSError):
        c.outcome = "error"
        c.detail = "Could not connect on port 443."
    checks.append(c)

    # TLS version check
    c2 = Check(id="EXT-SSL-002", control="user_application_hardening", title="Modern TLS versions only (1.2+)",
               severity="high")
    for bad_proto, name in [(ssl.PROTOCOL_TLSv1, "TLS 1.0"), (ssl.PROTOCOL_TLSv1_1, "TLS 1.1")]:
        try:
            ctx = ssl.SSLContext(bad_proto)
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                c2.outcome = "fail"
                c2.detail = f"{name} is accepted. Disable legacy TLS protocols."
                break
        except (ssl.SSLError, OSError, AttributeError):
            pass  # Good — protocol rejected
    if c2.outcome == "not_assessed":
        c2.outcome = "pass"
        c2.detail = "Only TLS 1.2+ accepted. Legacy protocols disabled."
    checks.append(c2)

    return checks


def check_headers(domain: str) -> list[Check]:
    """Check HTTP security headers."""
    import urllib.request

    headers_raw = {}
    try:
        req = urllib.request.Request(f"https://{domain}/",
                                     headers={"User-Agent": "E8Mate-Scanner/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            headers_raw = {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        # Try HTTP fallback
        try:
            req = urllib.request.Request(f"http://{domain}/",
                                         headers={"User-Agent": "E8Mate-Scanner/0.1"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                headers_raw = {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return [Check(id="EXT-HDR-001", control="user_application_hardening",
                         title="HTTP headers check", outcome="error",
                         detail="Could not connect to web server.")]

    checks = []

    # HSTS
    c = Check(id="EXT-HDR-001", control="user_application_hardening",
              title="Strict-Transport-Security (HSTS)", severity="high")
    hsts = headers_raw.get("strict-transport-security", "")
    if hsts:
        c.outcome = "pass"
        c.detail = f"HSTS enabled: {hsts[:80]}"
    else:
        c.outcome = "fail"
        c.detail = "HSTS header missing. Browsers can be downgraded to HTTP."
    checks.append(c)

    # Content-Security-Policy
    c = Check(id="EXT-HDR-002", control="user_application_hardening",
              title="Content-Security-Policy (CSP)", severity="medium")
    csp = headers_raw.get("content-security-policy", "")
    if csp:
        c.outcome = "pass"
        c.detail = f"CSP set: {csp[:80]}..."
    else:
        c.outcome = "fail"
        c.detail = "No Content-Security-Policy header. XSS risk increased."
    checks.append(c)

    # X-Content-Type-Options
    c = Check(id="EXT-HDR-003", control="user_application_hardening",
              title="X-Content-Type-Options", severity="medium")
    if headers_raw.get("x-content-type-options", "").lower() == "nosniff":
        c.outcome = "pass"
        c.detail = "X-Content-Type-Options: nosniff — MIME sniffing prevented."
    else:
        c.outcome = "fail"
        c.detail = "Missing X-Content-Type-Options header."
    checks.append(c)

    # X-Frame-Options
    c = Check(id="EXT-HDR-004", control="user_application_hardening",
              title="X-Frame-Options", severity="medium")
    xfo = headers_raw.get("x-frame-options", "").lower()
    if xfo in ("deny", "sameorigin"):
        c.outcome = "pass"
        c.detail = f"X-Frame-Options: {xfo} — clickjacking mitigated."
    else:
        c.outcome = "fail"
        c.detail = "Missing or weak X-Frame-Options header."
    checks.append(c)

    # Server header leakage
    c = Check(id="EXT-HDR-005", control="user_application_hardening",
              title="Server header not leaking version", severity="low")
    server = headers_raw.get("server", "")
    if not server:
        c.outcome = "pass"
        c.detail = "No Server header exposed."
    elif re.search(r"\d+\.\d+", server):
        c.outcome = "fail"
        c.detail = f"Server header exposes version: {server}"
    else:
        c.outcome = "pass"
        c.detail = f"Server header present but no version leaked: {server}"
    checks.append(c)

    return checks


def check_email_security(domain: str) -> list[Check]:
    """Check SPF, DMARC, and DKIM configuration via DNS."""
    import subprocess
    checks = []

    def dns_txt(name: str) -> str:
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", name],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Fallback for systems without dig
            try:
                import socket
                # nslookup fallback
                result = subprocess.run(
                    ["nslookup", "-type=TXT", name],
                    capture_output=True, text=True, timeout=10
                )
                return result.stdout.strip()
            except Exception:
                return ""

    # SPF
    c = Check(id="EXT-EMAIL-001", control="user_application_hardening",
              title="SPF record configured", severity="medium")
    spf = dns_txt(domain)
    if "v=spf1" in spf:
        c.outcome = "pass"
        c.detail = f"SPF record found."
    else:
        c.outcome = "fail"
        c.detail = "No SPF record. Email spoofing is possible."
    checks.append(c)

    # DMARC
    c = Check(id="EXT-EMAIL-002", control="user_application_hardening",
              title="DMARC record configured", severity="medium")
    dmarc = dns_txt(f"_dmarc.{domain}")
    if "V=DMARC1" in dmarc.upper():
        if "p=reject" in dmarc.lower() or "p=quarantine" in dmarc.lower():
            c.outcome = "pass"
            c.detail = f"DMARC configured with enforcement."
        else:
            c.outcome = "warn"
            c.detail = f"DMARC set to p=none (monitoring only)."
    else:
        c.outcome = "fail"
        c.detail = "No DMARC record found."
    checks.append(c)

    return checks


def check_exposed_services(ip: str) -> list[Check]:
    """Check for commonly exposed dangerous services."""
    checks = []

    dangerous_ports = [
        (3389, "RDP", "EXT-SVC-001", "multi_factor_authentication", "critical",
         "RDP exposed to internet — requires MFA and NLA"),
        (445, "SMB", "EXT-SVC-002", "user_application_hardening", "critical",
         "SMB exposed to internet — high risk for ransomware"),
        (23, "Telnet", "EXT-SVC-003", "user_application_hardening", "high",
         "Telnet exposed — cleartext protocol, should be disabled"),
        (5985, "WinRM-HTTP", "EXT-SVC-004", "multi_factor_authentication", "high",
         "WinRM HTTP exposed — credentials may be transmitted insecurely"),
    ]

    for port, service, check_id, control, severity, desc in dangerous_ports:
        c = Check(id=check_id, control=control, title=f"{service} (port {port}) not exposed",
                  severity=severity)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                c.outcome = "fail"
                c.detail = f"{service} is accessible on port {port}. {desc}."
            else:
                c.outcome = "pass"
                c.detail = f"{service} (port {port}) is not accessible from the internet."
        except (socket.timeout, OSError):
            c.outcome = "pass"
            c.detail = f"{service} (port {port}) is not accessible."
        checks.append(c)

    return checks


def check_https_redirect(domain: str) -> list[Check]:
    """Check if HTTP redirects to HTTPS."""
    import urllib.request

    c = Check(id="EXT-HTTPS-001", control="user_application_hardening",
              title="HTTP redirects to HTTPS", severity="high")
    try:
        req = urllib.request.Request(f"http://{domain}/",
                                     headers={"User-Agent": "E8Mate-Scanner/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.url.startswith("https://"):
                c.outcome = "pass"
                c.detail = f"HTTP correctly redirects to HTTPS."
            else:
                c.outcome = "fail"
                c.detail = "HTTP does not redirect to HTTPS."
    except Exception:
        c.outcome = "warn"
        c.detail = "Could not check HTTP redirect."

    return [c]


def scan_domain(domain: str, framework: str = "e8") -> dict:
    """Run all external checks against a domain."""
    start = time.time()

    # Clean domain input
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')
    domain = domain.split('/')[0]  # Remove any path

    # Validate domain format
    if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$', domain):
        return {"error": f"Invalid domain: {domain}"}

    # Validate framework
    if framework not in FRAMEWORK_INFO:
        framework = "e8"

    result = ExternalScanResult(
        domain=domain,
        scan_date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    # Resolve IP
    ip = resolve_domain(domain)
    if not ip:
        return {"error": f"Could not resolve domain: {domain}"}
    result.ip_address = ip

    # Run checks
    all_checks = []
    all_checks.extend(check_https_redirect(domain))
    all_checks.extend(check_ssl(domain))
    all_checks.extend(check_headers(domain))
    all_checks.extend(check_email_security(domain))
    all_checks.extend(check_exposed_services(ip))

    # Attach framework mappings
    for c in all_checks:
        c.frameworks = FRAMEWORK_MAP.get(c.id, {})

    result.checks = [asdict(c) for c in all_checks]
    result.scan_duration = round(time.time() - start, 2)
    result.calculate_score()

    output = asdict(result)
    output["framework"] = framework
    output["framework_info"] = FRAMEWORK_INFO.get(framework, FRAMEWORK_INFO["e8"])
    return output


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 external_scan.py <domain> [--framework e8|sg|global] [--json]")
        sys.exit(1)

    domain = sys.argv[1]
    framework = "e8"
    if "--framework" in sys.argv:
        idx = sys.argv.index("--framework")
        if idx + 1 < len(sys.argv):
            framework = sys.argv[idx + 1]

    result = scan_domain(domain, framework)

    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(f"Error: {result['error']}")
            sys.exit(1)

        fw = result.get("framework_info", {})
        print(f"\n  {fw.get('flag','')} {fw.get('name', 'Security')} External Scan")
        print(f"  Domain:   {result['domain']}")
        print(f"  IP:       {result['ip_address']}")
        print(f"  Grade:    {result['grade']}")
        print(f"  Score:    {result['score']}/{result['max_score']}")
        print(f"  Duration: {result['scan_duration']}s\n")

        for c in result["checks"]:
            icon = {"pass": "✅", "fail": "❌", "warn": "⚠️", "error": "💀", "info": "ℹ️"}.get(c["outcome"], "❓")
            fm = c.get("frameworks", {}).get(framework, {})
            ctrl = fm.get("control", c.get("control", ""))
            print(f"  {icon} [{c['id']}] {c['title']}")
            if ctrl:
                print(f"     {fw.get('flag','')} {ctrl} — {fm.get('ref', '')}")
            if c["outcome"] in ("fail", "warn"):
                print(f"     → {c['detail']}")
