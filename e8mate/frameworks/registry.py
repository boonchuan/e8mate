"""Framework definitions and check-to-control mappings.

Supports:
  - e8:     Australian Essential Eight (ASD)
  - sg:     Singapore Cyber Essentials (CSA SS 712:2025)
  - global: CIS Critical Security Controls v8
"""

FRAMEWORK_INFO = {
    "e8": {
        "name": "Essential Eight",
        "full_name": "ASD Essential Eight Maturity Model",
        "country": "Australia",
        "flag": "\U0001f1e6\U0001f1fa",
        "description": "Australian Signals Directorate baseline cybersecurity framework",
        "url": "https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight",
    },
    "sg": {
        "name": "Cyber Essentials",
        "full_name": "CSA Cyber Essentials (SS 712:2025)",
        "country": "Singapore",
        "flag": "\U0001f1f8\U0001f1ec",
        "description": "Cyber Security Agency of Singapore certification for organisations",
        "url": "https://www.csa.gov.sg/our-programmes/support-for-enterprises/sg-cyber-safe-programme",
    },
    "global": {
        "name": "CIS Controls",
        "full_name": "CIS Critical Security Controls v8",
        "country": "Global",
        "flag": "\U0001f30f",
        "description": "Center for Internet Security prioritised cybersecurity best practices",
        "url": "https://www.cisecurity.org/controls",
    },
}

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


def get_framework(code: str) -> dict:
    """Return framework info by code, defaulting to Essential Eight."""
    return FRAMEWORK_INFO.get(code, FRAMEWORK_INFO["e8"])
