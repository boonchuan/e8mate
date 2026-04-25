# 🛡️ E8Mate — Open Source Essential Eight Compliance Scanner

**Automated assessment of your organisation's cybersecurity posture against Australia's [ASD Essential Eight](https://www.cyber.gov.au/resources-business-and-government/essential-cyber-security/essential-eight) framework.**

[![PyPI](https://img.shields.io/pypi/v/e8mate?color=00e5b0&label=PyPI)](https://pypi.org/project/e8mate/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security Score](https://img.shields.io/badge/security8.work-Grade%20A-00e5b0)](https://security8.work)

---

## Why E8Mate?

The Essential Eight is Australia's baseline cybersecurity framework — mandatory for Commonwealth agencies, increasingly required by cyber insurers and government supply chains.

**The problem:** No open-source tool to automatically assess Essential Eight compliance. Existing options are expensive commercial products or manual Excel checklists.

**E8Mate fixes this.** Free, open-source, and supports three frameworks:

- 🇦🇺 **Essential Eight** — ASD Maturity Model (Australia)
- 🇸🇬 **Cyber Essentials** — CSA SS 712:2025 (Singapore)
- 🌏 **CIS Controls v8** — Global best practices

**Who this is for:**
- **Australian SMEs and not-for-profits** without budget for Tenable or Qualys, who still need to demonstrate Essential Eight progress
- **MSPs and consultants** serving Australian and Singaporean SMBs who want a defensible self-assessment baseline before a formal audit
- **In-house IT and compliance teams** preparing for a CSA Cyber Essentials or ASD-approved E8 assessment

## Quick Start

```bash
# Install from PyPI
pip install e8mate

# Scan the local Windows machine
e8mate scan

# Generate HTML audit report
e8mate scan --format html --output report.html

# Scan with mock data (for testing on Linux/macOS)
e8mate scan --transport mock --scenario partial
```

## Web Scanner

Try it now at **[security8.work](https://security8.work)** — free external scan of any domain against all three frameworks. No signup required.

## Essential Eight Controls

All 8 controls implemented at Maturity Level 1 with 30 checks:

| # | Control | Checks | Status |
|---|---------|--------|--------|
| 1 | Application Control | 4 | ✅ |
| 2 | Patch Applications | 3 | ✅ |
| 3 | Configure MS Office Macros | 3 | ✅ |
| 4 | User Application Hardening | 4 | ✅ |
| 5 | Restrict Admin Privileges | 4 | ✅ |
| 6 | Patch Operating Systems | 5 | ✅ |
| 7 | Multi-Factor Authentication | 3 | ✅ |
| 8 | Regular Backups | 4 | ✅ |

## How It Works

```
Collectors (28 checks)  -->  Scoring (ML0-ML3)  -->  Reporters (JSON/HTML)
       |
  Transport Layer
  +-- LocalPS      Windows PowerShell (direct)
  +-- WinRM        Remote Windows scanning
  +-- Mock         Dev/demo (3 scenarios)
```

## SaaS Dashboard

Multi-tenant MSP dashboard at [security8.work/dashboard](https://security8.work/dashboard/):

- Client management with per-org framework selection
- One-click external scans with grade tracking
- Branded printable reports (PDF via print)
- Scheduled scans (daily/weekly/monthly)
- Remediation tracker with auto-resolve on re-scan
- User management and audit logging

## Nuclei Templates

Companion [Nuclei](https://github.com/projectdiscovery/nuclei) templates for Essential Eight:

```bash
nuclei -t nuclei-templates/ -u https://target.example.com -tags essential-eight
```

## Development

```bash
git clone https://github.com/boonchuan/e8mate.git
cd e8mate
pip install -e ".[dev]"
pytest
ruff check .
```

## Roadmap

- [x] v0.1 — All 8 controls at ML1, 30 checks, JSON/HTML reports
- [x] v0.1 — Web scanner at security8.work (14 external checks)
- [x] v0.1 — Multi-framework support (AU/SG/Global)
- [x] v0.1 — SaaS dashboard for MSPs
- [x] v0.1 — Published on PyPI
- [ ] v0.2 — ML2/ML3 rule definitions
- [ ] v0.3 — Microsoft Graph API (MFA, Conditional Access)
- [ ] v0.4 — Branded PDF report generation
- [ ] v0.5 — Client portal (client-facing login)

## Open Source Contributions

E8Mate's author actively contributes Essential Eight and security-tooling content back to the broader ecosystem:

- **[Wazuh](https://github.com/wazuh/wazuh) — [PR #35645](https://github.com/wazuh/wazuh/pull/35645):** ACSC Essential Eight (ML1+ML2) SCA policy for Windows 10/11
- **[Lynis](https://github.com/CISOfy/lynis) — [PR #1731](https://github.com/CISOfy/lynis/pull/1731):** Nitrux Linux OS detection
- **[Lynis](https://github.com/CISOfy/lynis) — [PR #1733](https://github.com/CISOfy/lynis/pull/1733):** Kylin Linux Advanced Server detection
- **[Prowler](https://github.com/prowler-cloud/prowler):** prior merged contributions to AWS compliance checks
- **[Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates):** prior merged contributions

If you use the tools above and find Essential Eight content useful, please consider starring this repo too — it helps surface E8Mate to others looking for the same.

## Disclaimer

E8Mate is an **assessment tool**, not a certification body. Only ASD-approved assessors can formally certify Essential Eight maturity levels.

## Contributing

Contributions welcome! Priority areas: ML2/ML3 rule definitions, Nuclei templates, test coverage, documentation.

## License

MIT License — see [LICENSE](LICENSE) for details.

---

Built with 🇦🇺🤝🇸🇬 by [Boon](https://github.com/boonchuan) for the Australian and Singaporean cybersecurity community.

[security8.work](https://security8.work) · [PyPI](https://pypi.org/project/e8mate/) · [GitHub](https://github.com/boonchuan/e8mate)
