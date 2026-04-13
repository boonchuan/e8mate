# 🛡️ E8Mate — Open Source Essential Eight Compliance Scanner

**Automated assessment of your organisation's cybersecurity posture against Australia's [ASD Essential Eight](https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model) framework.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## Why E8Mate?

The Essential Eight is Australia's baseline cybersecurity framework. It's mandatory for Commonwealth government agencies and increasingly expected across the private sector, government supply chains, and cyber insurance applications.

**The problem:** There is no open-source tool to automatically assess Essential Eight compliance. Existing options are either expensive commercial products or manual Excel checklists.

**E8Mate fixes this.** It's a free, open-source scanner that:

- 🔍 **Scans** Windows/M365 environments against all 8 controls
- 📊 **Scores** maturity levels (ML0–ML3) per ASD's official methodology
- 📄 **Generates** audit-ready reports with evidence packages
- 🔧 **Prioritises** remediation steps to reach your target maturity level

## Quick Start

```bash
# Install
pip install e8mate

# Scan the local machine
e8mate scan --local

# Scan specific controls
e8mate scan --local --controls patch-os,mfa,admin

# Target a specific maturity level
e8mate scan --local --maturity-level 2

# Output HTML report
e8mate scan --local --output report.html --format html
```

## Essential Eight Controls

| # | Control | ML1 Status |
|---|---------|-----------|
| 1 | Application Control | 🔜 In Progress |
| 2 | Patch Applications | 🔜 In Progress |
| 3 | Configure MS Office Macros | 🔜 In Progress |
| 4 | User Application Hardening | 🔜 In Progress |
| 5 | Restrict Admin Privileges | 🔜 In Progress |
| 6 | Patch Operating Systems | ✅ Implemented |
| 7 | Multi-Factor Authentication | 🔜 In Progress |
| 8 | Regular Backups | 🔜 In Progress |

## How It Works

E8Mate runs PowerShell commands (locally or via WinRM) to collect evidence about your system's configuration, then scores each finding against ASD's maturity model rules.

```
┌─────────────────┐     ┌──────────────┐     ┌───────────────┐
│   Collectors     │────▶│   Scoring    │────▶│   Reporters   │
│ (8 controls)     │     │ (ML0–ML3)    │     │ (JSON/HTML)   │
└─────────────────┘     └──────────────┘     └───────────────┘
        │
   ┌────┴─────┐
   │Transport  │
   │Layer      │
   ├──────────┤
   │• Local PS │
   │• WinRM    │
   │• Graph API│
   └──────────┘
```

## Development

```bash
# Clone
git clone https://github.com/e8mate/e8mate.git
cd e8mate

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check .
```

### Adding a New Collector

1. Create a new file in `e8mate/collectors/` (e.g., `patch_apps.py`)
2. Extend `BaseCollector` and implement `collect()`
3. Register it in `e8mate/scanner.py` COLLECTOR_REGISTRY
4. Add ML1 rules in `rules/ml1.yaml`
5. Write tests in `tests/test_collectors/`

See `e8mate/collectors/patch_os.py` for a complete example.

## Nuclei Templates

E8Mate includes companion [Nuclei](https://github.com/projectdiscovery/nuclei) templates for network-side Essential Eight checks. These test internet-facing services for common misconfigurations.

```bash
# Run E8 Nuclei templates
nuclei -t nuclei-templates/ -u https://target.example.com
```

## Roadmap

- **v0.1** — MVP: All 8 collectors at ML1, JSON/HTML reports
- **v0.2** — ML2/ML3 rule definitions, WinRM remote scanning
- **v0.3** — Microsoft Graph API integration (MFA, Conditional Access)
- **v0.4** — Web dashboard for MSPs (multi-tenant)
- **v0.5** — Singapore Cyber Essentials (SS 712:2025) dual-framework support

## Important Disclaimer

E8Mate is an **assessment tool**, not a certification body. Only ASD-approved assessors can formally certify Essential Eight maturity levels. E8Mate helps you prepare for and track compliance, but its results should not be represented as official certification.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](docs/contributing.md) for guidelines.

Priority areas:
- Collector implementations for remaining controls
- ML2/ML3 rule definitions
- HTML report template design
- Test coverage
- Documentation

## License

MIT License — see [LICENSE](LICENSE) for details.

---

Built with 🇦🇺🤝🇸🇬 by [Boon](https://github.com/boon) for the Australian and Singaporean cybersecurity community.
