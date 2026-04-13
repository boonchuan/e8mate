# E8Mate — Open Source Essential Eight Compliance Scanner

## Product Specification & MVP Roadmap

---

## 1. Executive Summary

**E8Mate** is an open-source, automated compliance scanner that assesses an organisation's cybersecurity posture against Australia's ASD Essential Eight Maturity Model. It runs agentlessly against Windows/Microsoft 365 environments, produces scored maturity reports per control, and generates audit-ready evidence packages.

**Why this wins:** There is no open-source Essential Eight scanner. The only existing tools are commercial (Huntsman's E8 Auditor, ConnectSecure) or manual (Excel trackers, GPO templates). ASD's own assessment tools (E8MVT, ACVT) are only available via their Partner Portal. E8Mate fills a genuine market gap.

**Target users:**
- Australian MSPs serving SME clients (channel partners)
- IT managers at SMEs pursuing Essential Eight compliance
- Government contractors needing to demonstrate maturity levels
- Cybersecurity consultants doing E8 assessments

**Business model:** Open-source core scanner (MIT license) → Commercial dashboard, reporting, and managed compliance SaaS on top.

---

## 2. The Essential Eight Controls (What We Scan)

Each control has 4 maturity levels (ML0–ML3). MVP targets ML1 assessment with a roadmap to ML2/ML3.

### Control 1: Application Control
**What it checks:** Only approved/trusted applications can execute.
**Technical approach (MVP - ML1):**
- Query Windows AppLocker / WDAC (Windows Defender Application Control) policies via PowerShell
- Check if application control is enforced on workstations (not just audit mode)
- Enumerate any bypass paths (e.g., user-writable directories in allowed paths)
- Verify Microsoft's recommended block rules are applied

**PowerShell checks:**
```powershell
# Check AppLocker policy status
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections
# Check WDAC policy
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# Check if AppLocker service is running
Get-Service AppIDSvc | Select-Object Status, StartType
```

### Control 2: Patch Applications
**What it checks:** Internet-facing applications patched within 2 weeks; known exploited vulnerabilities patched within 48 hours.
**Technical approach (MVP - ML1):**
- Enumerate installed applications and versions via registry/WMI
- Cross-reference against known vulnerability databases (CVE/NVD via API)
- Check patch age against ML1 thresholds (1 month for non-critical, 48h for exploited)
- Flag end-of-life / unsupported applications
- Focus on high-risk apps: browsers, Office, PDF readers, Java, .NET

**PowerShell checks:**
```powershell
# Enumerate installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
  Select-Object DisplayName, DisplayVersion, InstallDate
# Check specific browser versions
(Get-Item "C:\Program Files\Google\Chrome\Application\chrome.exe").VersionInfo.ProductVersion
# Check Windows Update history
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
```

### Control 3: Configure Microsoft Office Macro Settings
**What it checks:** Macros disabled for users who don't need them; only trusted/signed macros for those who do.
**Technical approach (MVP - ML1):**
- Read Group Policy settings for Office macro configuration
- Check registry keys for macro trust settings across Office apps
- Verify macro notification/blocking mode per application
- Check for macro antivirus scanning configuration

**Registry/PowerShell checks:**
```powershell
# Check Word macro settings (VBAWarnings: 1=enable all, 2=notify, 3=signed only, 4=disable all)
Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security" -Name VBAWarnings -ErrorAction SilentlyContinue
# Check Excel macro settings
Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Excel\Security" -Name VBAWarnings -ErrorAction SilentlyContinue
# Check if macros are blocked from internet
Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\16.0\Word\Security" -Name blockcontentexecutionfrominternet -ErrorAction SilentlyContinue
```

### Control 4: User Application Hardening
**What it checks:** Web browsers, Office, PDF readers hardened (no Flash, no Java in browser, no ads, OLE packages blocked).
**Technical approach (MVP - ML1):**
- Check browser security settings (Chrome/Edge policies via registry)
- Verify Flash/Java/ActiveX are disabled
- Check if web advertisements are blocked (browser extension or DNS-level)
- Verify PowerShell is configured for Constrained Language Mode
- Check .NET Framework hardening

**PowerShell checks:**
```powershell
# Check if Internet Explorer/Edge ActiveX is disabled
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
# Check PowerShell language mode
$ExecutionContext.SessionState.LanguageMode
# Check PowerShell logging
Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
# Check if .NET is hardened
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
```

### Control 5: Restrict Administrative Privileges
**What it checks:** Admin accounts are limited, not used for email/web, and regularly reviewed.
**Technical approach (MVP - ML1):**
- Enumerate local admin group members
- Enumerate domain admin / privileged group members (if AD joined)
- Check for admin accounts with email/internet access
- Detect service accounts with excessive privileges
- Check admin account usage patterns (last logon times)

**PowerShell checks:**
```powershell
# List local admins
Get-LocalGroupMember -Group "Administrators"
# Check privileged AD groups
Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name, SamAccountName
Get-ADGroupMember -Identity "Enterprise Admins" | Select-Object Name, SamAccountName
# Check for accounts that haven't been used
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 | Where-Object {$_.Enabled}
```

### Control 6: Patch Operating Systems
**What it checks:** OS patches applied within timeframes; unsupported OS versions removed.
**Technical approach (MVP - ML1):**
- Check OS version and build number against current release
- Verify Windows Update is configured and recent
- Check WSUS/SCCM/Intune patch compliance status
- Flag end-of-life OS versions (Windows 10 builds, Server 2012, etc.)
- Check patch age against ML1 thresholds

**PowerShell checks:**
```powershell
# Get OS version
[System.Environment]::OSVersion.Version
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
# Check last update
(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
# Check Windows Update service
Get-Service wuauserv | Select-Object Status, StartType
# Check if auto-update is enabled
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
```

### Control 7: Multi-Factor Authentication (MFA)
**What it checks:** MFA on internet-facing services, privileged accounts, and (at higher ML) all users.
**Technical approach (MVP - ML1):**
- Query Azure AD / Entra ID for MFA registration status (via Microsoft Graph API)
- Check conditional access policies for MFA requirements
- Verify MFA on VPN, RDP, and remote access services
- Flag accounts without MFA registered
- Check MFA method strength (SMS vs authenticator app vs FIDO2)

**Approach:**
```
# Via Microsoft Graph API (requires app registration with appropriate permissions)
GET https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails
# Check conditional access policies
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
```

### Control 8: Regular Backups
**What it checks:** Important data and settings are backed up, tested, and protected.
**Technical approach (MVP - ML1):**
- Check Windows Backup / Volume Shadow Copy configuration
- Verify backup schedule exists and recent backup succeeded
- Check if backups are stored offline or in a separate location
- Verify backup access controls (not accessible by standard user accounts)
- Check for ransomware-resilient backup configurations

**PowerShell checks:**
```powershell
# Check Volume Shadow Copy
Get-Service VSS | Select-Object Status
vssadmin list shadows
# Check Windows Server Backup (if available)
Get-WBSummary -ErrorAction SilentlyContinue
# Check backup schedule
Get-WBPolicy -ErrorAction SilentlyContinue
```

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────┐
│                    E8Mate CLI                        │
│                  (Python / Go)                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐      │
│  │ Collector  │  │ Collector  │  │ Collector  │ ... │
│  │ AppControl │  │ Patching   │  │ MFA        │      │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘      │
│        │              │              │              │
│  ┌─────▼──────────────▼──────────────▼─────┐       │
│  │           Evidence Engine                │       │
│  │   (raw data → normalized findings)       │       │
│  └─────────────────┬───────────────────────┘       │
│                    │                                │
│  ┌─────────────────▼───────────────────────┐       │
│  │          Maturity Scorer                 │       │
│  │  (findings → ML0/ML1/ML2/ML3 per ctrl)  │       │
│  └─────────────────┬───────────────────────┘       │
│                    │                                │
│  ┌─────────────────▼───────────────────────┐       │
│  │         Report Generator                 │       │
│  │  (JSON / HTML / PDF / CSV)               │       │
│  └─────────────────────────────────────────┘       │
│                                                     │
└─────────────────────────────────────────────────────┘
         │                           │
    ┌────▼────┐               ┌─────▼──────┐
    │ Local   │               │ Remote     │
    │ Scan    │               │ Scan       │
    │ (agent) │               │ (WinRM /   │
    │         │               │  SSH / API) │
    └─────────┘               └────────────┘
```

### Technology Choice: Python

**Why Python over Go for MVP:**
- Faster to prototype (your strength is in web dev, Python is approachable)
- Rich ecosystem: `pywinrm` for remote Windows, `requests` for API calls, `jinja2` for reports
- Most cybersecurity tools are Python (Nuclei templates aside)
- Can always rewrite hot paths in Go later if performance matters

**Key dependencies:**
```
pywinrm          # Remote Windows management
python-nmap      # Network scanning integration
requests         # API calls (Graph API, NVD)
jinja2           # HTML report templating
pyyaml           # Configuration files
rich             # Beautiful CLI output
typer            # CLI framework
```

---

## 4. Project Structure

```
e8mate/
├── README.md
├── LICENSE                    # MIT
├── pyproject.toml
├── e8mate/
│   ├── __init__.py
│   ├── cli.py                 # CLI entry point (typer)
│   ├── config.py              # Configuration management
│   ├── scanner.py             # Main orchestrator
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py            # Abstract collector class
│   │   ├── app_control.py     # Control 1: Application Control
│   │   ├── patch_apps.py      # Control 2: Patch Applications
│   │   ├── macro_settings.py  # Control 3: Office Macros
│   │   ├── app_hardening.py   # Control 4: User App Hardening
│   │   ├── admin_privs.py     # Control 5: Admin Privileges
│   │   ├── patch_os.py        # Control 6: Patch OS
│   │   ├── mfa.py             # Control 7: MFA
│   │   └── backups.py         # Control 8: Backups
│   ├── evidence/
│   │   ├── __init__.py
│   │   ├── engine.py          # Evidence normalization
│   │   └── models.py          # Data models (findings, scores)
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── maturity.py        # ML0-ML3 scoring logic
│   │   └── rules.py           # ASD maturity model rules (YAML)
│   ├── reporters/
│   │   ├── __init__.py
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py
│   │   ├── csv_reporter.py
│   │   └── templates/
│   │       └── report.html.j2
│   ├── transports/
│   │   ├── __init__.py
│   │   ├── local.py           # Local PowerShell execution
│   │   ├── winrm.py           # Remote via WinRM
│   │   └── graph_api.py       # Microsoft Graph API (for MFA/cloud)
│   └── utils/
│       ├── __init__.py
│       ├── nvd.py             # NVD/CVE lookup
│       └── powershell.py      # PS script builder/executor
├── rules/
│   ├── ml1.yaml               # Maturity Level 1 rules
│   ├── ml2.yaml               # Maturity Level 2 rules
│   └── ml3.yaml               # Maturity Level 3 rules
├── nuclei-templates/
│   ├── e8-app-control/
│   ├── e8-patch-apps/
│   ├── e8-macro-settings/
│   ├── e8-app-hardening/
│   ├── e8-admin-privs/
│   ├── e8-patch-os/
│   ├── e8-mfa/
│   └── e8-backups/
├── tests/
│   ├── test_collectors/
│   ├── test_scoring/
│   └── test_reporters/
├── docs/
│   ├── getting-started.md
│   ├── controls-reference.md
│   └── contributing.md
└── examples/
    ├── sample-config.yaml
    └── sample-report.html
```

---

## 5. CLI Interface Design

```bash
# Full scan against local machine
e8mate scan --local

# Scan remote host via WinRM
e8mate scan --target 192.168.1.100 --user admin --transport winrm

# Scan specific controls only
e8mate scan --local --controls patch-apps,mfa,admin-privs

# Target specific maturity level
e8mate scan --local --maturity-level 2

# Output formats
e8mate scan --local --output report.html --format html
e8mate scan --local --output report.json --format json

# Scan M365/Entra ID for MFA compliance (cloud check)
e8mate scan --cloud --tenant-id <TENANT> --client-id <APP_ID>

# Generate evidence package for auditors
e8mate evidence --local --output evidence-pack/

# Show current score summary
e8mate score --from-report last-scan.json

# Compare two scans (track progress)
e8mate diff scan-jan.json scan-mar.json
```

---

## 6. Scoring Model

Each control is scored independently across the maturity levels.

```yaml
# rules/ml1.yaml (example excerpt)
application_control:
  maturity_level: 1
  controls:
    - id: AC-ML1-001
      description: "Application control is implemented on workstations"
      check: "applocker_or_wdac_enforced"
      weight: critical
      evidence_type: policy_export

    - id: AC-ML1-002
      description: "Application control restricts execution to approved set"
      check: "applocker_default_deny"
      weight: critical
      evidence_type: rule_listing

    - id: AC-ML1-003
      description: "Microsoft recommended block rules are implemented"
      check: "ms_block_rules_applied"
      weight: important
      evidence_type: rule_comparison

    - id: AC-ML1-004
      description: "Application control is applied to user profiles and temp folders"
      check: "user_writable_paths_blocked"
      weight: important
      evidence_type: path_audit

scoring:
  # Per ASD: ALL controls in a strategy must be effective to claim that ML
  method: "all_must_pass"
  outcomes:
    - effective          # Meets the control objective
    - alternate_control  # Meets objective via different mechanism
    - ineffective        # Does not meet objective
    - not_implemented    # Control not present
    - not_applicable     # Control doesn't apply to this environment
```

### Overall Maturity Determination

Per ASD's assessment process: an organisation achieves a maturity level **only if ALL eight controls meet that level**. One failure in any control drops the entire system to the lower level.

```
Overall ML = min(ML_appcontrol, ML_patchapps, ML_macros, ML_hardening,
                 ML_adminprivs, ML_patchos, ML_mfa, ML_backups)
```

---

## 7. Report Output (HTML)

The HTML report should include:

1. **Executive Summary** — Overall maturity level, scan date, system info
2. **Maturity Heatmap** — 8 controls × 3 levels, color-coded (green/amber/red)
3. **Per-Control Detail** — Each control with:
   - Current maturity level achieved
   - Individual check results with evidence
   - Specific remediation steps to reach next ML
   - Links to relevant ASD guidance
4. **Remediation Roadmap** — Prioritised list of actions to reach target ML
5. **Evidence Appendix** — Raw data supporting each finding (for auditors)

---

## 8. Nuclei Templates (Companion Project)

Alongside the main scanner, create Nuclei templates for network-accessible Essential Eight checks. These get submitted upstream to ProjectDiscovery's template repository for visibility.

**What Nuclei can check (network-side):**
- Exposed RDP without network-level authentication
- Missing HTTP security headers (HSTS, CSP, X-Frame-Options)
- TLS/SSL misconfigurations on internet-facing services
- Outdated web server versions (IIS, Apache)
- Microsoft Exchange version detection (patch status)
- OWA/ECP exposed without MFA
- SMBv1 enabled (should be disabled)
- NTLM authentication exposed externally
- PowerShell remoting exposed to internet
- Admin portals (M365 admin, Azure portal) accessible without conditional access

**Template structure:**
```yaml
# nuclei-templates/e8-patch-apps/exchange-version-check.yaml
id: e8-exchange-version

info:
  name: Essential Eight - Exchange Server Version Check
  author: e8mate
  severity: high
  description: Checks Exchange Server version against known patched versions
  tags: essential-eight,e8,patch-applications,australia,compliance
  reference:
    - https://www.cyber.gov.au/acsc/view-all-content/publications/essential-eight-maturity-model

http:
  - method: GET
    path:
      - "{{BaseURL}}/owa/"
    matchers:
      - type: regex
        regex:
          - "X-OWA-Version: ([0-9.]+)"
    extractors:
      - type: regex
        regex:
          - "X-OWA-Version: ([0-9.]+)"
        group: 1
```

---

## 9. MVP Scope (8-Week Sprint)

### Weeks 1-2: Foundation
- [ ] Project scaffolding (pyproject.toml, CLI, config)
- [ ] Transport layer — local PowerShell execution wrapper
- [ ] Base collector class with evidence model
- [ ] First collector: **Patch OS** (easiest to validate — just version checks)
- [ ] JSON reporter (minimum viable output)

### Weeks 3-4: Core Controls
- [ ] Collector: **Patch Applications** (registry enumeration + NVD lookup)
- [ ] Collector: **Admin Privileges** (local/AD group enumeration)
- [ ] Collector: **Office Macro Settings** (registry reads)
- [ ] Scoring engine with ML1 rules
- [ ] HTML report template (Jinja2)

### Weeks 5-6: Advanced Controls + Cloud
- [ ] Collector: **Application Control** (AppLocker/WDAC policy check)
- [ ] Collector: **User App Hardening** (browser/PowerShell settings)
- [ ] Collector: **MFA** (Microsoft Graph API integration)
- [ ] Collector: **Backups** (VSS/Windows Backup check)
- [ ] WinRM transport for remote scanning

### Weeks 7-8: Polish + Launch
- [ ] HTML report design (professional, audit-ready)
- [ ] CLI UX polish (progress bars, colored output)
- [ ] 10 Nuclei templates for network-side E8 checks
- [ ] Documentation (README, getting-started, contributing guide)
- [ ] GitHub repo setup (CI/CD, issue templates, code of conduct)
- [ ] First blog post: "Why I Built an Open Source Essential Eight Scanner"
- [ ] Submit Nuclei templates PR to ProjectDiscovery

---

## 10. Post-MVP Roadmap

### Phase 2: Maturity Level 2 + 3 (Months 3-4)
- ML2 and ML3 rule definitions
- Enhanced checks (e.g., phishing-resistant MFA for ML2)
- Scheduled scanning and drift detection
- Integration with Intune/SCCM for patch data

### Phase 3: SaaS Dashboard (Months 4-6)
- Multi-tenant web dashboard (PHP/MySQL — your stack)
- Historical scan comparison and trend tracking
- Client management for MSPs
- PDF report generation (branded for consultancies)
- Automated remediation playbooks

### Phase 4: Singapore Cyber Essentials (Month 6+)
- Map CSA Cyber Essentials (SS 712:2025) controls
- Dual-framework reports (E8 + Cyber Essentials in one scan)
- Singapore-specific checks (PDPA data handling, etc.)

### Phase 5: Monetisation
- **Open core**: Scanner stays MIT, dashboard is commercial
- **MSP licensing**: Per-tenant pricing for managed service providers
- **Audit packages**: Evidence packs formatted for specific certification bodies
- **Training**: Essential Eight assessment course (mirrors ASD's official course)

---

## 11. Competitive Positioning

| Feature | E8Mate (You) | Huntsman E8 Auditor | ConnectSecure | Excel Tracker |
|---------|-------------|-------------------|---------------|---------------|
| Open source | ✅ MIT | ❌ Commercial | ❌ Commercial | ✅ |
| Automated scanning | ✅ | ✅ | ✅ | ❌ Manual |
| Agentless | ✅ | ✅ | ❌ Agent-based | N/A |
| Cloud (M365/Entra) | ✅ | Partial | ✅ | ❌ |
| SME-friendly price | ✅ Free core | $$$ | $$$ | ✅ Free |
| Evidence packages | ✅ | ✅ | Partial | ❌ |
| Nuclei integration | ✅ | ❌ | ❌ | ❌ |
| SG Cyber Essentials | Roadmap | ❌ | ❌ | ❌ |
| Self-hostable | ✅ | ❌ | ❌ | N/A |

**Your moat:**
1. Only open-source E8 scanner → community contributions, trust
2. Nuclei templates → visibility in the broader security community
3. Dual AU/SG framework support → unique market position
4. Self-hostable → data sovereignty for government clients

---

## 12. Go-to-Market: First 90 Days

### Content (Builds Authority)
- Week 1: "Why Australia Needs an Open Source Essential Eight Scanner" (blog)
- Week 2: GitHub launch with README, demo scan, sample report
- Week 3: Submit Nuclei templates PR to ProjectDiscovery
- Week 4: Post on r/AusFinance, r/sysadmin, r/netsec, LinkedIn
- Month 2: Talk at BSides Singapore or DC65 (SG DefCon group)
- Month 2: Reach out to Australian MSP communities (MSP subreddit, CRN AU)
- Month 3: "Essential Eight Compliance for SMEs" whitepaper (lead gen)

### Partnerships
- Australian MSPs: Offer free onboarding to first 10 MSPs who deploy E8Mate
- CSA ecosystem: Position for future CISOaaS tooling integration
- ProjectDiscovery: Become recognized E8 template maintainer

### Community
- GitHub Discussions for support
- Discord server for users and contributors
- Monthly "E8 Compliance Office Hours" (virtual meetup)

---

## 13. Legal & Licensing Notes

- **Scanner**: MIT License (maximum adoption)
- **Dashboard/SaaS**: Proprietary (commercial)
- **Nuclei templates**: MIT (required for upstream submission)
- **Important**: E8Mate assesses compliance but does NOT certify. Make this clear in all materials. Only ASD-approved assessors can formally certify E8 maturity.
- **Trademark**: "Essential Eight" is ASD's term — use it descriptively, not as a trademark. Name the project E8Mate (or similar) to build its own brand.

---

## 14. Name Alternatives

| Name | Pros | Cons |
|------|------|------|
| **E8Mate** | Aussie-friendly, memorable, clear purpose | Might seem too casual |
| **OctaGuard** | Professional, "octa" = 8 | Less immediately clear |
| **EightShield** | Descriptive | Generic |
| **Comply8** | Clear purpose | Sounds like a SaaS product |
| **e8scan** | Technical, clean | Too generic |
| **MaturityMate** | Broader scope | Doesn't clearly tie to E8 |

**Recommendation: E8Mate** — it's memorable, clearly Australian, implies partnership ("mate"), and the E8 prefix immediately communicates Essential Eight to the target market.
