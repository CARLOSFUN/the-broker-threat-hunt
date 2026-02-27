# 🛡️ The Broker

## Enterprise Multi-Stage Intrusion – Credential Theft, Lateral Movement & Financial Data Staging Investigation

<div align="center">

![Threat Hunting](https://img.shields.io/badge/Type-Threat%20Hunting-red?style=for-the-badge)
![Microsoft Defender](https://img.shields.io/badge/Platform-Microsoft%20Defender-blue?style=for-the-badge)
![KQL](https://img.shields.io/badge/Language-KQL-orange?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-success?style=for-the-badge)
![Flags](https://img.shields.io/badge/Flags-40%20Documented-purple?style=for-the-badge)

**A comprehensive SOC-grade threat hunt investigating a full enterprise compromise — from malicious CV execution to credential theft, lateral movement, multi-layer persistence, and payroll data staging across 40 documented investigation flags.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What's Inside](#-whats-inside)
- [Investigation Summary](#-investigation-summary)
- [Attack Chain](#-attack-chain)
- [Key Findings](#-key-findings)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Detection Rules](#-detection-rules)
- [Repository Structure](#-repository-structure)
- [Skills Demonstrated](#-skills-demonstrated)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

**The Broker** documents a full-scope enterprise intrusion investigation conducted using **Microsoft Defender for Endpoint Advanced Hunting** (KQL).

This hunt reconstructs a complete adversary lifecycle across **9 attack phases** and **40 individual investigation flags**, covering:

- Malicious double-extension CV execution
- Command & Control establishment
- Registry hive credential dumping (SAM & SYSTEM)
- Living-off-the-land binary abuse (certutil, reg, mstsc, wmic)
- Enterprise-wide AnyDesk remote access persistence
- Multi-hop RDP lateral movement
- Disabled account re-activation
- Scheduled task and backdoor account persistence
- Sensitive payroll financial data access & editing
- Pre-exfiltration archive staging
- Windows event log clearing (anti-forensics)
- Reflective in-memory credential theft (SharpChrome)

### Investigation Scope

| Attribute | Details |
|-----------|---------|
| Hunt Name | The Broker |
| Organisation | Ashford Sterling Recruitment |
| Investigation Period | January 15–20, 2026 |
| Detection Platform | Microsoft Defender for Endpoint |
| Query Language | Kusto Query Language (KQL) |
| Primary Host | as-pc1 |
| Additional Hosts | as-pc2, as-srv |
| Total Flags Documented | 40 across 9 sections |
| Persistence Mechanisms | AnyDesk, Scheduled Task, Backdoor Account (svc_backup) |
| MITRE ATT&CK Techniques | 20+ techniques across 9 tactics |
| Classification | TLP:AMBER |

---

### What Makes This Investigation Unique?

- ✅ 40 Individual Flags — Every investigation question documented
- ✅ Complete Enterprise Compromise Lifecycle (Initial Access → Exfil Staging)
- ✅ Credential Theft via SAM/SYSTEM Hive Dump + Reflective SharpChrome
- ✅ Living-Off-the-Land Binary Abuse (certutil, reg, mstsc, wmic, schtasks)
- ✅ Multi-Hop Lateral Movement Reconstruction (as-pc1 → as-pc2 → as-srv)
- ✅ Financial Fraud Risk Identified via LibreOffice Lock File Artifact
- ✅ Production-Grade KQL Queries with Noise Exclusions
- ✅ Full IOC Table with 28 Indicators
- ✅ MITRE ATT&CK Mapped per Flag

---

## 📦 What's Inside

### 📄 SOC Threat Hunt Report
**Location:** `report/TheBroker_ThreatHuntReport_v3.md`

A complete multi-stage investigation report including:

- 40 documented investigation flags across 9 sections
- Individual KQL query per flag with field projections and noise filtering
- Screenshot reference placeholder per flag
- Per-flag analyst assessment and kill chain context
- Full attack chain timeline reconstruction
- Complete MITRE ATT&CK mapping (per flag)
- 28-entry IOC table
- Recommendations table (immediate action + long-term fix per flag)
- TLP:AMBER classified executive summary and conclusion

---

### 📸 Evidence Screenshots
**Location:** `screenshots/`

Screenshots supporting each investigation phase, organised by section:

```
screenshots/
├── section1_initial_access/
├── section2_c2/
├── section3_credential_access/
├── section4_discovery/
├── section5_persistence_remote_tool/
├── section6_lateral_movement/
├── section7_persistence_scheduled_task/
├── section8_data_access/
└── section9_anti_forensics_memory/
```

Each screenshot is referenced directly inside the main report under its corresponding flag (F01–F40).

---

## 🔍 Investigation Summary

The intrusion began with execution of a malicious double-extension file on workstation **as-pc1**:

```
Daniel_Richardson_CV.pdf.exe
SHA256: 48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5
```

**Execution chain:**
```
explorer.exe
└── Daniel_Richardson_CV.pdf.exe
    └── notepad.exe ""   ← injection staging host
```

**Full attack progression:**

| Phase | Activity |
|-------|---------|
| Initial Access | User executed double-extension CV payload via explorer.exe |
| C2 | Payload connected to cdn.cloud-endpoint.net; staged tools from sync.cloud-endpoint.net |
| Credential Access | reg.exe dumped SAM + SYSTEM hives to C:\Users\Public as sophie.turner |
| Discovery | whoami.exe, net.exe view, administrators group enumeration |
| Persistence (RAT) | AnyDesk deployed via certutil.exe across as-pc1, as-pc2, as-srv; password: intrud3r! |
| Lateral Movement | psexec/wmic failed; mstsc.exe succeeded: as-pc1 → as-pc2 → as-srv |
| Account Abuse | david.mitchell re-activated (/active:yes) and used for RDP auth |
| Persistence (Task) | MicrosoftEdgeUpdateCheck scheduled task + RuntimeBroker.exe (same hash as payload) |
| Backdoor Account | svc_backup local account created on as-pc2 |
| Data Access | BACS_Payments_Dec2025.ods accessed AND edited (lock file confirmed) from as-pc2 |
| Staging | Shares.7z archive created (SHA256: 6886c0a2...) |
| Anti-Forensics | Security + System event logs cleared via wevtutil |
| Memory | SharpChrome reflectively loaded into notepad.exe via ClrUnbackedModuleLoaded |

---

## ⛓️ Attack Chain

```
[Section 1] INITIAL ACCESS
     User executes Daniel_Richardson_CV.pdf.exe via explorer.exe
     └─► notepad.exe "" spawned (process masquerade / injection vessel)

[Section 2] COMMAND & CONTROL
     └─► C2 beacon → cdn.cloud-endpoint.net
     └─► Tool staging → sync.cloud-endpoint.net

[Section 3] CREDENTIAL ACCESS
     └─► reg save SAM + SYSTEM → C:\Users\Public (as sophie.turner)

[Section 4] DISCOVERY
     └─► whoami.exe → net.exe view → administrators group enum

[Section 5] PERSISTENCE — REMOTE TOOL
     └─► certutil.exe downloads AnyDesk (LOLBin abuse)
     └─► system.conf configured — unattended password: intrud3r!
     └─► AnyDesk deployed: as-pc1, as-pc2, as-srv

[Section 6] LATERAL MOVEMENT
     └─► psexec.exe / wmic.exe FAIL against as-pc2
     └─► mstsc.exe SUCCESS: as-pc1 → as-pc2 → as-srv
     └─► david.mitchell re-activated (/active:yes) and authenticated

[Section 7] PERSISTENCE — SCHEDULED TASK
     └─► MicrosoftEdgeUpdateCheck task created on as-pc2
     └─► RuntimeBroker.exe deployed (hash matches initial payload)
     └─► svc_backup backdoor account created

[Section 8] DATA ACCESS
     └─► BACS_Payments_Dec2025.ods accessed + EDITED on as-srv
     └─► .~lock. artifact confirms active editing (potential fraud)
     └─► Shares.7z archive created for staging

[Section 9] ANTI-FORENSICS & MEMORY
     └─► Security + System event logs cleared
     └─► SharpChrome reflectively loaded into notepad.exe
     └─► ClrUnbackedModuleLoaded detected by MDE
```

---

## 🚨 Key Findings

### Compromised Systems

| Host | Role | Flags |
|------|------|-------|
| as-pc1 | Initial infection host | F01–F11, F38–F40 |
| as-pc2 | Lateral movement waypoint + persistence host | F21–F31 |
| as-srv | File server — financial data target | F32–F36 |

### Compromised Accounts

| Account | How Compromised | Flags |
|---------|----------------|-------|
| sophie.turner | Executed payload; SAM dump context | F03, F11, F18 |
| david.mitchell | Re-activated via /active:yes; used for RDP | F25, F26, F27 |
| svc_backup | Created by attacker as backdoor | F31 |

### C2 & Staging Infrastructure

| Domain | Purpose | Flag |
|--------|---------|------|
| cdn.cloud-endpoint.net | Primary C2 | F06, F07 |
| sync.cloud-endpoint.net | Payload staging | F08 |

### Critical Artifacts

| Artifact | Significance | Flag |
|----------|-------------|------|
| `Daniel_Richardson_CV.pdf.exe` | Initial payload | F01 |
| `48b97fd9...` | Payload hash — reused as RuntimeBroker.exe | F02, F30 |
| `notepad.exe ""` | Injection vessel used throughout chain | F04, F05, F40 |
| `BACS_Payments_Dec2025.ods` | Targeted payroll/financial document | F32 |
| `.~lock.BACS_Payments_Dec2025.ods#` | Proves document was edited, not just viewed | F33 |
| `Shares.7z` | Pre-exfiltration data archive | F35 |
| `6886c0a2...` | Archive SHA256 hash | F36 |
| `ClrUnbackedModuleLoaded` | MDE signal for in-memory SharpChrome | F38, F39, F40 |
| `intrud3r!` | AnyDesk unattended access password | F19 |

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | ID | Flags |
|--------|----------|----|-------|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | F01, F02 |
| Execution | User Execution: Malicious File | T1204.002 | F03 |
| Defense Evasion | Process Injection | T1055 | F04, F40 |
| Defense Evasion | Masquerading | T1036 | F05 |
| Command & Control | Application Layer Protocol: Web Protocols | T1071.001 | F06, F07 |
| Command & Control | Ingress Tool Transfer | T1105 | F08, F17 |
| Credential Access | OS Credential Dumping: SAM | T1003.002 | F09, F10, F11 |
| Discovery | System Owner/User Discovery | T1033 | F12 |
| Discovery | Network Share Discovery | T1135 | F13 |
| Discovery | Account Discovery: Local Account | T1087.001 | F14 |
| Persistence | External Remote Services | T1133 | F15–F20 |
| Lateral Movement | Remote Services (RDP) | T1021.001 | F21–F24 |
| Lateral Movement / Persistence | Valid Accounts: Local Accounts | T1078.003 | F25–F27 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 | F28, F30 |
| Defense Evasion | Masquerading: Rename System Utilities | T1036.003 | F29 |
| Persistence | Create Account: Local Account | T1136.001 | F31 |
| Collection | Data from Local System | T1005 | F32, F33 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | F35, F36 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | F37 |
| Defense Evasion | Reflective Code Loading | T1620 | F38 |
| Credential Access | Credentials from Web Browsers | T1555.003 | F39 |

---

## 🔎 Detection Rules

This investigation produced the following **Microsoft Defender-ready detection patterns**, all with production KQL:

| # | Detection | Query Table | Flag |
|---|-----------|------------|------|
| 1 | Double-extension executable detection (*.pdf.exe) | DeviceProcessEvents | F01 |
| 2 | Payload hash match across all hosts | DeviceProcessEvents | F02, F30 |
| 3 | notepad.exe with empty quoted arguments | DeviceProcessEvents | F05 |
| 4 | Payload binary initiating network connections | DeviceNetworkEvents | F07 |
| 5 | certutil.exe external URL download (LOLBin) | DeviceProcessEvents | F17 |
| 6 | reg.exe saving SAM/SYSTEM hives | DeviceProcessEvents | F09 |
| 7 | Hive files dropped in C:\Users\Public | DeviceFileEvents | F10 |
| 8 | AnyDesk installation outside approved baseline | DeviceFileEvents | F15, F16 |
| 9 | AnyDesk config file modification | DeviceFileEvents | F18 |
| 10 | net user /active:yes account re-activation | DeviceProcessEvents | F26 |
| 11 | psexec.exe / wmic.exe remote execution attempts | DeviceProcessEvents | F21 |
| 12 | Anomalous RemoteInteractive logon events | DeviceLogonEvents | F23, F24 |
| 13 | schtasks /create from non-admin processes | DeviceProcessEvents | F28 |
| 14 | Known Windows process names in non-standard paths | DeviceFileEvents | F29 |
| 15 | net user /add (unexpected account creation) | DeviceProcessEvents | F31 |
| 16 | .~lock. file creation near sensitive documents | DeviceFileEvents | F33 |
| 17 | Archive creation following sensitive file access | DeviceFileEvents | F35 |
| 18 | wevtutil cl — event log clearing | DeviceProcessEvents | F37 |
| 19 | ClrUnbackedModuleLoaded in non-CLR host processes | DeviceEvents | F38, F39, F40 |

---

## 📁 Repository Structure

```
The-Broker/
│
├── README.md                          ← You are here
│
├── report/
│   └── TheBroker_ThreatHuntReport_v3.md   ← Full 40-flag SOC report
│
├── screenshots/
│   ├── section1_initial_access/
│   │   ├── F01_malicious_cv_execution.png
│   │   ├── F02_payload_hash.png
│   │   ├── F03_explorer_parent.png
│   │   ├── F04_notepad_child.png
│   │   └── F05_empty_args.png
│   ├── section2_c2/
│   │   ├── F06_c2_domain.png
│   │   ├── F07_c2_process.png
│   │   └── F08_staging_domain.png
│   ├── section3_credential_access/
│   │   ├── F09_hive_dump.png
│   │   ├── F10_staging_path.png
│   │   └── F11_execution_identity.png
│   ├── section4_discovery/
│   │   ├── F12_whoami.png
│   │   ├── F13_net_view.png
│   │   └── F14_admins_enum.png
│   ├── section5_persistence_remote_tool/
│   │   ├── F15_anydesk_deploy.png
│   │   ├── F16_anydesk_hash.png
│   │   ├── F17_certutil_download.png
│   │   ├── F18_config_access.png
│   │   ├── F19_unattended_password.png
│   │   └── F20_deployment_footprint.png
│   ├── section6_lateral_movement/
│   │   ├── F21_failed_tools.png
│   │   ├── F22_target_host.png
│   │   ├── F23_rdp_pivot.png
│   │   ├── F24_movement_path.png
│   │   ├── F25_compromised_account.png
│   │   ├── F26_account_activation.png
│   │   └── F27_activation_context.png
│   ├── section7_persistence_scheduled_task/
│   │   ├── F28_scheduled_task.png
│   │   ├── F29_renamed_binary.png
│   │   ├── F30_hash_match.png
│   │   └── F31_backdoor_account.png
│   ├── section8_data_access/
│   │   ├── F32_bacs_access.png
│   │   ├── F33_lock_file.png
│   │   ├── F34_access_origin.png
│   │   ├── F35_archive_created.png
│   │   └── F36_archive_hash.png
│   └── section9_anti_forensics_memory/
│       ├── F37_log_clearing.png
│       ├── F38_reflective_loading.png
│       ├── F39_sharpchrme.png
│       └── F40_host_process.png
│
└── queries/
    ├── section1_initial_access.kql
    ├── section2_c2.kql
    ├── section3_credential_access.kql
    ├── section4_discovery.kql
    ├── section5_persistence_remote_tool.kql
    ├── section6_lateral_movement.kql
    ├── section7_persistence_scheduled_task.kql
    ├── section8_data_access.kql
    └── section9_anti_forensics_memory.kql
```

---

## 💼 Skills Demonstrated

### Technical Skills

| Skill | Evidence |
|-------|---------|
| Microsoft Defender Advanced Hunting | 40 flags hunted across 5 MDE tables |
| Kusto Query Language (KQL) | 50+ production-grade queries with noise exclusions |
| Endpoint Detection & Response | Full kill chain reconstruction from telemetry |
| Credential Dump Detection | SAM/SYSTEM hive dump + SharpChrome reflective load |
| Lateral Movement Correlation | Multi-hop RDP tracking with logon correlation |
| LOLBin Abuse Detection | certutil, reg, mstsc, wmic, schtasks |
| Reflective Loading Detection | ClrUnbackedModuleLoaded process correlation |
| Persistence Mechanism Analysis | 3 independent persistence layers identified |
| Financial Fraud Risk Identification | LibreOffice lock file artifact analysis |
| Enterprise Timeline Reconstruction | 40-flag sequential attack chain |

### Analytical Capabilities

- Hypothesis-driven threat hunting
- Multi-table telemetry correlation (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceEvents)
- IOC identification and documentation (28 indicators)
- MITRE ATT&CK mapping per individual finding
- Business impact and financial fraud risk assessment
- Anti-forensic resilience (cloud EDR vs local log clearing)

### Communication

- SOC-grade technical documentation (1,700+ line report)
- Per-flag structured investigation with KQL + screenshot + analyst assessment
- Executive-level summarisation (TLP:AMBER classified)
- Detection engineering recommendations (19 detection rules)
- GitHub portfolio presentation

---

## ⚠️ Disclaimer

All artifacts in this repository originate from a **controlled lab / simulated Cyber Range environment**.

- No real-world organisation data is included
- All hostnames, domains, accounts, and file paths are fictional
- Domains listed (cdn.cloud-endpoint.net, sync.cloud-endpoint.net) are **not to be visited, scanned, or submitted to online tools**
- SHA256 hashes are **not to be submitted to VirusTotal or online sandboxes**
- This project is intended strictly for **educational and portfolio demonstration purposes**

---

## 🛡️ Defense Through Detection

*Carlos Funezsanchez | SOC Analyst | TLP:AMBER*
