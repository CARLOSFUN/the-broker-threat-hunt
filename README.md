# 🛡️ The Broker

## Enterprise Multi-Stage Intrusion – Credential Theft, Lateral Movement & Data Staging Investigation

<div align="center">

![Threat Hunting](https://img.shields.io/badge/Type-Threat%20Hunting-red?style=for-the-badge)
![Microsoft Defender](https://img.shields.io/badge/Platform-Microsoft%20Defender-blue?style=for-the-badge)
![KQL](https://img.shields.io/badge/Language-KQL-orange?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Complete-success?style=for-the-badge)

**A comprehensive SOC-style threat hunt investigating a full enterprise compromise — from malicious document execution to credential theft, lateral movement, persistence, and payroll data staging.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [What's Inside](#-whats-inside)
- [Investigation Summary](#-investigation-summary)
- [Key Findings](#-key-findings)
- [MITRE ATT&CK Coverage](#-mitre-attck-coverage)
- [Detection Rules](#-detection-rules)
- [Repository Structure](#-repository-structure)
- [Skills Demonstrated](#-skills-demonstrated)
- [Disclaimer](#-disclaimer)

---

## 🎯 Overview

**The Broker** documents a full-scope enterprise intrusion investigation conducted using Microsoft Defender for Endpoint Advanced Hunting and Microsoft Sentinel telemetry.

This hunt reconstructs a complete adversary lifecycle including:

- Malicious document execution
- Command & Control communications
- Credential dumping (SAM & SYSTEM)
- Remote tool persistence (AnyDesk)
- Lateral movement via RDP
- Scheduled task persistence
- Sensitive payroll data access
- Anti-forensics and reflective memory loading

### Investigation Scope

| Attribute | Details |
|-----------|----------|
| Hunt Name | The Broker |
| Incident Brief | Ashford Sterling Recruitment |
| Investigation Period | January 15, 2026 |
| Detection Platform | Microsoft Defender for Endpoint |
| Query Language | Kusto Query Language (KQL) |
| Affected Systems | as-pc1, as-pc2, as-srv |
| Persistence Mechanisms | AnyDesk, Scheduled Task, Backdoor Account |
| MITRE ATT&CK Techniques | 15+ techniques across 8 tactics |

---

### What Makes This Investigation Unique?

- ✅ Complete Enterprise Compromise Simulation  
- ✅ Credential Theft & Reflective Loading Detection  
- ✅ Living-Off-the-Land Abuse (certutil.exe)  
- ✅ Multi-Host Lateral Movement Tracking  
- ✅ Production-Grade KQL Hunts  
- ✅ IOC & Timeline Reconstruction  

---

## 📦 What's Inside

### 📄 SOC Threat Hunt Report  
**Location:** `report/The_Broker_Threat_Hunt_Report.md`

A complete multi-stage investigation including:

- 36 documented investigation flags  
- All KQL queries used  
- Evidence screenshots per flag  
- Timeline reconstruction  
- MITRE ATT&CK mapping  
- IOC documentation  
- Defensive recommendations  
- Analyst methodology reflection  

---

### 📸 Evidence Screenshots  
**Location:** `screenshots/`

Screenshots supporting each investigation phase:

- Section 1 – Initial Access  
- Section 2 – Command & Control  
- Section 3 – Credential Access  
- Section 4 – Discovery  
- Section 5 – Remote Tool Persistence  
- Section 6 – Lateral Movement  
- Section 7 – Scheduled Task Persistence  
- Section 8 – Data Access  
- Section 9 – Anti-Forensics & Memory  

All screenshots are referenced directly inside the main report with contextual analysis.

---

## 🔍 Investigation Summary

The intrusion began with execution of a malicious double-extension file:

Daniel_Richardson_CV.pdf.exe

Execution chain:

explorer.exe
└── Daniel_Richardson_CV.pdf.exe
└── notepad.exe “”

The payload:

- Established C2 communication to `cdn.cloud-endpoint.net`
- Retrieved additional payloads from `sync.cloud-endpoint.net`
- Dumped `SAM` and `SYSTEM` registry hives
- Staged credentials in `C:\Users\Public`
- Installed AnyDesk for persistent remote access
- Attempted lateral movement via `psexec.exe` and `wmic.exe`
- Successfully pivoted using `mstsc.exe`
- Enabled a disabled account using `/active:yes`
- Created scheduled task `MicrosoftEdgeUpdateCheck`
- Renamed payload to `RuntimeBroker.exe`
- Created backdoor account `svc_backup`
- Accessed payroll document `BACS_Payments_Dec2025.ods`
- Archived data into `Shares.7z`
- Cleared Security and System logs
- Loaded SharpChrome reflectively into `notepad.exe`

---

## 🚨 Key Findings

### Compromised Systems

- as-pc1 (Initial infection)
- as-pc2 (Lateral pivot)
- as-srv (Data access & persistence)

### Compromised Accounts

- sophie.turner  
- david.mitchell  
- svc_backup  

### C2 Infrastructure

- cdn.cloud-endpoint.net  
- sync.cloud-endpoint.net  

### High-Impact Artifacts

Sensitive File:

BACS_Payments_Dec2025.ods

Archive:

Shares.7z
SHA256: 6886c0a2e59792e69df94d2cf6ae62c2364fda50a23ab44317548895020ab048

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|------------|----|
| Initial Access | User Execution | T1204 |
| Execution | Command & Scripting Interpreter | T1059 |
| Credential Access | OS Credential Dumping | T1003.002 |
| Discovery | Account Discovery | T1033 |
| Discovery | Network Share Discovery | T1135 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Create Account | T1136 |
| Defense Evasion | Clear Windows Event Logs | T1070.001 |
| Defense Evasion | Reflective Code Loading | T1620 |
| Lateral Movement | Remote Services (RDP) | T1021.001 |
| Collection | Data from Local System | T1005 |
| Collection | Archive Collected Data | T1560 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |

---

## 🔎 Detection Rules

This investigation produced Defender-ready detection patterns:

1. Double-extension executable detection (`*.pdf.exe`)
2. Registry hive dumping via `reg save`
3. certutil.exe external downloads
4. AnyDesk installation monitoring
5. Scheduled task creation via `schtasks.exe`
6. RDP pivot correlation
7. Suspicious archive creation (`.7z`)
8. Event log clearing detection
9. ClrUnbackedModuleLoaded monitoring

All KQL queries are stored in the `/queries/` directory.


---

## 💼 Skills Demonstrated

### Technical Skills

- Microsoft Defender Advanced Hunting  
- Kusto Query Language (KQL)  
- Endpoint Detection & Response Analysis  
- Credential Dump Detection  
- Lateral Movement Correlation  
- Reflective Loading Detection  
- Persistence Mechanism Analysis  
- Enterprise Timeline Reconstruction  

### Analytical Capabilities

- Hypothesis-driven threat hunting  
- Multi-table telemetry correlation  
- IOC identification & documentation  
- MITRE ATT&CK mapping  
- Business impact assessment  

### Communication

- SOC-grade technical documentation  
- Structured investigation reporting  
- Executive-level summarization  
- Detection engineering recommendations  

---

## ⚠️ Disclaimer

All artifacts in this repository originate from a controlled lab / simulated Cyber Range environment.

- No real-world organization data is included.
- All hostnames, domains, accounts, and file paths are fictional.
- This project is intended strictly for educational and portfolio demonstration purposes.

---

## 🛡️ Defense Through Detection
