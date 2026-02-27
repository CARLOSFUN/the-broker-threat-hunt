# 🛡️ The Broker — Threat Hunt

<div align="center">

![Threat Hunting](https://img.shields.io/badge/Type-Threat%20Hunting-red?style=for-the-badge)
![Microsoft Defender](https://img.shields.io/badge/Platform-Microsoft%20Defender-blue?style=for-the-badge)
![KQL](https://img.shields.io/badge/Language-KQL-orange?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-green?style=for-the-badge)
![Flags](https://img.shields.io/badge/Flags-40%20Documented-purple?style=for-the-badge)

**Full enterprise compromise investigated across 40 flags and 9 attack phases from malicious CV execution to in-memory credential theft and payroll data staging.**

</div>

---

## 📄 Read the Full Report

<div align="center">

[![View Full Report](https://img.shields.io/badge/📄%20View%20Full%20Report-Click%20Here-blue?style=for-the-badge)](report/The_Broker_Threat_Hunt_Report.md)

*40 flags · 9 sections · KQL queries · screenshots · MITRE mapping · IOC table · recommendations*

</div>

---

## Overview

**The Broker** is a SOC-grade threat hunt conducted in Microsoft Defender for Endpoint using KQL. It reconstructs a complete adversary lifecycle against a simulated recruitment company, documenting every stage of the attack from initial access through to anti-forensics.

| Field | Detail |
|-------|--------|
| Organisation | Ashford Sterling Recruitment |
| Period | January 15–20, 2026 |
| Platform | Microsoft Defender for Endpoint |
| Hosts Compromised | as-pc1, as-pc2, as-srv |
| Total Flags | 40 across 9 sections |
| Classification | TLP:AMBER |

---

## Attack Chain

```
[1] INITIAL ACCESS       Daniel_Richardson_CV.pdf.exe executed via explorer.exe
                         └─► notepad.exe "" spawned as injection vessel

[2] COMMAND & CONTROL    C2 → cdn.cloud-endpoint.net
                         Staging → sync.cloud-endpoint.net

[3] CREDENTIAL ACCESS    reg.exe dumps SAM + SYSTEM → C:\Users\Public (as sophie.turner)

[4] DISCOVERY            whoami.exe → net view → administrators group enum

[5] PERSISTENCE (RAT)    certutil downloads AnyDesk → deployed on all 3 hosts
                         Unattended password: intrud3r!

[6] LATERAL MOVEMENT     psexec/wmic FAIL → mstsc.exe SUCCESS
                         as-pc1 → as-pc2 → as-srv (david.mitchell re-activated)

[7] PERSISTENCE (TASK)   MicrosoftEdgeUpdateCheck scheduled task + svc_backup account
                         RuntimeBroker.exe = same hash as initial payload

[8] DATA ACCESS          BACS_Payments_Dec2025.ods accessed AND edited on as-srv
                         Shares.7z archive created for staging

[9] ANTI-FORENSICS       Security + System logs cleared via wevtutil
                         SharpChrome reflectively loaded into notepad.exe
```

---

## Key IOCs

| Type | Value |
|------|-------|
| Filename | `Daniel_Richardson_CV.pdf.exe` |
| Payload Hash | `48b97fd91946e81e3e7742b3554585360551551cbf9398e1f34f4bc4eac3a6b5` |
| C2 Domain | `cdn.cloud-endpoint.net` |
| Staging Domain | `sync.cloud-endpoint.net` |
| AnyDesk Password | `intrud3r!` |
| AnyDesk Hash | `f42b635d93720d1624c74121b83794d706d4d064bee027650698025703d20532` |
| Archive | `Shares.7z` — SHA256: `6886c0a2...` |
| Accounts Abused | `sophie.turner`, `david.mitchell`, `svc_backup` |
| MDE Signal | `ClrUnbackedModuleLoaded` (SharpChrome in-memory) |


## What's Inside

```
the-broker-threat-hunt/
├── README.md
├── report/
│   └── The_Broker_Threat_Hunt_Report.md   ← Full 40-flag SOC report
└── screenshots/
    ├── section1_initial_access/            ← F01–F05
    ├── section2_c2/                        ← F06–F08
    ├── section3_credential_access/         ← F09–F11
    ├── section4_discovery/                 ← F12–F14
    ├── section5_persistence_remote_tool/   ← F15–F20
    ├── section6_lateral_movement/          ← F21–F27
    ├── section7_persistence_scheduled_task/← F28–F31
    ├── section8_data_access/               ← F32–F36
    └── section9_anti_forensics_memory/     ← F37–F40
```

The report contains for every flag: a KQL query, evidence screenshot, MITRE ATT&CK mapping, and analyst assessment. Also included: 28-entry IOC table, 19 detection rules, and a full recommendations section.

---

## Skills Demonstrated

- **KQL / MDE Advanced Hunting** — 50+ production queries across 5 data tables
- **Credential Dump Detection** — SAM/SYSTEM hive dump + reflective SharpChrome
- **Lateral Movement Correlation** — Multi-hop RDP tracking with logon telemetry
- **LOLBin Abuse** — certutil, reg, mstsc, wmic, schtasks
- **Persistence Analysis** — 3 independent layers (AnyDesk, scheduled task, backdoor account)
- **Financial Fraud Risk ID** — LibreOffice lock file artifact proving active document editing
- **MITRE ATT&CK Mapping** — 20+ techniques across 9 tactics

---

## ⚠️ Disclaimer

All data originates from a **controlled lab / simulated Cyber Range environment**. No real organisations, credentials, or infrastructure are involved. Do not submit the listed domains or hashes to online tools. For educational and portfolio purposes only.

---

*Carlos Funezsanchez | SOC Analyst | TLP:AMBER*
