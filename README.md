# WinSentinel 🛡️
### Enterprise-Grade Windows Privacy, Telemetry & Bloatware Hardening Suite

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey.svg)](https://microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Production](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

**WinSentinel** is an automated system audit, telemetry de-bloat, and hardware hardening engine designed for system administrators, engineers, and privacy-conscious users. It audits and secures your workstation or server against 10 critical privacy vectors without breaking Windows Update, hardware drivers, or core OS services.

---

## 🚀 Key Features

* **Non-Destructive Audit Engine (`-AuditOnly`):** Performs a comprehensive system health check across 10 security/privacy vectors, calculating an overall Hardening Score (0% – 100%) without modifying system state.
* **Granular Error Handling:** Every registry edit, service state change, scheduled task, and firewall command is enclosed in isolated `try/catch` handlers with fail-safe recovery and execution continuation.
* **Persistent File Logging (`Write-Log`):** Generates timestamped session logs with standard severity levels (`[INFO]`, `[DEBUG]`, `[WARN]`, `[SUCCESS]`, `[ERROR]`) saved automatically to `.\Logs\`. Supports custom paths via `-LogPath`.
* **Automatic Device Companion App Neutralization:** Blocks Windows from querying the Device Metadata Retrieval service (`DMRClient.exe`) to prevent silent manufacturer app pushes (e.g., LG Monitor App, HP Smart, Razer Synapse).
* **Network-Level Firewall Enforcement:** Enforces an outbound block rule on `%SystemRoot%\System32\DMRClient.exe` to permanently sever companion app retrieval at the packet level.
* **Proprietary Audio & Microphone Hook Neutralization:** Disables hidden OEM voice-processing and audio interception services (MSI Sound Tune, Nahimic Audio Engine, intelliGo Audio Service) that monitor microphone streams.
* **OS Telemetry & Inventory De-bloat:** Permanently shuts down `DiagTrack`, `DPS`, `PcaSvc`, and deep storage inventory scanners like `CompatTelRunner.exe` and CEIP `Consolidator`.
* **Consumer Cloud Experience Lockdown:** Sets enterprise Group Policies to block Microsoft from silently pushing games, apps (TikTok, Candy Crush, Spotify), and full-screen SCOOBE setup takeovers.
* **Integrated Safety & Rollback (`-Backup`):** Automatically creates a Windows System Restore Point and exports registry backups to `C:\WinSentinel_Backups\` prior to applying modifications.
* **Headless Deployment Ready (`-Silent`):** Can run non-interactively across Active Directory, Microsoft Intune, SCCM, Ansible, or remote management pipelines.
* **Full Multi-Platform Support:** Dynamically adapts rules for **Windows 11**, **Windows 10**, and **Windows Server (2019/2022/2025)**.

---

## 📋 Vectors Audited & Remediated

| # | Threat Vector | Technical Target | What WinSentinel Does |
| :---: | :--- | :--- | :--- |
| **1** | **Core OS Telemetry** | `DiagTrack`, `dmwappushservice` | Stops and permanently disables background event and diagnostic loggers. |
| **2** | **Deep System Scanners** | `CompatTelRunner.exe`, `ProgramDataUpdater` | Disables scheduled tasks that scan storage and driver inventories. |
| **3** | **CEIP Telemetry** | `Consolidator`, `UsbCeip` | Shuts down hardware usage and USB peripheral tracking tasks. |
| **4** | **Device Metadata Pushes** | `PreventDeviceMetadataFromNetwork = 1` | Blocks Windows from auto-downloading companion apps when hardware is connected. |
| **5** | **Outbound Metadata Firewall** | `DMRClient.exe` Firewall Rule | Blocks outbound network connections to Microsoft metadata servers. |
| **6** | **Cloud Consumer Pushes** | `DisableWindowsConsumerFeatures = 1` | Blocks sponsored apps, Start Menu ads, and SCOOBE takeovers. |
| **7** | **Silent Store Auto-Downloads** | `AutoDownload = 2` | Disables silent background app pushes from the Microsoft Store. |
| **8** | **Input & Contact Harvesting** | `HarvestContacts = 0`, Inking Policies | Stops Windows from indexing local contact lists and typing dictionaries. |
| **9** | **GameDVR & Display Hooks** | `GameDVR_Enabled = 0`, `AppCaptureEnabled = 0` | Disables DirectX/graphics background video recording and memory hooks. |
| **10** | **OEM Audio Interception** | `NahimicService`, `IgoAudioService`, `SoundTune` | Neutralizes proprietary AI voice-processing and microphone filter hooks. |

---

## 🛠️ Usage

### Option 1: 1-Click Interactive Menu (Recommended)
1. Right-click **`Run-WinSentinel.bat`** and select **"Run as administrator"**.
2. Select your desired operation from the interactive menu:
   * `[1]` Run Non-Destructive System Audit
   * `[2]` Apply Full System Hardening & Bloatware Purge
   * `[3]` Create Safety Backup (Registry & Restore Point)
   * `[4]` Neutralize Audio & Microphone Hooks Only
   * `[5]` Apply Device Metadata & Companion App Firewall Block Only

---

### Option 2: PowerShell CLI (Automated / Headless)

#### Run a Non-Destructive System Audit:
```powershell
.\WinSentinel.ps1 -AuditOnly
```

#### Run Full System Hardening with Automatic Safety Backup:
```powershell
.\WinSentinel.ps1 -RemediateAll -Backup
```

#### Export Audit Findings to a JSON Report:
```powershell
.\WinSentinel.ps1 -AuditOnly -ExportReport "C:\Reports\AuditReport.json"
```

#### Headless Deployment via Remote Management (Intune / SCCM / Ansible):
```powershell
.\WinSentinel.ps1 -RemediateAll -Backup -Silent -LogPath "C:\ProgramData\WinSentinel\deploy.log"
```

---

## 🔒 Safety & Stability Guarantees

WinSentinel was built to adhere to enterprise stability standards:
* **Windows Updates:** Core OS updates, cumulative patches, and security definitions remain **100% operational**.
* **Driver Functionality:** Standard audio playback, microphone hardware, GPUs, network cards, and monitors function normally via Windows Core drivers.
* **Plug-and-Play Hardware:** Any mouse, keyboard, monitor, or USB drive plugged into the machine will install and operate immediately.
* **No Broken Dependencies:** Does not rip out foundational Windows subsystems or corrupt DISM component stores.
* **Rollback Protection:** Every registry modification is preceded by an export to `C:\WinSentinel_Backups\` for zero-risk restoration.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE). Feel free to fork, adapt, and share.
