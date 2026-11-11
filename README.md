# WinSentinel 🛡️
### Enterprise-Grade Windows Privacy, Telemetry & Bloatware Hardening Suite

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/powershell)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey.svg)](https://microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status: Production](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)]()

**WinSentinel** is an automated audit, telemetry de-bloat, and hardware hardening suite for **Windows 11, 10, and Windows Server (2019/2022/2025)**. It eliminates invasive OS diagnostics, background microphone/voice interception hooks, silent Store pushes, and manufacturer companion apps without breaking Windows Updates or core drivers.

---

## 🚨 Windows Tracking Software & Bloatware List

> 📖 **Architecture Guide:** For binary file paths, service configs, registry keys, and network flows, see the **[Windows 11 Telemetry & Architecture Guide](WINDOWS-11-TELEMETRY-AUDIT.md)**.

| Component / Service | Threat Category | What It Tracks & Records | Destination / Recipient | Deep Dive |
| :--- | :--- | :--- | :--- | :--- |
| **`DiagTrack`** | OS Telemetry | System crashes, app usage, hardware IDs, OS events | Microsoft (`v10.events.data.microsoft.com`) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#1-connected-user-experiences-and-telemetry-diagtrack) |
| **`CompatTelRunner.exe`** | Disk Scanner | Full storage drive scan; executable hashes & driver inventory | Microsoft (Appraiser Backend) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#1-microsoft-compatibility-appraiser-compattelrunnerexe) |
| **`DPS` / `PcaSvc`** | Crash & Hang Logging | Monitored binary execution events, crash frequency, app hangs | Microsoft (Diagnostics Engine) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#2-diagnostic-policy-service-dps) |
| **`wsqmcons.exe` (CEIP)** | Hardware Profiling | USB peripheral serials/IDs, device connection timestamps | Microsoft (CEIP Servers) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#2-customer-experience-improvement-program-ceip--wsqmconsexe) |
| **`DMRClient.exe`** | Companion Retrieval | Hardware IDs of connected monitors/peripherals to auto-push apps | Microsoft (`dmd.metaservices.microsoft.com`) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#1-device-metadata-retrieval-client-dmrclientexe) |
| **`LGMonitorApp`** | OEM Companion App | Monitor telemetry, firmware status, display metrics | LG Electronics Servers | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#vector-3-device-metadata-retrieval--silent-companion-bloatware) |
| **`ContentDeliveryManager`** | Ad & App Push Engine | Ad impressions, user click engagement, Start menu clicks | Microsoft (Cloud Content Relay) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#4-content-delivery-manager--scoobe-prompts) |
| **`AdvertisingInfo`** | User Profiling | Cross-application advertising identifier (GUID) | Microsoft Advertising Network | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#1-windows-advertising-id) |
| **Bing Taskbar Search** | Search Tracking | Keystrokes and search queries typed into the Windows taskbar | Microsoft Bing (`bing.com`) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#3-start-menu-web-search--bing-queries) |
| **`HarvestContacts`** | Contact Harvesting | Address books, emails, typing vocabulary, handwriting ink | Microsoft Personalization Engine | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#2-predictive-text--contact-harvesting-harvestcontacts) |
| **`GameDVR` / `AppCapture`** | Display / Screen Hook | Injects hooks into DirectX/Vulkan frames; records gameplay buffers | Local Disk Buffer / Xbox Live | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#vector-5-graphics-hooks--screen-recording) |
| **`SoundTune.exe`** | Voice / Audio Filter | Real-time microphone audio stream via Audio Processing Object (APO) | Micro-Star International (MSI) / Local AI | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#1-msi-sound-tune) |
| **`IgoAudioService`** | Voice Interception | Kernel/driver-level microphone stream for AI voice extraction | intelliGo / Realtek Driver Pipeline | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#2-intelligo-audio-service-igoaudioservice) |
| **`NahimicService`** | Audio Processing Object | Core Audio playback and microphone capture endpoint streams | A-Volute / SteelSeries Servers | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#3-nahimic-audio-engine-nahimicservice) |
| **`MSI Center` / Services** | OEM System Telemetry | Hardware temperatures, voltages, running game titles, UUID | Micro-Star International (MSI) | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#3-threat-vector-quick-reference-matrix) |
| **`SteelSeries GG` (Moments)** | Screen / Audio Capture | Continuous screen recording buffer and audio capture | SteelSeries Analytics Servers | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#3-threat-vector-quick-reference-matrix) |
| **`CrossDeviceResume.exe`** | Cross-Device Sync | Syncs clipboard text, SMS history, call logs, phone notifications | Microsoft Cloud Relay | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#1-phone-link--cross-device-host) |
| **Edge Startup Boost** | Browser Preloader | Browser session tokens, background extensions, navigation logs | Microsoft Edge Analytics | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#2-microsoft-edge-startup-boost--autolaunch) |
| **Ad-Supported Appx Bloat** | Sponsored Apps | Usage metrics and ad impressions (Solitaire, BingTranslator, etc.) | Microsoft & Partner Ad Networks | [Read](WINDOWS-11-TELEMETRY-AUDIT.md#3-threat-vector-quick-reference-matrix) |

---

## ⚡ Quick Start: 1-Click Interactive Menu

1. Right-click **`Run-WinSentinel.bat`** and select **"Run as administrator"**.
2. Select your desired operation from the console menu:
   * **`[1]` Non-Destructive System Audit:** Scans your system and calculates a Hardening Compliance Score (0%–100%) without changing settings.
   * **`[2]` Full System Hardening & Bloatware Purge:** Executes complete lockdown across all 12 vectors with safety backup.
   * **`[3]` Anti-Bloat Lockdown:** Blocks future silent Store installs, Cloud Consumer features, and device companion apps.
   * **`[4]` Purge Bloatware Apps Only:** Uninstalls and deprovisions consumer bloatware packages from current and future profiles.
   * **`[5]` Neutralize Audio & Voice Hooks Only:** Stops and disables Nahimic, intelliGo, and MSI Sound Tune microphone monitors.
   * **`[6]` Device Metadata Firewall Block:** Blocks `DMRClient.exe` outbound network access and prevents silent hardware app downloads.
   * **`[7]` Create Safety Backup:** Creates a Windows Restore Point and exports registry keys to `C:\WinSentinel_Backups\`.

---

## 💻 PowerShell CLI & Remote Automation

Run WinSentinel programmatically across individual endpoints, Active Directory Group Policies, or MDM tools (**Microsoft Intune, SCCM, Ansible**):

```powershell
# Run a non-destructive audit and export report to JSON
.\WinSentinel.ps1 -AuditOnly -ExportReport "C:\Reports\AuditReport.json"

# Apply anti-bloatware lockdown with automated safety backup
.\WinSentinel.ps1 -BlockBloatware -Backup

# Purge installed and staged bloatware packages (AppX & Provisioned Images)
.\WinSentinel.ps1 -PurgeBloatware

# Neutralize proprietary audio & microphone interception hooks
.\WinSentinel.ps1 -NeutralizeAudio

# Full system hardening (silent, headless deployment with custom log file)
.\WinSentinel.ps1 -RemediateAll -Backup -Silent -LogPath "C:\ProgramData\WinSentinel\deploy.log"
```

---

## 🔒 Enterprise Stability & Safety Guarantees

* **Windows Updates:** Cumulative OS patches, Windows Defender definitions, and quality updates remain **100% operational**.
* **Zero Driver Breakage:** Audio playback, microphone inputs, GPUs, network adapters, and monitors continue functioning via standard Windows Core drivers.
* **Plug-and-Play Hardware:** New mice, keyboards, monitors, and USB peripherals install immediately without requiring OEM bloatware.
* **Non-Destructive Rollback:** Creates a System Restore Point (client OS) and exports registry branches to `C:\WinSentinel_Backups\` before any modification.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE). Maintained by [CROW Innovations](https://github.com/CROWInnovations).
