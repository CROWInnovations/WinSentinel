# Windows 11 Telemetry, Tracking & Bloatware Architecture Guide

> **Document Version:** 1.0.0  
> **Target OS:** Windows 11 (22H2/23H2/24H2), Windows 10, Windows Server 2022/2025  
> **Maintainer:** [CROW Innovations](https://github.com/CROWInnovations)  
> **Sanitization Status:** Verified Clean (Enterprise Generic / No Account Identifiers)

---

## 1. Executive Summary

Modern Windows operating systems (principally Windows 11 and Windows 10) integrate multiple persistent telemetry subsystems, scheduled inventory crawlers, device metadata fetchers, and audio driver hooks. These subsystems function out-of-the-box to catalog hardware profiles, monitor running processes, intercept audio/microphone endpoints, index user contacts, and display targeted partner advertisements.

This document details the exact technical mechanics of each tracking vector, including responsible services, binary locations on disk, registry entries, and network transmission destinations.

---

## 2. Technical Architecture & Component Breakdown

```
+-----------------------------------------------------------------------------------+
|                            WINDOWS 11 USER ENVIRONMENT                            |
+-----------------------------------------------------------------------------------+
           |                                   |                             |
           v                                   v                             v
+-----------------------+           +-----------------------+     +-----------------------+
|  Core OS Telemetry    |           | Hardware & Peripheral |     |  Audio & Voice APOs   |
|  - DiagTrack          |           | - DMRClient.exe       |     |  - NahimicService     |
|  - DPS / PcaSvc       |           | - CompatTelRunner     |     |  - IgoAudioService    |
|  - ContentDeliveryMgr |           | - wsqmcons (CEIP)     |     |  - SoundTune (MSI)    |
+-----------------------+           +-----------------------+     +-----------------------+
           |                                   |                             |
           v                                   v                             v
 [v10.events.data.ms.com]           [dmd.metaservices.ms.com]     [Local AI Audio Filters /
 [telemetry.microsoft.com]          [Silently Pushes Store Apps]   Vendor Analytics Out]
```

---

### Vector 1: Core OS Diagnostics & Event Telemetry

#### 1. Connected User Experiences and Telemetry (`DiagTrack`)
* **How It Works:** Acts as the primary Event Tracing for Windows (ETW) aggregation service. It intercepts OS error reports, application telemetry, crash dumps, and real-time usage metrics, batches them into encrypted payloads, and transmits them to Microsoft cloud endpoints.
* **Service Name:** `DiagTrack` (Display Name: *Connected User Experiences and Telemetry*)
* **Binary Location:** `%SystemRoot%\System32\diagtrack.dll` (hosted inside `svchost.exe -k utcsvc`)
* **Registry Key:** `HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack`
* **Cloud Endpoints:** `v10.events.data.microsoft.com`, `v20.events.data.microsoft.com`
* **Audit / Neutralization Setting:**
  ```powershell
  Stop-Service -Name "DiagTrack" -Force
  Set-Service -Name "DiagTrack" -StartupType Disabled
  ```

#### 2. Diagnostic Policy Service (`DPS`)
* **How It Works:** Manages diagnostic scenario execution, monitors system component responsiveness, detects app execution hangs, and logs performance metrics.
* **Service Name:** `DPS` (Display Name: *Diagnostic Policy Service*)
* **Binary Location:** `%SystemRoot%\System32\dps.dll`
* **Registry Key:** `HKLM\SYSTEM\CurrentControlSet\Services\DPS`
* **Audit / Neutralization Setting:**
  ```powershell
  Stop-Service -Name "DPS" -Force
  Set-Service -Name "DPS" -StartupType Disabled
  ```

#### 3. Program Compatibility Assistant (`PcaSvc`)
* **How It Works:** Monitors every binary launched by the user. If an application exits with an abnormal return code, crashes, or encounters driver conflicts, `PcaSvc` generates an inventory log and queries Microsoft databases for compatibility shims.
* **Service Name:** `PcaSvc` (Display Name: *Program Compatibility Assistant Service*)
* **Binary Location:** `%SystemRoot%\System32\pcasvc.dll`
* **Registry Key:** `HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc`
* **Audit / Neutralization Setting:**
  ```powershell
  Stop-Service -Name "PcaSvc" -Force
  Set-Service -Name "PcaSvc" -StartupType Disabled
  ```

---

### Vector 2: Storage Crawlers & Hardware Inventory Scanners

#### 1. Microsoft Compatibility Appraiser (`CompatTelRunner.exe`)
* **How It Works:** A scheduled task triggered daily or post-update. It crawls storage drives, parses application installation directories, computes executable file hashes, analyzes installed drivers, and transmits a full inventory report to Microsoft to assess OS upgrade compatibility.
* **Scheduled Task Path:** `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser`
* **Related Tasks:** `ProgramDataUpdater`, `StartupAppTask`
* **Binary Location:** `%SystemRoot%\System32\CompatTelRunner.exe`
* **Audit / Neutralization Setting:**
  ```powershell
  Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "Microsoft Compatibility Appraiser"
  Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "ProgramDataUpdater"
  Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "StartupAppTask"
  ```

#### 2. Customer Experience Improvement Program (`CEIP` / `wsqmcons.exe`)
* **How It Works:** Collects hardware interaction telemetry, including every USB peripheral connected to the system (Vendor IDs, Product IDs, connection frequency), and aggregates session metrics.
* **Scheduled Task Path:** `\Microsoft\Windows\Customer Experience Improvement Program\` (`Consolidator`, `UsbCeip`)
* **Binary Location:** `%SystemRoot%\System32\wsqmcons.exe`
* **Audit / Neutralization Setting:**
  ```powershell
  Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "Consolidator"
  Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "UsbCeip"
  ```

---

### Vector 3: Device Metadata Retrieval & Silent Companion Bloatware

#### 1. Device Metadata Retrieval Client (`DMRClient.exe`)
* **How It Works:** When a new peripheral (e.g., an LG monitor, HP printer, Razer mouse, or Corsair keyboard) is connected, Windows extracts the device's hardware IDs (HardwareID / CompatibleID). `DMRClient.exe` queries Microsoft's Device Metadata service (`dmd.metaservices.microsoft.com`). If the hardware vendor registered a companion application in the Microsoft Store (such as *LG Monitor App*, *HP Smart*, or *Razer Synapse*), Windows automatically queues and silently installs the companion software in the background without user confirmation.
* **Binary Location:** `%SystemRoot%\System32\DMRClient.exe`
* **Registry Key:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata`
* **Registry Value:** `PreventDeviceMetadataFromNetwork = 1` (DWORD)
* **Firewall Rule:** Block Outbound on `%SystemRoot%\System32\DMRClient.exe`
* **Audit / Neutralization Setting:**
  ```powershell
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord
  New-NetFirewallRule -DisplayName "Block-Windows-Device-Metadata-Retrieval" -Direction Outbound -Program "%SystemRoot%\System32\DMRClient.exe" -Action Block -Profile Any
  ```

#### 2. Windows Store Silent Background Pushes
* **Registry Key:** `HKLM\SOFTWARE\Policies\Microsoft\WindowsStore`
* **Registry Value:** `AutoDownload = 2` (2 = Disallow auto-download of store apps)
* **Audit / Neutralization Setting:**
  ```powershell
  New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
  Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Value 2 -Type DWord
  ```

---

### Vector 4: Advertising, Profiling & Contact Harvesting

#### 1. Windows Advertising ID
* **How It Works:** Assigns a persistent GUID to each user profile. Applications and third-party advertising SDKs query this identifier to track behavior across apps and display personalized ads.
* **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo`
* **Registry Value:** `Enabled = 0` (DWORD)
* **Policy Key:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo` (`DisabledByGroupPolicy = 1`)

#### 2. Predictive Text & Contact Harvesting (`HarvestContacts`)
* **How It Works:** Windows scans the user's address books, email caches, and typing patterns to build a localized predictive text profile, syncing data points with cloud personalization servers.
* **Registry Key:** `HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore`
* **Registry Values:**
  * `HarvestContacts = 0` (DWORD)
  * `RestrictImplicitInkCollection = 1` (DWORD in `HKCU\Software\Microsoft\InputPersonalization`)
  * `RestrictImplicitTextCollection = 1` (DWORD in `HKCU\Software\Microsoft\InputPersonalization`)

#### 3. Start Menu Web Search & Bing Queries
* **How It Works:** Every keystroke entered into the Windows Taskbar search box is transmitted in real time to Microsoft Bing servers to retrieve web suggestions, logging user search queries.
* **Registry Key:** `HKCU\Software\Policies\Microsoft\Windows\Explorer` & `HKCU\Software\Microsoft\Windows\CurrentVersion\Search`
* **Registry Values:**
  * `DisableSearchBoxSuggestions = 1`
  * `BingSearchEnabled = 0`
  * `CortanaConsent = 0`

#### 4. Content Delivery Manager & SCOOBE Prompts
* **How It Works:** Manages dynamic Start Menu tiles, promotional app suggestions (e.g., TikTok, Spotify, Candy Crush), lockscreen overlays, and post-update "Finish Setting Up Your PC" (SCOOBE) takeovers.
* **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager`
* **Registry Values Set to 0:**
  * `SoftLandingEnabled = 0`
  * `SubscribedContent-310093Enabled = 0` (Welcome experience)
  * `SubscribedContent-338387Enabled = 0` (Tips and tricks)
  * `SubscribedContent-338388Enabled = 0` (Suggested apps in Start)
  * `SubscribedContent-338389Enabled = 0` (Promotions)
  * `SystemPaneSuggestionsEnabled = 0`
  * `RotatingLockScreenOverlayEnabled = 0`
* **Group Policy Counterpart:**
  * Key: `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent`
  * Value: `DisableWindowsConsumerFeatures = 1`

---

### Vector 5: Graphics Hooks & Screen Recording

#### Windows GameDVR & AppCapture
* **How It Works:** Injects background capture hooks into DirectX and Vulkan graphics pipelines for fullscreen applications. Keeps a circular memory and disk buffer of recent video frames and audio channels.
* **Registry Locations:**
  * `HKCU\System\GameConfigStore` -> `GameDVR_Enabled = 0`
  * `HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR` -> `AppCaptureEnabled = 0`
* **Group Policy Key:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR` -> `AllowGameDVR = 0`

---

### Vector 6: Audio, Microphone & Voice Interception Engines

Modern OEM Windows installations bundle proprietary Audio Processing Objects (APOs) that run at the driver level. These services intercept live microphone capture and audio playback endpoints:

#### 1. MSI Sound Tune
* **How It Works:** A neural network engine bundled with OEM control software. It attaches an APO to the primary microphone stream to classify human speech vs. ambient noise, monitoring audio buffers in real time.
* **Binary Location:** `%ProgramFiles(x86)%\MSI\MSI Center\Sound Tune\SoundTune.exe`
* **Log Location:** `%ProgramFiles(x86)%\MSI\MSI Center\Log\Sound Tune\SoundTune.txt`

#### 2. intelliGo Audio Service (`IgoAudioService`)
* **How It Works:** Driver-level voice extraction software packaged into Realtek/Intel High Definition Audio driver bundles. Runs as a persistent Windows Service with elevated SYSTEM permissions, filtering microphone inputs.
* **Binary Location:** `%SystemRoot%\System32\DriverStore\FileRepository\igoaudioservice.inf_*\IgoAudioService_x64.exe`
* **Service Name:** `IgoAudioService`

#### 3. Nahimic Audio Engine (`NahimicService`)
* **How It Works:** Injects audio hooks into Windows Core Audio endpoints. Spawns persistent volume watchers and notification daemons that monitor audio streams and transmit usage metrics back to SteelSeries/A-Volute servers.
* **Binary Locations:**
  * `%SystemRoot%\System32\NahimicService.exe`
  * `%SystemRoot%\System32\NahimicAPO4Volume.exe`
  * `%LOCALAPPDATA%\NhNotifSys\nahimic\nahimicNotifSys.exe`
* **Service Name:** `NahimicService`

---

### Vector 7: Cross-Device Synchronization & Browser Background Preloading

#### 1. Phone Link & Cross-Device Host
* **How It Works:** Synchronizes local SMS, call history, photo galleries, contacts, and active clipboard contents between Windows and paired mobile devices via Microsoft cloud relays.
* **Package Names:** `Microsoft.YourPhone`, `MicrosoftWindows.CrossDevice`
* **Binary Location:** `%SystemRoot%\SystemApps\MicrosoftWindows.Client.CBS_*\CrossDeviceResume.exe`
* **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\SharedExperiences`
  * `CdpSessionUserAuthzPolicy = 0`
  * `RomeSdkChannelUserAuthzPolicy = 0`

#### 2. Microsoft Edge Startup Boost & AutoLaunch
* **How It Works:** Launches background Edge browser processes during Windows login before the user ever opens the application. Keeps background extensions active and maintains telemetry sockets.
* **Registry Key:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` -> `MicrosoftEdgeAutoLaunch_*`
* **User Profile Config:** `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Preferences` (`startup_boost.enabled = false`, `background_mode.enabled = false`)

---

## 3. Threat Vector Quick Reference Matrix

| Component / Subsystem | Primary Function | Data Collected / Intercepted | Cloud / Host Destination |
| :--- | :--- | :--- | :--- |
| **`DiagTrack`** | OS Event Logging | System crashes, app usage, hardware IDs | `v10.events.data.microsoft.com` |
| **`CompatTelRunner.exe`** | Disk & Driver Scanner | Executable file hashes, installed software, driver versions | Microsoft Compatibility Backend |
| **`DPS` / `PcaSvc`** | App Crash Monitor | Binary execution logs, hang events, error returns | Microsoft Diagnostics Engine |
| **`wsqmcons.exe` (CEIP)** | Peripheral Profiling | USB hardware IDs, device connection frequency | Microsoft CEIP Servers |
| **`DMRClient.exe`** | Device Metadata Client | Hardware IDs of monitors and peripherals | `dmd.metaservices.microsoft.com` (Pushes OEM Apps) |
| **`LGMonitorApp` / OEM Apps** | Peripheral Companion | Display metrics, firmware state, monitor serial | LG Electronics / OEM Servers |
| **`AdvertisingInfo`** | User Ad Profiling | Cross-application behavioral identifier | Microsoft Advertising Network |
| **`HarvestContacts`** | Contact Harvesting | Address books, emails, typing vocabulary | Microsoft Personalization Engine |
| **Taskbar Bing Search** | Search Query Logger | Keystrokes typed into Windows search box | Microsoft Bing (`bing.com`) |
| **`ContentDeliveryManager`** | App & Ad Push Engine | Engagement clicks, sponsored app impressions | Microsoft Cloud Content Relay |
| **`GameDVR` / `AppCapture`** | Screen/Graphics Hook | In-game frames, window handles, audio streams | Local Disk Buffer / Xbox Live |
| **`SoundTune.exe` (MSI)** | Microphone Filter | Real-time microphone audio stream | Local AI Processing / MSI Analytics |
| **`IgoAudioService`** | Voice Extraction | Driver-level microphone input stream | intelliGo / Realtek Driver Pipeline |
| **`NahimicService`** | Audio Processing Object | Core audio playback and microphone capture | A-Volute / SteelSeries Servers |
| **`CrossDeviceResume.exe`** | Mobile Device Relay | Clipboard data, notifications, SMS, call logs | Microsoft Graph / Cloud Services |
| **Edge Startup Boost** | Browser Preloader | Browser session tokens, background extensions | Microsoft Edge Analytics |

---

## 4. Remediation via WinSentinel

All vectors documented above can be automatically audited and secured using the open-source **[WinSentinel](https://github.com/CROWInnovations/WinSentinel)** suite.

* **Non-destructive Audit:** `.\WinSentinel.ps1 -AuditOnly`
* **Full Automated Remediation & Backup:** `.\WinSentinel.ps1 -RemediateAll -Backup`
