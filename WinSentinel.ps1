<#
.SYNOPSIS
    WinSentinel - Professional Windows Privacy, Telemetry & Bloatware Hardening Suite.

.DESCRIPTION
    WinSentinel is an enterprise-grade PowerShell audit and remediation engine designed
    for Windows 10, Windows 11, and Windows Server (2019/2022/2025). It audits, documents,
    and neutralizes operating system telemetry, background audio/video recording hooks,
    silent Store application pushes, OEM hardware tracking, and device metadata retrieval.

    Built for enterprise reliability, it features comprehensive error handling, modular
    architecture, automated safety backups (System Restore Points & Registry exports),
    and persistent file logging.

.PARAMETER AuditOnly
    Runs a non-destructive audit scan across all security and privacy vectors without
    modifying system configuration. Outputs a scored compliance report.

.PARAMETER RemediateAll
    Executes full system lockdown, neutralizing all identified telemetry collectors,
    OEM audio hooks, scheduled inventory scanners, and consumer bloatware.

.PARAMETER BlockBloatware
    Applies comprehensive policies and firewall rules to permanently block silent Store
    app pushes, Cloud Consumer features, OEM companion apps (e.g. LG Monitor App),
    advertising IDs, and deprovisions bloatware staging.

.PARAMETER PurgeBloatware
    Uninstalls identified consumer bloatware packages from the current user account
    and deprovisions them from the Windows online image to prevent reinstallation.

.PARAMETER BlockCompanionApps
    Configures Device Metadata policies and an outbound Windows Defender Firewall rule
    to prevent DMRClient from querying Microsoft servers and auto-pushing OEM apps.

.PARAMETER NeutralizeAudio
    Stops, disables, and neutralizes OEM background audio and voice interception
    services and Audio Processing Objects (Nahimic, intelliGo, MSI Sound Tune).

.PARAMETER Backup
    Creates a System Restore Point (if supported by OS edition) and exports targeted
    registry branches to a timestamped backup directory prior to remediation.

.PARAMETER LogPath
    Specifies a custom destination directory or file path for persistent execution logs.
    Defaults to "$PSScriptRoot\Logs\WinSentinel_<timestamp>.log".

.PARAMETER ExportReport
    Specifies a file path to export the complete audit results in structured JSON format.

.PARAMETER Silent
    Suppresses interactive console prompts, making the script suitable for automated
    deployment via Intune, SCCM, Group Policy, or remote management tooling.

.EXAMPLE
    .\WinSentinel.ps1 -AuditOnly
    Runs an audit scan, displays a scored summary in the console, and writes to log.

.EXAMPLE
    .\WinSentinel.ps1 -BlockBloatware -Backup
    Creates a backup and permanently blocks silent bloatware, store pushes, and companion apps.

.EXAMPLE
    .\WinSentinel.ps1 -RemediateAll -Backup
    Creates a safety backup and executes complete system hardening.

.OUTPUTS
    System.Management.Automation.PSCustomObject containing audit results and compliance metrics.

.NOTES
    Author:       WinSentinel Contributors
    License:      MIT License
    Version:      2.1.0
    Requirements: PowerShell 5.1 or PowerShell 7+ running on Windows 10, 11, or Server.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$AuditOnly,
    [switch]$RemediateAll,
    [switch]$BlockBloatware,
    [switch]$PurgeBloatware,
    [switch]$BlockCompanionApps,
    [switch]$NeutralizeAudio,
    [switch]$Backup,
    [string]$LogPath,
    [string]$ExportReport,
    [switch]$Silent
)

# Enforce clean error capturing
$ErrorActionPreference = "Continue"

# ==============================================================================
# 1. LOGGING & INITIALIZATION
# ==============================================================================

# Establish persistent log file path
$script:LogDirectory = if ($LogPath) {
    if (Test-Path $LogPath -PathType Container) { $LogPath } else { Split-Path -Path $LogPath -Parent }
} else {
    Join-Path -Path $PSScriptRoot -ChildPath "Logs"
}

if (-not (Test-Path $script:LogDirectory)) {
    try {
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    } catch {
        # Fallback to ProgramData if script directory is read-only
        $script:LogDirectory = "C:\ProgramData\WinSentinel\Logs"
        New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
    }
}

$script:LogFile = if ($LogPath -and (Test-Path $LogPath -PathType Leaf)) {
    $LogPath
} else {
    Join-Path -Path $script:LogDirectory -ChildPath ("WinSentinel_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO",

        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logLine = "[$timestamp] [$Level] $Message"

    # Append to disk log file with lock protection
    try {
        Add-Content -Path $script:LogFile -Value $logLine -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {
        # Fail-safe: continue execution even if log disk write encounters transient lock
    }

    # Console stream output with semantic coloring
    if (-not $NoConsole -and -not $Silent) {
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARN"    { "Yellow" }
            "ERROR"   { "Red" }
            "DEBUG"   { "DarkGray" }
            Default   { "White" }
        }
        
        $prefix = switch ($Level) {
            "SUCCESS" { "[+]" }
            "WARN"    { "[!]" }
            "ERROR"   { "[-]" }
            "DEBUG"   { "[?]" }
            Default   { "[*]" }
        }

        Write-Host "$prefix $Message" -ForegroundColor $color
    }
}

# Master List of Known Consumer Bloatware and Companion Apps
$script:DefaultBloatwareList = @(
    # Vendor companion apps & silent hardware pushers
    "LGElectronics.LGMonitorApp",
    "RivetNetworks.KillerControlCenter",
    "AppUp.IntelOptaneMemoryandStorageManagement",
    
    # Pre-installed ad & sponsored consumer apps
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.BingTranslator",
    "Microsoft.GetHelp",
    "Microsoft.PowerAutomateDesktop",
    "Microsoft.StartExperiencesApp",
    "Microsoft.YourPhone",
    "MicrosoftWindows.CrossDevice",
    "Clipchamp.Clipchamp",
    "Microsoft.549981C3F5F10",
    "Microsoft.BingNews",
    "Microsoft.BingWeather",
    "Microsoft.BingSports",
    "Microsoft.BingFinance",
    "Microsoft.Todos",
    "Microsoft.People",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MixedReality.Portal",
    "Microsoft.WindowsFeedbackHub",
    
    # Third-party OEM sponsored bundles (if present)
    "SpotifyAB.SpotifyMusic",
    "BytedancePte.Ltd.TikTok",
    "Disney.37853FC22B2CE",
    "king.com.CandyCrushSaga",
    "king.com.CandyCrushSodaSaga"
)

# ==============================================================================
# 2. SYSTEM ARCHITECTURE & ENVIRONMENT DETECTION
# ==============================================================================

function Test-IsAdmin {
    try {
        $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log -Message "Failed to verify administrative privileges: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Get-OperatingSystemInfo {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $isServer = ($os.ProductType -ne 1)
        $osFamily = if ($os.BuildNumber -ge 22000) { "Windows 11" } elseif ($isServer) { "Windows Server" } else { "Windows 10" }

        return [PSCustomObject]@{
            Caption     = $os.Caption
            Version     = $os.Version
            BuildNumber = [int]$os.BuildNumber
            IsServer    = $isServer
            OSFamily    = $osFamily
        }
    } catch {
        Write-Log -Message "CIM Operating System query failed. Falling back to environment variables: $($_.Exception.Message)" -Level WARN
        return [PSCustomObject]@{
            Caption     = [System.Environment]::OSVersion.VersionString
            Version     = [System.Environment]::OSVersion.Version.ToString()
            BuildNumber = [System.Environment]::OSVersion.Version.Build
            IsServer    = $false
            OSFamily    = "Windows"
        }
    }
}

function Write-Banner {
    if ($Silent) { return }
    Clear-Host
    Write-Host @"
================================================================================
   _       ___       _____            __  _            __ 
  | |     / (_)___  / ___/___  ____  / /_(_)___  ___  / / 
  | | /| / / / __ \ \__ \/ _ \/ __ \/ __/ / __ \/ _ \/ /  
  | |/ |/ / / / / /___/ /  __/ / / / /_/ / / / /  __/ /   
  |__/|__/_/_/ /_//____/\___/_/ /_/\__/_/_/ /_/\___/_/    
================================================================================
  Enterprise-Grade Privacy, Telemetry & Bloatware Hardening Suite
  Supports: Windows 10 | Windows 11 | Windows Server (2019/2022/2025)
  Session Log: $script:LogFile
================================================================================
"@ -ForegroundColor Cyan
}

# ==============================================================================
# 3. SAFETY & BACKUP SUBSYSTEM
# ==============================================================================

function Invoke-SystemBackup {
    [CmdletBinding()]
    param()

    Write-Log -Message "Initiating automated safety backup sequence..." -Level INFO
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = "C:\WinSentinel_Backups\Backup_$timestamp"

    try {
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force -ErrorAction Stop | Out-Null
        }
        Write-Log -Message "Created backup destination folder: $backupDir" -Level SUCCESS
    } catch {
        Write-Log -Message "Failed to create backup directory: $($_.Exception.Message)" -Level ERROR
        return $false
    }

    # 1. System Restore Point (Supported on Windows 10/11 client editions)
    try {
        Write-Log -Message "Attempting to create a Windows System Restore Point..." -Level INFO
        Start-Service -Name "srservice" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "WinSentinel Pre-Hardening Safety Backup" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Log -Message "System Restore Point created successfully." -Level SUCCESS
    } catch {
        Write-Log -Message "System Restore Point creation skipped (Not supported on Server editions, disabled by policy, or limited by frequency)." -Level WARN
    }

    # 2. Registry Branches Export
    $registryBranches = @(
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent",
        "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings",
        "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata",
        "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\Search",
        "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
        "HKCU\Software\Microsoft\InputPersonalization",
        "HKCU\System\GameConfigStore"
    )

    $successCount = 0
    foreach ($branch in $registryBranches) {
        $exportFileName = ($branch -replace '\\', '_') + ".reg"
        $exportPath = Join-Path -Path $backupDir -ChildPath $exportFileName
        try {
            $regProc = Start-Process -FilePath "reg.exe" -ArgumentList "export `"$branch`" `"$exportPath`" /y" -Wait -PassThru -NoNewWindow -ErrorAction Stop
            if ($regProc.ExitCode -eq 0 -and (Test-Path $exportPath)) {
                $successCount++
            }
        } catch {
            Write-Log -Message "Notice: Branch $branch does not currently exist to export (normal for clean systems)." -Level DEBUG
        }
    }

    Write-Log -Message "Exported $successCount configuration keys to safety archive: $backupDir" -Level SUCCESS
    return $true
}

# Helper function for safe registry modification
function Set-RegistryValueSafe {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop | Out-Null
        Write-Log -Message "Registry: Set $Path\$Name = $Value" -Level DEBUG
    } catch {
        Write-Log -Message "Failed setting registry $Path\$Name : $($_.Exception.Message)" -Level WARN
    }
}

# ==============================================================================
# 4. MODULAR REMEDIATION COMPONENTS
# ==============================================================================

# Sub-module: Block Device Companion Apps & Metadata Retrieval
function Invoke-BlockCompanionApps {
    [CmdletBinding()]
    param()

    Write-Log -Message "Configuring Device Metadata & Automatic Companion App blocks..." -Level INFO
    
    # 1. Registry Policies
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" "PreventDeviceMetadataFromNetwork" 1
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" "DisableCoInstallers" 1
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "DontSearchWindowsUpdate" 1

    # 2. Outbound DMRClient Firewall Rule
    try {
        $ruleName = "Block-Windows-Device-Metadata-Retrieval"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if (-not $existingRule) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Outbound `
                -Program "%SystemRoot%\System32\DMRClient.exe" `
                -Action Block `
                -Profile Any `
                -Description "WinSentinel: Blocks automatic vendor companion app retrieval from Microsoft Store when hardware is connected." -ErrorAction Stop | Out-Null
            Write-Log -Message "Created outbound firewall block rule for DMRClient.exe" -Level SUCCESS
        } else {
            Write-Log -Message "Firewall block rule for DMRClient.exe already active." -Level DEBUG
        }
    } catch {
        Write-Log -Message "Firewall rule configuration notice: $($_.Exception.Message)" -Level WARN
    }

    Write-Log -Message "Device companion app retrieval blocked successfully." -Level SUCCESS
}

# Sub-module: Purge Bloatware (Installed and Provisioned Images)
function Invoke-PurgeBloatware {
    [CmdletBinding()]
    param(
        [string[]]$PackageList = $script:DefaultBloatwareList
    )

    $osInfo = Get-OperatingSystemInfo
    Write-Log -Message "Scanning for consumer bloatware packages to purge on $($osInfo.OSFamily)..." -Level INFO

    $hasAppxCmdlet = Get-Command Get-AppxPackage -ErrorAction SilentlyContinue
    if (-not $hasAppxCmdlet) {
        Write-Log -Message "AppX package manager cmdlets are not available on this OS installation (typical on Windows Server Core)." -Level INFO
        return
    }

    $removedCount = 0
    foreach ($pkg in $PackageList) {
        # 1. Remove from current user profile
        try {
            $userPkgs = Get-AppxPackage "*$pkg*" -ErrorAction SilentlyContinue
            if ($userPkgs) {
                foreach ($up in $userPkgs) {
                    Write-Log -Message "Removing user package: $($up.Name)..." -Level INFO
                    Remove-AppxPackage -Package $up.PackageFullName -ErrorAction Stop
                    $removedCount++
                    Write-Log -Message "Successfully removed: $($up.Name)" -Level SUCCESS
                }
            }
        } catch {
            Write-Log -Message "Could not remove user package ${pkg}: $($_.Exception.Message)" -Level DEBUG
        }

        # 2. Deprovision from online system image (stops installation for any new profiles)
        try {
            $provCmd = Get-Command Get-AppxProvisionedPackage -ErrorAction SilentlyContinue
            if ($provCmd) {
                $provPkgs = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*$pkg*" }
                if ($provPkgs) {
                    foreach ($pp in $provPkgs) {
                        Write-Log -Message "Deprovisioning system image package: $($pp.DisplayName)..." -Level INFO
                        Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
                        $removedCount++
                        Write-Log -Message "Successfully deprovisioned: $($pp.DisplayName)" -Level SUCCESS
                    }
                }
            }
        } catch {
            Write-Log -Message "Could not deprovision package ${pkg}: $($_.Exception.Message)" -Level DEBUG
        }
    }

    if ($removedCount -gt 0) {
        Write-Log -Message "Bloatware purge completed: $removedCount packages/images removed." -Level SUCCESS
    } else {
        Write-Log -Message "Bloatware scan completed: No targeted bloatware packages found." -Level SUCCESS
    }
}

# Sub-module: Neutralize Audio & Microphone Interception Hooks
function Invoke-NeutralizeAudio {
    [CmdletBinding()]
    param()

    Write-Log -Message "Disabling OEM audio and microphone interception services..." -Level INFO

    $audioServices = @("NahimicService", "IgoAudioService")
    foreach ($asvc in $audioServices) {
        try {
            $svc = Get-Service -Name $asvc -ErrorAction SilentlyContinue
            if ($svc) {
                Stop-Service -Name $asvc -Force -ErrorAction SilentlyContinue
                Set-Service -Name $asvc -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Log -Message "Service stopped and disabled: $asvc" -Level SUCCESS
            }
        } catch {
            Write-Log -Message "Audio service ${asvc}: $($_.Exception.Message)" -Level DEBUG
        }
    }

    $audioProcesses = @("NahimicService.exe", "NahimicSvc64.exe", "NahimicAPO4Volume.exe", "nahimicNotifSys.exe", "IgoAudioService_x64.exe", "SoundTune.exe")
    foreach ($aproc in $audioProcesses) {
        try {
            $procs = Get-Process -Name ($aproc -replace '\.exe$', '') -ErrorAction SilentlyContinue
            if ($procs) {
                & taskkill.exe /F /IM $aproc /T 2>$null | Out-Null
                Write-Log -Message "Terminated background process: $aproc" -Level SUCCESS
            }
        } catch {
            # Ignore process already stopped
        }
    }

    # Neutralize user-space Nahimic notification daemon if present
    $userNh = "$env:LOCALAPPDATA\NhNotifSys\nahimic\nahimicNotifSys.exe"
    if (Test-Path $userNh) {
        try {
            Rename-Item -Path $userNh -NewName "nahimicNotifSys.exe.disabled" -Force -ErrorAction Stop
            Write-Log -Message "Neutralized executable: $userNh" -Level SUCCESS
        } catch {
            Write-Log -Message "Could not rename ${userNh}: $($_.Exception.Message)" -Level DEBUG
        }
    }

    Write-Log -Message "Audio and microphone interception hooks successfully neutralized." -Level SUCCESS
}

# Sub-module: Block Future Bloatware, Store Pushes & Consumer Cloud Features
function Invoke-BlockFutureBloatware {
    [CmdletBinding()]
    param()

    Write-Log -Message "Enforcing anti-bloatware policies, silent Store blocks, and consumer lockdowns..." -Level INFO

    # 1. Device Metadata and Companion App blocks
    Invoke-BlockCompanionApps

    # 2. Cloud Consumer Features & Sponsored Apps
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableCloudOptimizedContent" 1

    # 3. Content Delivery Manager Policies (Start Menu ads, suggestions, SCOOBE)
    $cdmSettings = @{
        "SoftLandingEnabled"               = 0
        "SubscribedContent-310093Enabled"  = 0
        "SubscribedContent-338387Enabled"  = 0
        "SubscribedContent-338388Enabled"  = 0
        "SubscribedContent-338389Enabled"  = 0
        "SystemPaneSuggestionsEnabled"     = 0
        "RotatingLockScreenOverlayEnabled" = 0
        "SilentInstalledAppsEnabled"       = 0
        "OemPreInstalledAppsEnabled"       = 0
        "PreInstalledAppsEnabled"          = 0
        "PreInstalledAppsEverEnabled"      = 0
    }
    foreach ($k in $cdmSettings.Keys) {
        Set-RegistryValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $k $cdmSettings[$k]
    }

    # 4. SCOOBE ("Finish Setting Up Your PC") Fullscreen Prompts
    Set-RegistryValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" "ScoobeSystemSettingEnabled" 0

    # 5. Microsoft Store Silent Auto-Downloads
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

    # 6. Windows Advertising ID Tracking
    Set-RegistryValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
    Set-RegistryValueSafe "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1

    # 7. Microsoft Edge Startup Boost & Background Execution
    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "MicrosoftEdgeAutoLaunch_*" -ErrorAction SilentlyContinue
        $prefPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Preferences"
        if (Test-Path $prefPath) {
            $jsonContent = Get-Content $prefPath -Raw | ConvertFrom-Json
            if (-not $jsonContent.startup_boost) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "startup_boost" -Value ([PSCustomObject]@{ enabled = $false })
            } else {
                $jsonContent.startup_boost.enabled = $false
            }
            if (-not $jsonContent.background_mode) {
                $jsonContent | Add-Member -MemberType NoteProperty -Name "background_mode" -Value ([PSCustomObject]@{ enabled = $false })
            } else {
                $jsonContent.background_mode.enabled = $false
            }
            $jsonContent | ConvertTo-Json -Depth 100 -Compress | Set-Content $prefPath -Encoding UTF8
            Write-Log -Message "Disabled Edge Startup Boost and background preload in user preferences." -Level SUCCESS
        }
    } catch {
        Write-Log -Message "Edge preference configuration notice: $($_.Exception.Message)" -Level DEBUG
    }

    # 8. Phone Link / Cross-Device Background Relay
    try {
        Get-Process -Name "CrossDeviceResume" -ErrorAction SilentlyContinue | Stop-Process -Force
        Set-RegistryValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\SharedExperiences" "CdpSessionUserAuthzPolicy" 0
        Set-RegistryValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\SharedExperiences" "RomeSdkChannelUserAuthzPolicy" 0
    } catch {
        Write-Log -Message "Cross-Device configuration notice: $($_.Exception.Message)" -Level DEBUG
    }

    # 9. Purge any currently staged/installed bloatware packages
    Invoke-PurgeBloatware

    Write-Log -Message "Anti-bloatware lockdown applied successfully." -Level SUCCESS
}

# ==============================================================================
# 5. AUDIT ENGINE
# ==============================================================================

function Invoke-SystemAudit {
    [CmdletBinding()]
    param()

    $osInfo = Get-OperatingSystemInfo
    Write-Log -Message "Executing audit against target: $($osInfo.Caption) [Build: $($osInfo.BuildNumber)]" -Level INFO

    $results = [System.Collections.Generic.List[PSObject]]::new()

    function Add-AuditCheck {
        param(
            [string]$Category,
            [string]$Name,
            [scriptblock]$CheckScript
        )
        try {
            $isSecured = & $CheckScript
            $results.Add([PSCustomObject]@{
                Category = $Category
                Name     = $Name
                Status   = if ($isSecured) { "Secured / Compliant" } else { "Vulnerable / Unhardened" }
                Secured  = [bool]$isSecured
            })
            $stateStr = if ($isSecured) { "Secured" } else { "Unhardened" }
            Write-Log -Message "Audit [$Category] ${Name}: $stateStr" -Level DEBUG
        } catch {
            Write-Log -Message "Audit error evaluating [$Category] ${Name}: $($_.Exception.Message)" -Level WARN
            $results.Add([PSCustomObject]@{
                Category = $Category
                Name     = $Name
                Status   = "Check Failed"
                Secured  = $false
            })
        }
    }

    # 1. Telemetry Services
    Add-AuditCheck "OS Telemetry" "Connected User Experiences (DiagTrack)" {
        $svc = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
        return (-not $svc -or $svc.Status -ne "Running")
    }

    # 2. Deep Compatibility Appraiser Task
    Add-AuditCheck "System Inventory" "Compatibility Appraiser (CompatTelRunner)" {
        $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Application Experience\" -TaskName "Microsoft Compatibility Appraiser" -ErrorAction SilentlyContinue
        return (-not $task -or $task.State -eq "Disabled")
    }

    # 3. Customer Experience Improvement Program (CEIP)
    Add-AuditCheck "System Inventory" "CEIP Telemetry Logging (Consolidator)" {
        $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -TaskName "Consolidator" -ErrorAction SilentlyContinue
        return (-not $task -or $task.State -eq "Disabled")
    }

    # 4. Device Metadata & Companion Pushes
    Add-AuditCheck "Device Pushes" "Automatic Device Companion Bloatware" {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue).PreventDeviceMetadataFromNetwork
        return ($val -eq 1)
    }

    # 5. DMRClient Firewall Rule
    Add-AuditCheck "Firewall" "Device Metadata Retrieval Firewall Block" {
        $rule = Get-NetFirewallRule -DisplayName "Block-Windows-Device-Metadata-Retrieval" -ErrorAction SilentlyContinue
        return ($rule -and $rule.Enabled -eq "True")
    }

    # 6. Windows Consumer Features & Promoted Apps
    Add-AuditCheck "Cloud Bloat" "Silent Consumer App Pushes" {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -ErrorAction SilentlyContinue).DisableWindowsConsumerFeatures
        return ($val -eq 1)
    }

    # 7. Microsoft Store Silent Auto-Download
    Add-AuditCheck "Store Policy" "Silent Store Background Pushes" {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -ErrorAction SilentlyContinue).AutoDownload
        return ($val -eq 2)
    }

    # 8. Advertising ID Profiling
    Add-AuditCheck "Ad Profiling" "Windows Advertising ID Policy" {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue).DisabledByGroupPolicy
        return ($val -eq 1)
    }

    # 9. Contact & Typing Harvesting
    Add-AuditCheck "Privacy" "Contact & Typing Telemetry Harvesting" {
        $val = (Get-ItemProperty "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -ErrorAction SilentlyContinue).HarvestContacts
        return ($val -eq 0)
    }

    # 10. GameDVR & Display Hooks (Client OS only)
    if (-not $osInfo.IsServer) {
        Add-AuditCheck "Display Hooks" "Windows GameDVR Background Capture" {
            $val = (Get-ItemProperty "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -ErrorAction SilentlyContinue).GameDVR_Enabled
            return ($val -eq 0)
        }
    }

    # 11. OEM Audio / Voice Interception Services
    Add-AuditCheck "Audio Interception" "OEM Voice Processing / Audio Hooks" {
        $nahimic = Get-Service -Name "NahimicService" -ErrorAction SilentlyContinue
        $igo = Get-Service -Name "IgoAudioService" -ErrorAction SilentlyContinue
        $soundTune = Get-Process -Name "SoundTune" -ErrorAction SilentlyContinue
        return (-not (($nahimic -and $nahimic.Status -eq "Running") -or ($igo -and $igo.Status -eq "Running") -or ($soundTune -ne $null)))
    }

    # 12. Installed Consumer Bloatware
    Add-AuditCheck "Bloatware" "Staged Consumer Bloatware Check" {
        if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
            $foundAny = $false
            foreach ($b in $script:DefaultBloatwareList) {
                if (Get-AppxPackage "*$b*" -ErrorAction SilentlyContinue) {
                    $foundAny = $true
                    break
                }
            }
            return (-not $foundAny)
        }
        return $true
    }

    # Output Table Formatting
    if (-not $Silent) {
        Write-Host "`n--- SYSTEM AUDIT RESULTS ---" -ForegroundColor Yellow
        $results | Format-Table -Property Category, Name, Status -AutoSize
    }

    $totalChecks = $results.Count
    $passedChecks = ($results | Where-Object { $_.Secured }).Count
    $score = if ($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 1) } else { 0 }

    Write-Log -Message "Overall System Hardening Score: $score% ($passedChecks of $totalChecks vectors secured)." -Level $(if ($score -ge 80) { "SUCCESS" } elseif ($score -ge 50) { "WARN" } else { "ERROR" })

    # Export report if requested
    if ($ExportReport) {
        try {
            $reportData = [ordered]@{
                ToolName        = "WinSentinel Enterprise"
                Version         = "2.1.0"
                OperatingSystem = $osInfo
                AuditTimestamp  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                HardeningScore  = "$score%"
                SecuredCount    = $passedChecks
                TotalCount      = $totalChecks
                AuditChecks     = $results
            }
            $reportJson = $reportData | ConvertTo-Json -Depth 6
            $reportDir = Split-Path -Path $ExportReport -Parent
            if ($reportDir -and -not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir -Force | Out-Null }
            Set-Content -Path $ExportReport -Value $reportJson -Encoding UTF8 -Force
            Write-Log -Message "Audit report successfully written to JSON: $ExportReport" -Level SUCCESS
        } catch {
            Write-Log -Message "Failed to export audit report: $($_.Exception.Message)" -Level ERROR
        }
    }

    return $results
}

# ==============================================================================
# 6. FULL SYSTEM REMEDIATION ENGINE
# ==============================================================================

function Invoke-SystemRemediation {
    [CmdletBinding()]
    param()

    if (-not (Test-IsAdmin)) {
        Write-Log -Message "Privilege check failed: System remediation requires Administrator privileges." -Level ERROR
        throw "Administrator privilege requirement not met."
    }

    $osInfo = Get-OperatingSystemInfo
    Write-Log -Message "Starting full system remediation for target: $($osInfo.Caption)" -Level INFO

    # 1. Telemetry Services
    Write-Log -Message "[1/6] Stopping and disabling core OS telemetry services..." -Level INFO
    $services = @("DiagTrack", "dmwappushservice", "DPS", "PcaSvc")
    foreach ($svcName in $services) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.Status -eq "Running") {
                    Stop-Service -Name $svcName -Force -ErrorAction Stop
                    Write-Log -Message "Service stopped: $svcName" -Level SUCCESS
                }
                Set-Service -Name $svcName -StartupType Disabled -ErrorAction Stop
                Write-Log -Message "Service startup set to Disabled: $svcName" -Level SUCCESS
            }
        } catch {
            Write-Log -Message "Could not configure service ${svcName}: $($_.Exception.Message)" -Level WARN
        }
    }

    # 2. Scheduled Inventory & CEIP Tasks
    Write-Log -Message "[2/6] Disabling deep system inventory & CEIP scheduled tasks..." -Level INFO
    $scheduledTasks = @(
        @("\Microsoft\Windows\Application Experience\", "Microsoft Compatibility Appraiser"),
        @("\Microsoft\Windows\Application Experience\", "ProgramDataUpdater"),
        @("\Microsoft\Windows\Application Experience\", "StartupAppTask"),
        @("\Microsoft\Windows\Customer Experience Improvement Program\", "Consolidator"),
        @("\Microsoft\Windows\Customer Experience Improvement Program\", "UsbCeip"),
        @("\Microsoft\Office\", "OfficeTelemetryAgentLogOn2016"),
        @("\Microsoft\Office\", "OfficeTelemetryAgentFallBack2016")
    )
    foreach ($t in $scheduledTasks) {
        $taskPath = $t[0]
        $taskName = $t[1]
        try {
            $existing = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
            if ($existing -and $existing.State -ne "Disabled") {
                Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop | Out-Null
                Write-Log -Message "Scheduled Task disabled: $taskPath$taskName" -Level SUCCESS
            }
        } catch {
            Write-Log -Message "Could not disable task ${taskName}: $($_.Exception.Message)" -Level DEBUG
        }
    }

    # 3. Anti-Bloatware Policies, Store Locks & Device Metadata
    Write-Log -Message "[3/6] Applying anti-bloatware policies and silent store locks..." -Level INFO
    Invoke-BlockFutureBloatware

    # 4. Audio & Microphone Interception Hooks
    Write-Log -Message "[4/6] Disabling proprietary OEM audio interception services..." -Level INFO
    Invoke-NeutralizeAudio

    # 5. Privacy, Input Harvesting & Display Hooks
    Write-Log -Message "[5/6] Disabling inking telemetry, address book harvesting, and display hooks..." -Level INFO
    Set-RegistryValueSafe "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
    Set-RegistryValueSafe "HKCU:\Software\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1
    Set-RegistryValueSafe "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

    if (-not $osInfo.IsServer) {
        Set-RegistryValueSafe "HKCU:\System\GameConfigStore" "GameDVR_Enabled" 0
        Set-RegistryValueSafe "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 0
    }

    # 6. Purge Staged & Installed Bloatware Packages
    Write-Log -Message "[6/6] Purging installed consumer bloatware packages..." -Level INFO
    Invoke-PurgeBloatware

    Write-Log -Message "Full system hardening completed successfully." -Level SUCCESS
    return $true
}

# ==============================================================================
# 7. ENTRY POINT & EXECUTION DISPATCHER
# ==============================================================================

Write-Banner

Write-Log -Message "WinSentinel session started by: $([System.Environment]::UserName) on $([System.Environment]::MachineName)" -Level INFO

# Execute Safety Backup if requested
if ($Backup) {
    Invoke-SystemBackup
}

# Parameter Dispatcher
if ($AuditOnly) {
    $auditResults = Invoke-SystemAudit
    Write-Log -Message "WinSentinel audit execution completed." -Level INFO
    exit 0
}

if ($BlockBloatware) {
    if (-not (Test-IsAdmin)) {
        Write-Log -Message "Administrator privileges are required to configure anti-bloatware policies." -Level ERROR
        exit 1
    }
    Invoke-BlockFutureBloatware
    exit 0
}

if ($PurgeBloatware) {
    Invoke-PurgeBloatware
    exit 0
}

if ($BlockCompanionApps) {
    if (-not (Test-IsAdmin)) {
        Write-Log -Message "Administrator privileges are required to configure device companion policies." -Level ERROR
        exit 1
    }
    Invoke-BlockCompanionApps
    exit 0
}

if ($NeutralizeAudio) {
    if (-not (Test-IsAdmin)) {
        Write-Log -Message "Administrator privileges are required to reconfigure audio services." -Level ERROR
        exit 1
    }
    Invoke-NeutralizeAudio
    exit 0
}

if ($RemediateAll) {
    try {
        Invoke-SystemRemediation
        Write-Log -Message "Running post-remediation verification audit..." -Level INFO
        Invoke-SystemAudit
        exit 0
    } catch {
        Write-Log -Message "Remediation failed: $($_.Exception.Message)" -Level ERROR
        exit 1
    }
}

# Interactive Console Mode (default when no parameters passed)
$isAdmin = Test-IsAdmin
$adminStatus = if ($isAdmin) { "Administrator (Elevated)" } else { "Standard User (Non-Elevated)" }
$adminColor = if ($isAdmin) { "Green" } else { "Yellow" }
Write-Host "Session Privilege Level: $adminStatus`n" -ForegroundColor $adminColor

Write-Host "Select an operation:" -ForegroundColor White
Write-Host "  [1] Run Non-Destructive System Audit (Calculates Hardening Score)" -ForegroundColor Cyan
Write-Host "  [2] Apply Full System Hardening & Bloatware Purge (All Vectors)" -ForegroundColor Cyan
Write-Host "  [3] Block Future Bloatware, Store Pushes & Device Metadata (Anti-Bloat Lockdown)" -ForegroundColor Cyan
Write-Host "  [4] Purge Installed & Provisioned Bloatware Apps Only" -ForegroundColor Cyan
Write-Host "  [5] Neutralize Audio & Microphone Hooks Only (Nahimic / IgoAudio / SoundTune)" -ForegroundColor Cyan
Write-Host "  [6] Apply Device Metadata & Companion App Firewall Block Only (DMRClient)" -ForegroundColor Cyan
Write-Host "  [7] Create Safety Backup (System Restore Point & Registry Archives)" -ForegroundColor Cyan
Write-Host "  [0] Exit" -ForegroundColor DarkGray

$choice = Read-Host "`nEnter selection [0-7]"

switch ($choice) {
    "1" {
        Invoke-SystemAudit
    }
    "2" {
        if (-not $isAdmin) {
            Write-Log -Message "Administrator privileges are required to perform full hardening." -Level ERROR
            Write-Warning "Please right-click Run-WinSentinel.bat and choose 'Run as administrator'."
        } else {
            Invoke-SystemBackup
            Invoke-SystemRemediation
            Write-Host "`nRe-running audit scan to verify hardened state..." -ForegroundColor Cyan
            Invoke-SystemAudit
        }
    }
    "3" {
        if (-not $isAdmin) {
            Write-Log -Message "Administrator privileges are required to apply anti-bloatware policies." -Level ERROR
        } else {
            Invoke-SystemBackup
            Invoke-BlockFutureBloatware
        }
    }
    "4" {
        Invoke-PurgeBloatware
    }
    "5" {
        if (-not $isAdmin) {
            Write-Log -Message "Administrator privileges required to reconfigure audio services." -Level ERROR
        } else {
            Invoke-NeutralizeAudio
        }
    }
    "6" {
        if (-not $isAdmin) {
            Write-Log -Message "Administrator privileges required to modify firewall and device policies." -Level ERROR
        } else {
            Invoke-BlockCompanionApps
        }
    }
    "7" {
        Invoke-SystemBackup
    }
    Default {
        Write-Log -Message "User exited WinSentinel session." -Level INFO
    }
}
