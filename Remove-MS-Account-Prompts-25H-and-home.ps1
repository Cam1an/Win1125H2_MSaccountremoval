## 2. Remove-MS-Account-Prompts-25H2.ps1

```powershell
# ============================================================
# Remove Microsoft account prompts + M365 applications
# Windows 11 Pro 25H2
# Run PowerShell as ADMINISTRATOR
# ============================================================

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Remove Microsoft account prompts + M365 app removal"      -ForegroundColor Cyan
Write-Host " Windows 11 Pro 25H2"                                      -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: Please run this script as Administrator!" -ForegroundColor Red
    Write-Host "Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    Read-Host "Press Enter to close"
    exit 1
}

Write-Host "WARNING: This script will remove the following:" -ForegroundColor Red
Write-Host "  - Microsoft account sign-in prompts (all known 25H2 nags)" -ForegroundColor White
Write-Host "  - Finish setting up your device (SCOOBE)" -ForegroundColor White
Write-Host "  - Microsoft consumer experiences (app suggestions)" -ForegroundColor White
Write-Host "  - Start menu orange dot notification" -ForegroundColor White
Write-Host "  - OneDrive" -ForegroundColor White
Write-Host "  - Microsoft 365 / Office apps (Word, Excel, PowerPoint etc.)" -ForegroundColor White
Write-Host "  - Outlook (new + classic)" -ForegroundColor White
Write-Host "  - Microsoft Teams" -ForegroundColor White
Write-Host ""
$confirm = Read-Host "Do you want to continue? (Y = yes, N = no)"
if ($confirm -notin @("Y","y","Yes","yes")) {
    Write-Host "Cancelled." -ForegroundColor Yellow
    Read-Host "Press Enter to close"
    exit 0
}

Write-Host ""
$step = 0

# ============================================================
# PART 1: REMOVE ALL MICROSOFT ACCOUNT PROMPTS (25H2)
# ============================================================

$step++
Write-Host "[$step/14] Creating system restore point..." -ForegroundColor Yellow
try {
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "Before MS account and app removal" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
    Write-Host "        Restore point created." -ForegroundColor Green
} catch {
    Write-Host "        Restore point creation skipped (not critical)." -ForegroundColor DarkYellow
}

$step++
Write-Host "[$step/14] Blocking Microsoft accounts (NoConnectedUser = 3)..." -ForegroundColor Yellow
$p1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if (-not (Test-Path $p1)) {
    New-Item -Path $p1 -Force | Out-Null
}
Set-ItemProperty -Path $p1 -Name "NoConnectedUser" -Value 3 -Type DWord -Force
Write-Host "        Microsoft accounts blocked." -ForegroundColor Green

$step++
Write-Host "[$step/14] Disabling SCOOBE finish setup nag..." -ForegroundColor Yellow
$p2 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement"
if (-not (Test-Path $p2)) {
    New-Item -Path $p2 -Force | Out-Null
}
Set-ItemProperty -Path $p2 -Name "ScoobeSystemSettingEnabled" -Value 0 -Type DWord -Force
try {
    reg load "HKU\TEMP" "C:\Users\Default\NTUSER.DAT" 2>$null
    reg add "HKU\TEMP\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f 2>$null
    reg unload "HKU\TEMP" 2>$null
    Write-Host "        SCOOBE disabled (current + default user)." -ForegroundColor Green
} catch {
    Write-Host "        SCOOBE disabled (current user)." -ForegroundColor Green
}

$step++
Write-Host "[$step/14] Disabling welcome experience, tips and suggestions..." -ForegroundColor Yellow
$p3 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
if (-not (Test-Path $p3)) {
    New-Item -Path $p3 -Force | Out-Null
}
Set-ItemProperty -Path $p3 -Name "SubscribedContent-310093Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SubscribedContent-338389Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SubscribedContent-338388Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SubscribedContent-338393Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SubscribedContent-353694Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SubscribedContent-353696Enabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SoftLandingEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $p3 -Name "SystemPaneSuggestionsEnabled" -Value 0 -Type DWord -Force
Write-Host "        All notification/suggestion settings disabled." -ForegroundColor Green

$step++
Write-Host "[$step/14] Disabling Microsoft Consumer Experiences..." -ForegroundColor Yellow
$p4 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $p4)) {
    New-Item -Path $p4 -Force | Out-Null
}
Set-ItemProperty -Path $p4 -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $p4 -Name "DisableSoftLanding" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $p4 -Name "DisableCloudOptimizedContent" -Value 1 -Type DWord -Force
$p5 = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
if (-not (Test-Path $p5)) {
    New-Item -Path $p5 -Force | Out-Null
}
Set-ItemProperty -Path $p5 -Name "DisableWindowsSpotlightFeatures" -Value 1 -Type DWord -Force
Set-ItemProperty -Path $p5 -Name "ConfigureWindowsSpotlight" -Value 2 -Type DWord -Force
Write-Host "        Microsoft Consumer Experiences disabled." -ForegroundColor Green

$step++
Write-Host "[$step/14] Hiding Settings Home page and blocking account banner..." -ForegroundColor Yellow
$p6 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
if (-not (Test-Path $p6)) {
    New-Item -Path $p6 -Force | Out-Null
}
Set-ItemProperty -Path $p6 -Name "SettingsPageVisibility" -Value "hide:home" -Type String -Force
$p7 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
Set-ItemProperty -Path $p7 -Name "Start_AccountNotifications" -Value 0 -Type DWord -Force
$p8 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.HelloFace"
if (-not (Test-Path $p8)) {
    New-Item -Path $p8 -Force | Out-Null
}
Set-ItemProperty -Path $p8 -Name "Enabled" -Value 0 -Type DWord -Force
Write-Host "        Settings Home page hidden, account banner blocked." -ForegroundColor Green

$step++
Write-Host "[$step/14] Blocking MS account auth and tailored experiences..." -ForegroundColor Yellow
$p9 = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftAccount"
if (-not (Test-Path $p9)) {
    New-Item -Path $p9 -Force | Out-Null
}
Set-ItemProperty -Path $p9 -Name "DisableUserAuth" -Value 1 -Type DWord -Force
$p10 = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
if (-not (Test-Path $p10)) {
    New-Item -Path $p10 -Force | Out-Null
}
Set-ItemProperty -Path $p10 -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value 0 -Type DWord -Force
Write-Host "        MS account auth and tailored experiences blocked." -ForegroundColor Green

$step++
Write-Host "[$step/14] Disabling scheduled setup tasks..." -ForegroundColor Yellow
$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
    "\Microsoft\Windows\Setup\SetupCleanupTask",
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
)
foreach ($task in $tasks) {
    try {
        Disable-ScheduledTask -TaskName $task -ErrorAction Stop | Out-Null
        Write-Host "        Disabled: $task" -ForegroundColor Green
    } catch {
        Write-Host "        Skipped: $task" -ForegroundColor DarkYellow
    }
}

# ============================================================
# PART 2: APPLICATION REMOVAL
# ============================================================

$step++
Write-Host "[$step/14] Removing OneDrive..." -ForegroundColor Yellow
Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue | Stop-Process -Force
$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path $runKey -Name "OneDrive" -Force -ErrorAction SilentlyContinue
$odSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
if (-not (Test-Path $odSetup)) {
    $odSetup = "$env:SystemRoot\System32\OneDriveSetup.exe"
}
if (Test-Path $odSetup) {
    Start-Process $odSetup -ArgumentList "/uninstall" -Wait -NoNewWindow
    Write-Host "        OneDrive removed (setup installer)." -ForegroundColor Green
} else {
    try {
        winget uninstall "Microsoft.OneDrive" --silent --accept-source-agreements 2>$null
        Write-Host "        OneDrive removed (winget)." -ForegroundColor Green
    } catch {
        Write-Host "        OneDrive not found or already removed." -ForegroundColor DarkYellow
    }
}
$p11 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
if (-not (Test-Path $p11)) {
    New-Item -Path $p11 -Force | Out-Null
}
Set-ItemProperty -Path $p11 -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force
Write-Host "        OneDrive auto-install blocked." -ForegroundColor Green

$step++
Write-Host "[$step/14] Removing Microsoft Teams..." -ForegroundColor Yellow
Get-Process -Name "ms-teams","Teams" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$tPkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*MicrosoftTeams*" -or $_.Name -like "*MSTeams*" }
foreach ($pkg in $tPkgs) {
    try {
        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
        Write-Host "        Removed: $($pkg.Name)" -ForegroundColor Green
    } catch {
        Write-Host "        Could not remove MSIX: $($pkg.Name)" -ForegroundColor DarkYellow
    }
}
$tProv = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*MicrosoftTeams*" -or $_.DisplayName -like "*MSTeams*" }
foreach ($pkg in $tProv) {
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
        Write-Host "        Provisioned removed: $($pkg.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Host "        Skipped provisioned: $($pkg.DisplayName)" -ForegroundColor DarkYellow
    }
}
try {
    winget uninstall "Microsoft Teams" --silent --accept-source-agreements 2>$null
    Write-Host "        Teams removed (winget)." -ForegroundColor Green
} catch {
    Write-Host "        Winget Teams removal skipped." -ForegroundColor DarkYellow
}
$p12 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
if (-not (Test-Path $p12)) {
    New-Item -Path $p12 -Force | Out-Null
}
Set-ItemProperty -Path $p12 -Name "ChatIcon" -Value 3 -Type DWord -Force
Write-Host "        Teams Chat icon hidden from taskbar." -ForegroundColor Green

$step++
Write-Host "[$step/14] Removing Outlook (new + Store version)..." -ForegroundColor Yellow
$oPkgs = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*OutlookForWindows*" -or $_.Name -like "*microsoft.windowscommunicationsapps*" }
foreach ($pkg in $oPkgs) {
    try {
        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
        Write-Host "        Removed: $($pkg.Name)" -ForegroundColor Green
    } catch {
        Write-Host "        Skipped: $($pkg.Name)" -ForegroundColor DarkYellow
    }
}
$oProv = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like "*OutlookForWindows*" -or $_.DisplayName -like "*windowscommunicationsapps*" }
foreach ($pkg in $oProv) {
    try {
        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName -ErrorAction Stop | Out-Null
        Write-Host "        Provisioned removed: $($pkg.DisplayName)" -ForegroundColor Green
    } catch {
        Write-Host "        Skipped provisioned: $($pkg.DisplayName)" -ForegroundColor DarkYellow
    }
}
Write-Host "        Outlook (Store/new) processed." -ForegroundColor Green

$step++
Write-Host "[$step/14] Removing Microsoft 365 / Office applications..." -ForegroundColor Yellow
$officeC2R = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*Microsoft 365*" -or $_.DisplayName -like "*Microsoft Office*" }
$officePath = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"
if ($officeC2R -and (Test-Path $officePath)) {
    Write-Host "        Found installed Office/M365. Removing..." -ForegroundColor White
    try {
        $c2rArgs = "scenario=install scenariosubtype=ARP sourcetype=None productstoremove=O365ProPlusRetail.16_fi-fi_x-none culture=fi-fi version.16=0.0.0.0"
        Start-Process $officePath -ArgumentList $c2rArgs -Wait -NoNewWindow -ErrorAction Stop
        Write-Host "        Office/M365 removed (ClickToRun)." -ForegroundColor Green
    } catch {
        Write-Host "        ClickToRun removal failed. Try manual removal:" -ForegroundColor DarkYellow
        Write-Host "        Settings -> Apps -> Installed apps -> Microsoft 365 -> Uninstall" -ForegroundColor White
    }
} else {
    $officeApps = @("Microsoft.Office","Microsoft.365")
    foreach ($app in $officeApps) {
        try {
            winget uninstall $app --silent --accept-source-agreements 2>$null
            Write-Host "        $app removed (winget)." -ForegroundColor Green
        } catch {
            Write-Host "        $app not found via winget." -ForegroundColor DarkYellow
        }
    }
}
$oStore = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*Microsoft.MicrosoftOfficeHub*" -or $_.Name -like "*Microsoft.Office.Desktop*" }
foreach ($pkg in $oStore) {
    try {
        Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
        Write-Host "        Removed Store app: $($pkg.Name)" -ForegroundColor Green
    } catch {
        Write-Host "        Skipped: $($pkg.Name)" -ForegroundColor DarkYellow
    }
}

$step++
Write-Host "[$step/14] Final cleanup and Group Policy update..." -ForegroundColor Yellow
$startupApps = @("Teams", "com.squirrel.Teams.Teams", "OneDrive", "Outlook")
foreach ($app in $startupApps) {
    Remove-ItemProperty -Path $runKey -Name $app -Force -ErrorAction SilentlyContinue
}
Write-Host "        Startup registry cleaned." -ForegroundColor Green
$cachePaths = @(
    "$env:LOCALAPPDATA\Microsoft\Teams",
    "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe"
)
foreach ($cpath in $cachePaths) {
    if (Test-Path $cpath) {
        Remove-Item -Path $cpath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "        Removed: $cpath" -ForegroundColor Green
    }
}
gpupdate /force 2>$null
Write-Host "        Group Policy updated." -ForegroundColor Green

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host " DONE! Please restart your computer."                       -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Removed/blocked:" -ForegroundColor Cyan
Write-Host "  [x] Microsoft account sign-in prompts" -ForegroundColor White
Write-Host "  [x] SCOOBE finish setup nag screen" -ForegroundColor White
Write-Host "  [x] Welcome experience, tips and suggestions" -ForegroundColor White
Write-Host "  [x] Microsoft Consumer Experiences" -ForegroundColor White
Write-Host "  [x] Settings app Home page and account banner" -ForegroundColor White
Write-Host "  [x] Start menu orange dot notification" -ForegroundColor White
Write-Host "  [x] MS account auth and tailored experiences" -ForegroundColor White
Write-Host "  [x] OneDrive" -ForegroundColor White
Write-Host "  [x] Microsoft Teams" -ForegroundColor White
Write-Host "  [x] Outlook (new/Store)" -ForegroundColor White
Write-Host "  [x] Microsoft 365 / Office apps" -ForegroundColor White
Write-Host ""
Read-Host "Press Enter to close"