# Win1125H2_MSaccountremoval
Powershell code to remove ms account forcing from local accounts

Markdown

# Windows 11 Pro 25H2 — Remove Microsoft Account Prompts & M365 Apps

PowerShell scripts to remove Microsoft account sign-in prompts, nag screens, and pre-installed Microsoft 365 applications from **Windows 11 Pro 25H2**.

Windows 11 25H2 introduced aggressive new prompts pushing users to sign in with a Microsoft account. These scripts disable all known nag screens and optionally remove OneDrive, Teams, Outlook, and Microsoft 365 Office apps.

---

## What It Does

### Part 1: Remove Microsoft Account Prompts

| Action | Registry / Method |
|---|---|
| Block Microsoft account sign-in | `NoConnectedUser = 3` (Group Policy) |
| Disable SCOOBE "Let's finish setting up your device" | `ScoobeSystemSettingEnabled = 0` |
| Disable welcome experience after updates | `SubscribedContent-310093Enabled = 0` |
| Disable "Get tips and suggestions" | `SubscribedContent-338389Enabled = 0` |
| Disable "Suggest ways to finish setup" | `SubscribedContent-338388Enabled = 0` |
| Disable Start menu app suggestions | `SubscribedContent-338393/353694/353696 = 0` |
| Disable Microsoft Consumer Experiences | `DisableWindowsConsumerFeatures = 1` |
| Disable cloud-optimized content | `DisableCloudOptimizedContent = 1` |
| Disable Windows Spotlight features | `DisableWindowsSpotlightFeatures = 1` |
| Hide Settings app Home page (removes banner) | `SettingsPageVisibility = hide:home` |
| Disable Start menu account notifications (orange dot) | `Start_AccountNotifications = 0` |
| Block Microsoft account authentication prompt | `DisableUserAuth = 1` |
| Disable tailored experiences | `TailoredExperiencesWithDiagnosticDataEnabled = 0` |
| Disable scheduled setup tasks | Task Scheduler |
| Force Group Policy update | `gpupdate /force` |

### Part 2: Application Removal

| Application | Removal Method |
|---|---|
| OneDrive | `OneDriveSetup.exe /uninstall` + winget fallback + auto-install block |
| Microsoft Teams | MSIX removal + provisioned package removal + winget + Chat icon hide |
| Outlook (new/Store) | AppxPackage removal + provisioned package removal |
| Microsoft 365 / Office | ClickToRun removal + winget fallback + Store app removal |

### Part 3: Ms account removal from settings in 25H2

| Application | Removal Method |
|---|---|
| Settings | Stops Windows from asking to sing in to MS account |


---

## Requirements

- **Windows 11 Pro 25H2** (may also work on 24H2 and Enterprise editions)
- **PowerShell** running as **Administrator**
- Execution Policy must allow script execution (the script will guide you)

---

## Usage

### Quick Start

1. Download `Remove-MS-Account-Prompts-25H2.ps1`
2. Open **PowerShell as Administrator** (`Win + X` → `A`)
3. Allow script execution for the current session:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Navigate to the download folder and run:


Powershell

cd C:\Users\YourName\Downloads
.\Remove-MS-Account-Prompts-25H2.ps1
Confirm with Y when prompted

Restart your computer

### One-Liner (no download needed)

Powershell

powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\Remove-MS-Account-Prompts-25H2.ps1"
Create a Desktop Shortcut
Right-click Desktop → New → Shortcut

Target:

powershell.exe -ExecutionPolicy Bypass -File "C:\path\to\Remove-MS-Account-Prompts-25H2.ps1"
Right-click the shortcut → Properties → Advanced → check Run as administrator

Double-click to run

Manual Steps (Recommended After Running the Script)
Some settings cannot be changed via registry alone. After running the script:

Disable Additional Notifications
Go to Settings → System → Notifications

Scroll to the very bottom → Additional settings

Uncheck all boxes

Disable Recommendations & Offers
Go to Settings → Privacy & security

Find Recommendations and offers and disable all toggles

Disable File Explorer Sync Notifications
Open File Explorer → click ⋯ → Options

Go to View tab

Uncheck Show sync provider notifications

Click OK

Restore
To undo all changes and reinstall removed applications:

Open PowerShell as Administrator

Run:


Powershell

Set-ExecutionPolicy Bypass -Scope Process -Force
.\Restore-MS-Account-Prompts-25H2.ps1
Restart your computer

The restore script will:

Re-enable Microsoft account sign-in

Restore all notification and suggestion settings

Restore the Settings Home page

Re-enable Microsoft Consumer Experiences

Reinstall OneDrive, Teams, and Outlook via winget

Provide instructions for manual M365/Office reinstallation

Note: You can also use the System Restore point created by the removal script. Go to Control Panel → Recovery → Open System Restore.

Files
File	Description
Remove-MS-Account-Prompts-25H2.ps1	Main script — removes prompts and apps
Restore-MS-Account-Prompts-25H2.ps1	Restore script — reverts all changes


Important Notes
Microsoft Store may stop working properly since Microsoft account sign-in is blocked at system level

OneDrive sync will stop — make sure your files are backed up locally before running

If the device is managed by Intune / Azure AD / MDM, group policies may override these settings

The script creates a System Restore point before making changes

The script asks for confirmation (Y/N) before proceeding — nothing is changed without your approval

All actions are logged in the PowerShell console with color-coded status messages

Troubleshooting
"Running scripts is disabled on this system"
Run this before executing the script:


Powershell

Set-ExecutionPolicy Bypass -Scope Process -Force
This only affects the current PowerShell session and resets when you close the window.

"Set-ItemProperty is not recognized" or similar errors
This happens when copying code from chat/web — lines break and commands get corrupted. Always use the downloaded .ps1 files instead of copy-pasting.

Prompts still appear after running the script
Make sure you restarted the computer

Complete the manual steps listed above

Run gpupdate /force in an admin PowerShell

Check if the device is managed by IT (MDM/Intune policies can override local settings)

Microsoft 365/Office was not removed
The ClickToRun removal depends on the installed Office product ID. If automatic removal fails:

Go to Settings → Apps → Installed apps

Find Microsoft 365 or Microsoft Office

Click ⋯ → Uninstall

Tested On
Windows 11 Pro 25H2 (Build 26100)

Fresh install + upgraded systems

Finnish and English locale

License
MIT License — free to use, modify, and distribute.

Author
Ville Huhtiniemi
