<#
.SYNOPSIS
    Installs your custom PowerShell profile (my_profile.ps1) and creates a backup of any existing profile.

.DESCRIPTION
    This script performs the same safe‑backup logic that the original
    `Invoke‑WinUtilInstallPSProfile` function used, but it is simplified
    for your own profile.  It:

    1. Detects the current user profile path ($PROFILE).
    2. If a profile already exists, copies it to "$PROFILE.bak" (unless a backup already exists).
    3. Copies the supplied custom profile (my_profile.ps1) to $PROFILE.
    4. Optionally restarts the current session.

.PARAMETER SourcePath
    Full path to the custom profile you want to install.  By default it points to
    a file named "my_profile.ps1" located in the same directory as this installer.

.PARAMETER RestartShell
    Switch to automatically reload the profile after installation.

.EXAMPLE
    .\Install-MyProfile.ps1
    # Installs the profile from the default location and leaves the current session unchanged.

.EXAMPLE
    .\Install-MyProfile.ps1 -RestartShell
    # Installs the profile and then reloads it in the current session.

.NOTES
    The script is deliberately minimal – it does not depend on external modules
    and works on any PowerShell version >= 5.1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = (Join-Path -Path $PSScriptRoot -ChildPath 'my_profile.ps1'),

    [switch]$RestartShell
)

function Write-InstallerLog {
    param(
        [ValidateSet('Info','Warning','Error')][string]$Level,
        [string]$Message
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = "[Installer $Level] $timestamp"
    switch ($Level) {
        'Info'    { Write-Host "$prefix $Message" -ForegroundColor Green }
        'Warning' { Write-Warning "$prefix $Message" }
        'Error'   { Write-Error   "$prefix $Message" }
    }
}

# Helper to install utilities via Scoop when available
function Install-ViaScoop {
    param([string]$PackageName)
    if (Get-Command -Name scoop -ErrorAction SilentlyContinue) {
        Write-InstallerLog -Level Info -Message "Installing $PackageName via Scoop"
        try {
            scoop install $PackageName -g | Out-Null
            Write-InstallerLog -Level Info -Message "$PackageName installed with Scoop"
            return $true
        } catch {
            Write-InstallerLog -Level Warning -Message "Scoop failed to install ${PackageName}: $_"
            return $false
        }
    }
    return $false
}

# Resolve the target profile path
$targetProfile = $PROFILE
Write-InstallerLog -Level Info -Message "Target profile: $targetProfile"

# Verify source profile exists
if (-not (Test-Path $SourcePath)) {
    Write-InstallerLog -Level Error -Message "Source profile not found at $SourcePath"
    exit 1
}

# If Scoop is present, ensure the 'extras' bucket (commonly used for PowerShell modules) is added
if (Get-Command -Name scoop -ErrorAction SilentlyContinue) {
    if (-not (scoop bucket list | Select-String -Pattern 'extras' -Quiet)) {
        Write-InstallerLog -Level Info -Message "Adding Scoop 'extras' bucket for module support"
        scoop bucket add extras | Out-Null
    }
}
Write-InstallerLog -Level Info -Message "Source profile: $SourcePath"

# Create backup if needed
$backupPath = "$targetProfile.bak"
if (Test-Path $targetProfile) {
    if (-not (Test-Path $backupPath)) {
        try {
            Copy-Item -Path $targetProfile -Destination $backupPath -Force
            Write-InstallerLog -Level Info -Message "Existing profile backed up to $backupPath"
        } catch {
            Write-InstallerLog -Level Error -Message "Failed to create backup: $_"
            exit 1
        }
    } else {
        Write-InstallerLog -Level Warning -Message "Backup already exists at $backupPath – skipping backup"
    }
} else {
    Write-InstallerLog -Level Info -Message "No existing profile found – no backup needed"
}

# Install the new profile
try {
    Copy-Item -Path $SourcePath -Destination $targetProfile -Force
    Write-InstallerLog -Level Info -Message "Custom profile installed to $targetProfile"
} catch {
    Write-InstallerLog -Level Error -Message "Failed to install custom profile: $_"
    exit 1
}

# Optionally reload the profile in the current session
if ($RestartShell) {
    try {
        & $targetProfile
        Write-InstallerLog -Level Info -Message "Profile reloaded in current session"
    } catch {
        # Suppress non‑critical errors that can arise from environment‑variable assignments
        # (e.g., Set‑Item receiving an array). Log the warning but do not abort the installer.
        Write-InstallerLog -Level Warning -Message "Profile reload produced non‑critical errors: $_"
    }
}