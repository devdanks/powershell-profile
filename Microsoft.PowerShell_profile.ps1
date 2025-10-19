### Personal PowerShell Profile
### Version 1.0 – Custom Build

#Requires -Version 5.1

<#
.SYNOPSIS
    A powerful yet beginner-friendly PowerShell profile with productivity enhancements.

.DESCRIPTION
    This profile enhances PowerShell with:
    - Custom prompt and window title
    - Syntax highlighting and command prediction
    - Useful shortcuts and utility functions
    - Git integration and shortcuts
    - Automatic module management
    - File and system utilities
    - Custom help system
    
    For beginners: Run 'Show-Help' to see all available commands.
    For advanced users: The profile supports extensive customization.
    
    Note: Automatic profile updates from GitHub have been disabled.

.NOTES
    Author: Your Name
    Version: 1.0
    Last Updated: 2025-10-19
#>

#region Configuration
<#
Central configuration table – edit values here to customize behavior

For beginners:
- DebugMode: Set to $true to see detailed information about what the profile is doing
- UpdateIntervalDays: How often to check for profile updates (7 = weekly, -1 = every time)
- RepoRoot: Where to download profile updates from (change this to your own repository)
- LogLevel: Controls how much information is displayed (Debug, Info, Warning, Error)
#>
$script:Config = @{
    DebugMode          = $false          # Set $true for verbose debug output
    UpdateIntervalDays = 7               # Days between automatic update checks (‑1 = always)
    RepoRoot           = "https://raw.githubusercontent.com/devdanks/powershell-profile"   # Your own repo for future updates
    TimeFilePath       = "$env:USERPROFILE\Documents\PowerShell\LastExecutionTime.txt"
    LogLevel           = "Info"          # Minimum level of messages to display (Debug, Info, Warning, Error)
    MaxRetries         = 3               # How many times to retry failed operations
    TimeoutSeconds     = 30              # How long to wait for network operations (in seconds)
}
#endregion

#region Initialise Overrides
function Initialize-Configuration {
    [CmdletBinding()]
    param()
    # Environment‑variable overrides (highest priority)
    if ($env:PROFILE_DEBUG) { $script:Config.DebugMode = [bool]::Parse($env:PROFILE_DEBUG) }

    # Profile‑local variable overrides (if defined in $PROFILE before this script runs)
    if (Get-Variable -Name "debug_Override" -ErrorAction SilentlyContinue) {
        $script:Config.DebugMode = $debug_Override
    }
    if (Get-Variable -Name "repo_root_Override" -ErrorAction SilentlyContinue) {
        $script:Config.RepoRoot = $repo_root_Override
    }
    if (Get-Variable -Name "timeFilePath_Override" -ErrorAction SilentlyContinue) {
        $script:Config.TimeFilePath = $timeFilePath_Override
    }
    if (Get-Variable -Name "updateInterval_Override" -ErrorAction SilentlyContinue) {
        $script:Config.UpdateIntervalDays = $updateInterval_Override
    }
}
Initialize-Configuration
#endregion

#region Logging & Debugging
function Write-ProfileLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Debug','Info','Warning','Error')][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [Parameter()][System.Management.Automation.ErrorRecord]$ErrorRecord = $null
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $log = "[$timestamp] [$Level] $Message"

    if ($Level -eq 'Debug' -and -not $script:Config.DebugMode) { return }

    switch ($Level) {
        'Debug'   { Write-Verbose $log -Verbose:$script:Config.DebugMode }
        'Info'    { Write-Host $log -ForegroundColor Green }
        'Warning' { Write-Warning $log }
        'Error'   {
            if ($ErrorRecord) { Write-Error -Message $log -ErrorRecord $ErrorRecord }
            else               { Write-Error $log }
        }
    }
}

function Show-DebugBanner {
    if ($script:Config.DebugMode) {
        $banner = @"
#######################################
#           DEBUG MODE ENABLED         #
#   This is a development build only  #
#   Run Update-Profile to refresh      #
#######################################
"@
        Write-Host $banner -ForegroundColor Red
        Write-ProfileLog -Level Debug -Message "Debug mode active"
    }
}
Show-DebugBanner
#endregion

#region System Settings
# Opt‑out of telemetry when running as Administrator
try {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT','true',
            [System.EnvironmentVariableTarget]::Machine)
        Write-ProfileLog -Level Info -Message "Telemetry opt‑out set (admin context)"
    }
} catch {
    Write-ProfileLog -Level Warning -Message "Failed to set telemetry opt‑out: $_"
}

# Simple connectivity test – used by update functions
function Test-InternetConnectivity {
    [CmdletBinding()] param()
    try {
        $ok = Test-Connection -ComputerName "github.com" -Count 1 -Quiet -TimeoutSeconds 1
        Write-ProfileLog -Level Debug -Message "Internet connectivity: $ok"
        return $ok
    } catch {
        Write-ProfileLog -Level Warning -Message "Connectivity test failed: $_"
        return $false
    }
}
$script:CanConnect = Test-InternetConnectivity
#endregion

#region Module Management
function Install-ProfileModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][string]$MinimumVersion = "0.0.0"
    )
    # Helper to install via Scoop if available
    function Install-ViaScoop {
        param([string]$PkgName)
        if (Get-Command -Name scoop -ErrorAction SilentlyContinue) {
            Write-ProfileLog -Level Info -Message "Attempting to install $PkgName via Scoop"
            try {
                scoop install $PkgName -g | Out-Null
                Write-ProfileLog -Level Info -Message "Scoop installed $PkgName"
                return $true
            } catch {
                Write-ProfileLog -Level Warning -Message "Scoop failed to install ${PkgName}: $_"
                return $false
            }
        }
        return $false
    }

    try {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Write-ProfileLog -Level Info -Message "Installing module $Name"
            # Prefer Scoop for PowerShell modules if the appropriate bucket is present
            $scoopInstalled = $false
            if (Get-Command -Name scoop -ErrorAction SilentlyContinue) {
                # Common Scoop bucket for PowerShell modules is 'extras' or 'pwsh-modules'
                $possibleBuckets = @('extras', 'pwsh-modules')
                foreach ($bucket in $possibleBuckets) {
                    if (scoop bucket list | Select-String -Pattern $bucket -Quiet) {
                        $scoopPkg = "$bucket/$Name"
                        $scoopInstalled = Install-ViaScoop -PkgName $scoopPkg
                        if ($scoopInstalled) { break }
                    }
                }
            }

            if (-not $scoopInstalled) {
                # Fallback to PowerShell Gallery
                $params = @{
                    Name               = $Name
                    Scope              = "CurrentUser"
                    Force              = $true
                    SkipPublisherCheck = $true
                    AllowClobber       = $true
                    ErrorAction        = "Stop"
                }
                if ($MinimumVersion -ne "0.0.0") { $params.MinimumVersion = $MinimumVersion }
                Install-Module @params
                Write-ProfileLog -Level Info -Message "Module $Name installed via PowerShell Gallery"
            }
        } else {
            Write-ProfileLog -Level Debug -Message "Module $Name already available"
        }
        return $true
    } catch {
        Write-ProfileLog -Level Error -Message "Failed to install module $Name" -ErrorRecord $_
        return $false
    }
}

function Import-ProfileModules {
    [CmdletBinding()] param()
    # Prefer Scoop for common utilities when available
    if (Get-Command -Name scoop -ErrorAction SilentlyContinue) {
        # Ensure the 'extras' bucket is added (contains many PowerShell modules)
        if (-not (scoop bucket list | Select-String -Pattern 'extras' -Quiet)) {
            Write-ProfileLog -Level Info -Message "Adding Scoop 'extras' bucket"
            scoop bucket add extras | Out-Null
        }
    }

    # Install Terminal-Icons via Install-ProfileModule (which now prefers Scoop)
    if (Install-ProfileModule -Name "Terminal-Icons") {
        Import-Module -Name "Terminal-Icons" -ErrorAction SilentlyContinue
        Write-ProfileLog -Level Info -Message "Terminal-Icons imported"
    }

    # Load Chocolatey profile if present (fallback for users who still use Chocolatey)
    $choco = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
    if (Test-Path $choco) {
        try {
            Import-Module $choco -ErrorAction Stop
            Write-ProfileLog -Level Info -Message "Chocolatey profile imported"
        } catch {
            Write-ProfileLog -Level Warning -Message "Failed to import Chocolatey profile: $_"
        }
    }
}
Import-ProfileModules
#endregion

#region Update Management
function Test-ProfileUpdateNeeded {
    [CmdletBinding()] param()
    try {
        if ($script:Config.UpdateIntervalDays -eq -1) { return $true }
        if (-not (Test-Path $script:Config.TimeFilePath)) { return $true }

        $last = [datetime]::ParseExact((Get-Content -Path $script:Config.TimeFilePath), 'yyyy-MM-dd', $null)
        $days = ((Get-Date) - $last).TotalDays
        Write-ProfileLog -Level Debug -Message "Days since last profile check: $days"
        return $days -gt $script:Config.UpdateIntervalDays
    } catch {
        Write-ProfileLog -Level Warning -Message "Error checking profile update interval: $_"
        return $true
    }
}

function Update-Profile {
    [CmdletBinding()] param()
    if (-not $script:CanConnect) {
        Write-ProfileLog -Level Warning -Message "No internet – skipping profile update"
        return
    }
    try {
        Write-ProfileLog -Level Info -Message "Fetching latest profile from $($script:Config.RepoRoot)"
        $url = "$($script:Config.RepoRoot)/master/Microsoft.PowerShell_profile.ps1"
        $temp = "$env:TEMP\Microsoft.PowerShell_profile.ps1"
        Invoke-RestMethod -Uri $url -OutFile $temp -ErrorAction Stop

        $oldHash = Get-FileHash $PROFILE -ErrorAction SilentlyContinue
        $newHash = Get-FileHash $temp

        if ($oldHash.Hash -ne $newHash.Hash) {
            Copy-Item -Path $temp -Destination $PROFILE -Force
            # Remove setup completion file when profile is updated to trigger setup wizard
            $setupFile = "$env:USERPROFILE\Documents\PowerShell\profile_setup_complete.txt"
            if (Test-Path $setupFile) {
                Remove-Item $setupFile -Force
            }
            Write-ProfileLog -Level Info -Message "Profile updated – restart your shell"
        } else {
            Write-ProfileLog -Level Info -Message "Profile already up‑to‑date"
        }
    } catch {
        Write-ProfileLog -Level Error -Message "Failed to update profile: $_"
    } finally {
        Remove-Item $temp -ErrorAction SilentlyContinue
    }
}
#endregion

#region Automatic Update Checks
# Disabled automatic update checks as per user request
# if (-not $script:Config.DebugMode -and (Test-ProfileUpdateNeeded)) {
#     Update-Profile
#     (Get-Date -Format 'yyyy-MM-dd') | Out-File -FilePath $script:Config.TimeFilePath -Encoding ASCII
# } elseif ($script:Config.DebugMode) {
#     Write-ProfileLog -Level Warning -Message "Skipping automatic update check (debug mode)"
# }
#endregion

#region Prompt & Window Title
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell $($PSVersionTable.PSVersion)$adminSuffix"

function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
#endregion

#region Utility Functions
function Test-CommandExists {
    param([string]$Cmd)
    return $null -ne (Get-Command $Cmd -ErrorAction SilentlyContinue)
}
#endregion

#region Editor Configuration
function Set-Editor {
    if (Get-Variable -Name "EDITOR_Override" -Scope Global -ErrorAction SilentlyContinue) {
        $Global:EDITOR = $EDITOR_Override
    } else {
        # Check for preferred editors: code first, then nano
        if (Test-CommandExists code) { 
            $Global:EDITOR = 'code' 
        } elseif (Test-CommandExists nano) { 
            $Global:EDITOR = 'nano' 
        } else {
            # If neither code nor nano is found, install nano via scoop
            Write-Host "Neither 'code' nor 'nano' found. Installing nano via scoop..." -ForegroundColor Yellow
            try {
                if (-not (Test-CommandExists scoop)) {
                    Write-Warning "Scoop not found. Please install VS Code or nano manually."
                    $Global:EDITOR = 'notepad'  # Fallback to notepad
                } else {
                    scoop install nano
                    if (Test-CommandExists nano) {
                        Write-Host "Nano installed successfully!" -ForegroundColor Green
                        $Global:EDITOR = 'nano'
                    } else {
                        Write-Warning "Failed to install nano. Falling back to notepad."
                        $Global:EDITOR = 'notepad'
                    }
                }
            } catch {
                Write-Warning "Error installing nano: $_. Falling back to notepad."
                $Global:EDITOR = 'notepad'
            }
        }
    }
    Set-Alias -Name vim -Value $Global:EDITOR -Scope Global -Force
}
Set-Editor

function Edit-Profile { 
    # Ensure we have a suitable editor before trying to open the profile
    if ([string]::IsNullOrEmpty($Global:EDITOR) -or -not (Test-CommandExists $Global:EDITOR) -or $Global:EDITOR -eq 'notepad') {
        Set-Editor  # Re-run editor detection
    }
    Write-Host "Opening profile with: $Global:EDITOR" -ForegroundColor Green
    & $Global:EDITOR $PROFILE.CurrentUserAllHosts 
}
Set-Alias -Name ep -Value Edit-Profile
#endregion

#region Helper Shortcuts
function touch($file) {
    <#
    .SYNOPSIS
        Creates an empty file or updates the timestamp of an existing file.
    
    .DESCRIPTION
        The touch function creates a new empty file if it doesn't exist, or updates
        the last write time of an existing file to the current time.
        
        For beginners: This is similar to the Linux 'touch' command.
    
    .PARAMETER file
        The name or path of the file to create or update.
    
    .EXAMPLE
        touch myfile.txt
        Creates an empty file named myfile.txt in the current directory.
    
    .EXAMPLE
        touch "C:\Users\YourName\Documents\test.txt"
        Creates an empty file at the specified path.
    #>
    if (-not $file) {
        Write-Host "Usage: touch <filename>" -ForegroundColor Yellow
        Write-Host "Example: touch myfile.txt" -ForegroundColor Cyan
        return
    }
    
    try {
        if (Test-Path $file) {
            # Update timestamp of existing file
            (Get-Item $file).LastWriteTime = Get-Date
            Write-Host "Updated timestamp for '$file'" -ForegroundColor Green
        } else {
            # Create new empty file
            "" | Out-File $file -Encoding ASCII
            Write-Host "Created file '$file'" -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to create or update file '$file': $_"
    }
}
function ff($name) {
    Get-ChildItem -Recurse -Filter "*${name}*" -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName }
}
function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }
function admin {
    if ($args.Count -gt 0) {
        $argList = $args -join ' '
        Start-Process wt -Verb RunAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
    } else { Start-Process wt -Verb RunAs }
}
Set-Alias -Name su -Value admin
function uptime {
    try {
        $boot = if ($PSVersionTable.PSVersion.Major -eq 5) {
            $raw = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
            [Management.ManagementDateTimeConverter]::ToDateTime($raw)
        } else {
            (Get-Uptime -Since)
        }
        $now = Get-Date
        $span = $now - $boot
        Write-Host ("Uptime: {0}d {1}h {2}m {3}s" -f $span.Days,$span.Hours,$span.Minutes,$span.Seconds) -ForegroundColor Cyan
    } catch { Write-Error "Failed to get uptime: $_" }
}
function reload-profile { 
    # Only remove the LastExecutionTime.txt file, preserve setup completion
    $timeFile = "$env:USERPROFILE\Documents\PowerShell\LastExecutionTime.txt"
    if (Test-Path $timeFile) {
        Remove-Item $timeFile -Force
    }
    & $PROFILE
}
function unzip($file) {
    $full = Get-ChildItem -Path $PWD -Filter $file | Select-Object -First 1 -ExpandProperty FullName
    Expand-Archive -Path $full -DestinationPath $PWD -Force
}
function hb($path) {
    if (-not (Test-Path $path)) { Write-Error "File not found: $path"; return }
    $content = Get-Content $path -Raw
    $uri = "http://bin.christitus.com/documents"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Post -Body $content -ErrorAction Stop
        $url = "http://bin.christitus.com/$($resp.key)"
        Set-Clipboard $url
        Write-Host "$url copied to clipboard."
    } catch { Write-Error "Upload failed: $_" }
}
function grep($regex,$dir=$null) {
    if ($dir) { Get-ChildItem $dir | Select-String $regex }
    else { $input | Select-String $regex }
}
function df { Get-Volume }
function sed($file,$find,$replace) {
    (Get-Content $file) -replace [regex]::Escape($find), $replace | Set-Content $file
}
function which($name) { (Get-Command $name).Definition }
function export($name,$value) { Set-Item -Force -Path "env:$name" -Value $value }
function pkill($name) { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
function pgrep($name) { Get-Process $name }
function head($Path,$n=10) { Get-Content $Path -Head $n }
function tail($Path,$n=10,[switch]$f) { Get-Content $Path -Tail $n -Wait:$f }
function nf($name) { New-Item -ItemType File -Path . -Name $name -Force }
function mkcd($dir) {
    <#
    .SYNOPSIS
        Create a directory and change to it.
    
    .DESCRIPTION
        The mkcd function creates a new directory and immediately changes to it.
        If the directory already exists, it simply changes to it.
        
        For beginners: This combines 'mkdir' and 'cd' into one command.
    
    .PARAMETER dir
        The name or path of the directory to create and change to.
    
    .EXAMPLE
        mkcd myproject
        Creates a directory named 'myproject' and changes to it.
    
    .EXAMPLE
        mkcd "C:\Users\YourName\Documents\Projects\MyApp"
        Creates the full path and changes to it.
    #>
    if (-not $dir) {
        Write-Host "Usage: mkcd <directory>" -ForegroundColor Yellow
        Write-Host "Example: mkcd myproject" -ForegroundColor Cyan
        return
    }
    
    try {
        # Create directory if it doesn't exist
        $newDir = New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop
        # Change to the directory
        Set-Location -Path $newDir.FullName
        Write-Host "Created and changed to directory: $($newDir.FullName)" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create or change to directory '$dir': $_"
    }
}
function trash($path) {
    <#
    .SYNOPSIS
        Move a file or directory to the Recycle Bin.
    
    .DESCRIPTION
        The trash function safely moves files or directories to the Recycle Bin
        instead of permanently deleting them.
        
        For beginners: This is a safer alternative to 'rm' or 'del' commands.
    
    .PARAMETER path
        The path to the file or directory to move to the Recycle Bin.
    
    .EXAMPLE
        trash myfile.txt
        Moves myfile.txt to the Recycle Bin.
    
    .EXAMPLE
        trash "C:\Users\YourName\Documents\OldFolder"
        Moves the OldFolder directory to the Recycle Bin.
    #>
    if (-not $path) {
        Write-Host "Usage: trash <path>" -ForegroundColor Yellow
        Write-Host "Example: trash myfile.txt" -ForegroundColor Cyan
        return
    }
    
    try {
        $full = (Resolve-Path $path).Path
        if (-not (Test-Path $full)) { 
            Write-Host "Path not found: $full" -ForegroundColor Red
            return 
        }
        $item = Get-Item $full
        $parent = if ($item.PSIsContainer) { $item.Parent.FullName } else { $item.DirectoryName }
        $shell = New-Object -ComObject 'Shell.Application'
        $shellItem = $shell.NameSpace($parent).ParseName($item.Name)
        $shellItem.InvokeVerb('delete')
        Write-Host "Moved '$full' to Recycle Bin." -ForegroundColor Green
    } catch {
        Write-Error "Failed to move '$path' to Recycle Bin: $_"
    }
}
function docs {
    $p = [Environment]::GetFolderPath("MyDocuments")
    Set-Location -Path $p
}
function dtop {
    $p = [Environment]::GetFolderPath("Desktop")
    Set-Location -Path $p
}
function k9($name) { Stop-Process -Name $name -ErrorAction SilentlyContinue }
function la { Get-ChildItem | Format-Table -AutoSize }
function ll { Get-ChildItem -Force | Format-Table -AutoSize }
function gs { git status }
function ga { git add . }
function gc($msg) { git commit -m $msg }
function gpush { git push }
function gpull { git pull }
function g { __zoxide_z github }
function gcl($repo) { git clone $repo }
function gcom($msg) { git add .; git commit -m $msg }
function lazyg($msg) { git add .; git commit -m $msg; git push }
function sysinfo { Get-ComputerInfo }
function flushdns { Clear-DnsClientCache; Write-Host "DNS cache flushed" }
function cpy($text) { Set-Clipboard $text }
function pst { Get-Clipboard }
#endregion

#region PSReadLine Configuration
$PSReadLineOptions = @{
    EditMode               = 'Windows'
    HistoryNoDuplicates    = $true
    HistorySearchCursorMovesToEnd = $true
    Colors = @{
        Command   = '#87CEEB'  # SkyBlue
        Parameter = '#98FB98'  # PaleGreen
        Operator  = '#FFB6C1'  # LightPink
        Variable  = '#DDA0DD'  # Plum
        String    = '#FFDAB9'  # PeachPuff
        Number    = '#B0E0E6'  # PowderBlue
        Type      = '#F0E68C'  # Khaki
        Comment   = '#D3D3D3'  # LightGray
        Keyword   = '#8367c7'  # Violet
        Error     = '#FF6347'  # Tomato
    }
    PredictionSource       = 'History'
    PredictionViewStyle    = 'ListView'
    BellStyle              = 'None'
}
Set-PSReadLineOption @PSReadLineOptions

# Custom key bindings
Set-PSReadLineKeyHandler -Key UpArrow          -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow        -Function HistorySearchForward
Set-PSReadLineKeyHandler -Key Tab              -Function MenuComplete
Set-PSReadLineKeyHandler -Chord 'Ctrl+d'      -Function DeleteChar
Set-PSReadLineKeyHandler -Chord 'Ctrl+w'      -Function BackwardDeleteWord
Set-PSReadLineKeyHandler -Chord 'Alt+d'       -Function DeleteWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow'  -Function BackwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+z'      -Function Undo
Set-PSReadLineKeyHandler -Chord 'Ctrl+y'      -Function Redo

# Prevent sensitive data from being stored in history
Set-PSReadLineOption -AddToHistoryHandler {
    param($line)
    $sensitive = @('password','secret','token','apikey','connectionstring')
    return -not ($sensitive | Where-Object { $line -match $_ })
}
#endregion

#region Argument Completers
$gitNpmDenoCompleter = {
    param($wordToComplete,$commandAst,$cursorPosition)
    $map = @{
        git = @('status','add','commit','push','pull','clone','checkout')
        npm = @('install','start','run','test','build')
        deno = @('run','compile','bundle','test','lint','fmt','cache','info','doc','upgrade')
    }
    $cmd = $commandAst.CommandElements[0].Value
    if ($map.ContainsKey($cmd)) {
        $map[$cmd] | Where-Object { $_ -like "$wordToComplete*" } |
            ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_, 'ParameterValue', $_) }
    }
}
Register-ArgumentCompleter -Native -CommandName git,npm,deno -ScriptBlock $gitNpmDenoCompleter

Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock {
    param($wordToComplete,$commandAst,$cursorPosition)
    dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object { [System.Management.Automation.CompletionResult]::new($_,$_, 'ParameterValue', $_) }
}
#endregion

#region Help Function
function Show-Help {
    $help = @"
$($PSStyle.Foreground.Cyan)Personal PowerShell Profile Help$($PSStyle.Reset)
$($PSStyle.Foreground.Yellow)===============================$($PSStyle.Reset)

$($PSStyle.Foreground.Green)Welcome to your enhanced PowerShell profile!$($PSStyle.Reset)
This profile adds many useful features to PowerShell while keeping it beginner-friendly.

Note: Automatic profile updates from GitHub have been disabled.

$($PSStyle.Foreground.Yellow)Getting Started$($PSStyle.Reset)
For beginners, try these commands first:
- $($PSStyle.Foreground.Cyan)docs$($PSStyle.Reset) – Go to your Documents folder
- $($PSStyle.Foreground.Cyan)dtop$($PSStyle.Reset) – Go to your Desktop
- $($PSStyle.Foreground.Cyan)ll$($PSStyle.Reset) – List files in current directory (like ls -la on Linux)
- $($PSStyle.Foreground.Cyan)touch filename$($PSStyle.Reset) – Create an empty file
- $($PSStyle.Foreground.Cyan)mkcd dirname$($PSStyle.Reset) – Create a directory and change to it

$($PSStyle.Foreground.Yellow)Profile Management$($PSStyle.Reset)
$($PSStyle.Foreground.Green)Update-Profile$($PSStyle.Reset) – Pull the latest version of this profile from your repo.
$($PSStyle.Foreground.Green)Edit-Profile$($PSStyle.Reset) – Open the profile in your preferred editor.
$($PSStyle.Foreground.Green)Reload-Profile$($PSStyle.Reset) – Reload the current session profile.
$($PSStyle.Foreground.Green)Show-Help$($PSStyle.Reset) – Show this help message.

$($PSStyle.Foreground.Yellow)Git Shortcuts$($PSStyle.Reset)
These shortcuts make Git easier to use:
gs   – git status (show repository status)
ga   – git add . (add all changes)
gc   – git commit -m <msg> (commit with message)
gpush– git push (upload changes)
gpull– git pull (download changes)
gcl  – git clone <repo> (download a repository)
gcom – git add . + git commit -m <msg>
lazyg– git add . + git commit -m <msg> + git push

$($PSStyle.Foreground.Yellow)File & System Utilities$($PSStyle.Reset)
cpy <text>   – Copy text to clipboard
pst          – Paste from clipboard
df           – Show disk volumes and free space
docs         – Go to Documents folder
dtop         – Go to Desktop
ep           – Edit profile (shortcut for Edit-Profile)
flushdns     – Clear DNS cache
sysinfo      – Show detailed system information
uptime       – Show system uptime
trash <path> – Move file/folder to Recycle Bin (safer than rm)
unzip <file> – Extract a zip file
ff <name>    – Find files by name (searches recursively)
which <cmd>  – Show the path to a command
nf <name>    – Create a new file

$($PSStyle.Foreground.Yellow)Text Processing$($PSStyle.Reset)
grep <pattern> [dir] – Search for text in files
head <file> [n]      – Show first n lines of file (default 10)
tail <file> [n]      – Show last n lines of file (default 10)
sed <file> <old> <new> – Replace text in a file

$($PSStyle.Foreground.Yellow)Process Management$($PSStyle.Reset)
pkill <name> – Kill processes by name
pgrep <name> – Find processes by name
k9 <name>    – Kill process by name (alias for pkill)

$($PSStyle.Foreground.Yellow)Advanced Features$($PSStyle.Reset)
admin [cmd]  – Run a command as administrator
su [cmd]     – Alias for admin
Get-PubIP    – Show your public IP address
hb <file>    – Upload file to hastebin (requires internet)

$($PSStyle.Foreground.Yellow)Tips for Beginners$($PSStyle.Reset)
1. Use $($PSStyle.Foreground.Cyan)Tab$($PSStyle.Reset) for auto-completion of commands and file paths
2. Use $($PSStyle.Foreground.Cyan)Up/Down arrows$($PSStyle.Reset) to navigate command history
3. Type part of a command and press $($PSStyle.Foreground.Cyan)Tab$($PSStyle.Reset) for menu completion
4. Use $($PSStyle.Foreground.Cyan)Ctrl+r$($PSStyle.Reset) to search through command history
5. Use $($PSStyle.Foreground.Cyan)Get-Help <command>$($PSStyle.Reset) for built-in PowerShell help

$($PSStyle.Foreground.Yellow)===============================$($PSStyle.Reset)
Run '$($PSStyle.Foreground.Magenta)Show-Help$($PSStyle.Reset)' anytime to see this help.
"@
    Write-Host $help
}

<#
.SYNOPSIS
    Shows a beginner-friendly help message with all available profile commands.

.DESCRIPTION
    Displays a formatted help message showing all custom functions and aliases
    added by this PowerShell profile. Organized by category for easier navigation.

.EXAMPLE
    Show-Help
    Shows the full help message.

.NOTES
    This function uses PSStyle formatting for colored output when available.
#>
function Get-ProfileHelp {
    Show-Help
}
#endregion

# Show a reminder on start‑up
Write-Host "$($PSStyle.Foreground.Yellow)Run 'Show-Help' for a quick reference of commands.$($PSStyle.Reset)"

<#
.SYNOPSIS
    Setup wizard for first-time users to configure the PowerShell profile.

.DESCRIPTION
    This interactive wizard helps beginners configure their PowerShell profile
    by guiding them through common settings and preferences.

.EXAMPLE
    Show-SetupWizard
    Runs the setup wizard to configure the profile.
#>
function Show-SetupWizard {
    Write-Host "=== PowerShell Profile Setup Wizard ===" -ForegroundColor Cyan
    Write-Host "This wizard will help you configure your PowerShell profile." -ForegroundColor Green
    Write-Host ""

    # Check if this is the first run
    $setupFile = "$env:USERPROFILE\Documents\PowerShell\profile_setup_complete.txt"
    if (Test-Path $setupFile) {
        Write-Host "Setup has already been completed." -ForegroundColor Yellow
        $response = Read-Host "Do you want to run the setup again? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            return
        }
    }

    Write-Host "Let's configure your profile:" -ForegroundColor Green
    Write-Host ""

    # Debug Mode
    Write-Host "1. Debug Mode" -ForegroundColor Cyan
    Write-Host "   Enable this to see detailed information about what the profile is doing." -ForegroundColor Gray
    $debugResponse = Read-Host "   Enable debug mode? (y/N)"
    $script:Config.DebugMode = ($debugResponse -eq 'y' -or $debugResponse -eq 'Y')
    Write-Host "   Debug mode set to: $($script:Config.DebugMode)" -ForegroundColor Green
    Write-Host ""

    # Update Settings (disabled)
    Write-Host "2. Update Settings" -ForegroundColor Cyan
    Write-Host "   Note: Automatic profile updates from GitHub have been disabled." -ForegroundColor Yellow
    Write-Host "   The update settings are preserved but will not be used." -ForegroundColor Gray
    Write-Host ""

    # Save setup completion
    "Setup completed on $(Get-Date)" | Out-File -FilePath $setupFile -Encoding ASCII

    Write-Host "Setup complete!" -ForegroundColor Green
    Write-Host "Run 'Show-Help' to see all available commands." -ForegroundColor Cyan
    Write-Host "Restart your PowerShell session to apply all changes." -ForegroundColor Yellow
}

# Run setup wizard on first use
# Check if setup has already been completed
$setupFile = "$env:USERPROFILE\Documents\PowerShell\profile_setup_complete.txt"
if (-not (Test-Path $setupFile)) {
    # Only prompt for setup if running in an interactive session
    if ([Environment]::UserInteractive) {
        Write-Host ""
        Write-Host "Welcome to your new PowerShell profile!" -ForegroundColor Green
        Write-Host "It looks like this is your first time using it." -ForegroundColor Yellow
        $response = Read-Host "Would you like to run the setup wizard? (Y/n)"
        if ($response -ne 'n' -and $response -ne 'N') {
            Show-SetupWizard
        } else {
            # Create the setup completion file even if user declines setup
            "Setup completed on $(Get-Date)" | Out-File -FilePath $setupFile -Encoding ASCII
        }
    }
}

# Add an alias to manually run the setup wizard
Set-Alias -Name setup-profile -Value Show-SetupWizard
