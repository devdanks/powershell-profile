# PowerShell Profile AI Instructions

## Overview
This is a PowerShell profile based on Chris Titus Tech's template with override functionality. The profile provides Unix-like aliases, enhanced PSReadLine configuration, automatic updates, and utility functions for Windows PowerShell.

## Architecture & Override System

### Core Pattern: Override System
- **Base Profile**: Auto-updates from https://github.com/ChrisTitusTech/powershell-profile.git
- **Customization**: Use `Edit-Profile` to create `profile.ps1` with `_Override` suffixed variables/functions
- **Example Override**: `$EDITOR_Override = "code"` or `function Update-Profile_Override { ... }`

```powershell
# Override variables by appending _Override
$debug_Override = $true
$EDITOR_Override = "code"

# Override functions the same way
function Get-Theme_Override {
    oh-my-posh init pwsh --config "custom-theme.json" | Invoke-Expression
}
```

## Key Components

### Update System
- **Auto-check interval**: Controlled by `$updateInterval` (7 days default)
- **Debug mode**: Set `$debug = $true` to skip all auto-updates
- **Manual update**: Use `Update-Profile` and `Update-PowerShell` functions

### Editor Priority Chain
```powershell
code → nano → auto-install nano via scoop → notepad (fallback)
```

### Git Shortcuts Pattern
- Single letter commands: `gs`, `ga`, `gc`, `g` (zoxide github directory)
- Compound operations: `gcom` (add + commit), `lazyg` (add + commit + push)

## Development Workflows

### Profile Customization
1. Use `Edit-Profile` (alias: `ep`) to open custom profile
2. Add `_Override` suffix to any variable/function you want to customize
3. Reload with `reload-profile` or restart shell

### Testing Changes
```powershell
$debug_Override = $true  # Skip auto-updates during development
reload-profile           # Test changes immediately
```

### Adding New Functions
- Place in custom `profile.ps1` (not main profile - it auto-updates)
- Follow Unix-like naming convention where applicable
- Use proper error handling with `-ErrorAction SilentlyContinue`

## Conventions & Patterns

### Function Naming
- **Unix aliases**: `ls`, `grep`, `which`, `tail`, `head`, `df`
- **Short utilities**: `ff` (find files), `nf` (new file), `mkcd` (make & change directory)
- **System tools**: `admin`/`su`, `uptime`, `sysinfo`, `flushdns`

### Error Handling Pattern
```powershell
function example-function {
    try {
        # Main logic
    } catch {
        Write-Error "Description: $_"
    } finally {
        # Cleanup
    }
}
```

### Module Dependencies
- **Terminal-Icons**: Auto-installed if missing
- **oh-my-posh**: Uses cobalt2 theme by default
- **zoxide**: Auto-installed via winget if missing

## Integration Points

### External Tools
- **winget**: Used for PowerShell and zoxide installation
- **git**: Extensive alias integration
- **Windows Terminal**: Admin elevation with `wt -Verb runAs`
- **Chocolatey**: Auto-imports profile if available

### PSReadLine Configuration
- **Prediction**: HistoryAndPlugin with ListView style
- **Colors**: Pastel theme with specific hex values
- **Key bindings**: Emacs-style with Ctrl shortcuts
- **History**: Excludes sensitive data (passwords, tokens, etc.)

## File Locations
- **Main Profile**: `$PROFILE` (auto-managed, don't edit)
- **Custom Profile**: `$PROFILE.CurrentUserAllHosts` (your edits here)
- **Update Tracking**: `$env:USERPROFILE\Documents\PowerShell\LastExecutionTime.txt`

## Development Notes
- Profile updates are hash-checked to avoid unnecessary overwrites
- Debug mode prevents all auto-update behavior for development
- Custom completions registered for git, npm, deno, and dotnet
- All functions check for `_Override` variants before executing default behavior