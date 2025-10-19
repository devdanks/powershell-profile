# Personal PowerShell Profile

A powerful yet beginner-friendly PowerShell profile with productivity enhancements, based on Chris Titus Tech's template with custom modifications.

## Features

- **Custom prompt and window title**
- **Syntax highlighting and command prediction**
- **Useful shortcuts and utility functions**
- **Git integration and shortcuts**
- **Automatic module management**
- **File and system utilities**
- **Custom help system**

## Installation

1. Download the `Microsoft.PowerShell_profile.ps1` file
2. Place it in your PowerShell profile directory:
   ```powershell
   $PROFILE
   ```
3. Restart PowerShell
4. Run `Show-Help` to see all available commands

## Quick Start

For beginners, try these commands first:
- `docs` – Go to your Documents folder
- `dtop` – Go to your Desktop
- `ll` – List files in current directory (like ls -la on Linux)
- `touch filename` – Create an empty file
- `mkcd dirname` – Create a directory and change to it
- `Show-Help` – Display all available commands

## Git Shortcuts

- `gs` – git status
- `ga` – git add .
- `gc "message"` – git commit -m "message"
- `gpush` – git push
- `gpull` – git pull
- `gcom "message"` – add + commit in one command
- `lazyg "message"` – add + commit + push in one command

## Customization

The profile supports override functionality. Create your own `profile.ps1` file and use `_Override` suffixed variables/functions to customize behavior without modifying the main profile.

## Updates

The profile includes an update system. Use `Update-Profile` to pull the latest version from this repository.

## Author

Personal build based on Chris Titus Tech's PowerShell profile template.