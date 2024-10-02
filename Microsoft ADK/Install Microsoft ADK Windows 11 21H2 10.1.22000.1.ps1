#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install Microsoft ADK Windows 11 21H2 10.1.22000.1
.LINK
https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    Write-Host -Message 'WinGet is already installed.'
}
else {
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -Verbose
    }
    catch {
        Write-Error -Message 'WinGet could not be installed.'
    }
}

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Show package information
    # winget show --id Microsoft.WindowsADK
    
    # Show version information
    # winget show --id Microsoft.WindowsADK --versions
    
    # Install
    winget install --id Microsoft.WindowsADK --version 10.1.22000.1 --exact --accept-source-agreements --accept-package-agreements

    # Show package information
    # winget show --id Microsoft.ADKPEAddon
    
    # Show version information
    # winget show --id Microsoft.ADKPEAddon --versions
    
    # Install
    winget install --id Microsoft.ADKPEAddon --version 10.1.22000.1 --exact --accept-source-agreements --accept-package-agreements
    
    # Bugfix for MDT Windows PE x86 MMC snap-in error
    if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
        New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
    }
}
else {
    Write-Error -Message 'WinGet is not installed.'
}