#Requires -RunAsAdministrator
<#
.DESCRIPTION
Installs WinGet, Microsoft ADK and the Windows PE add-on for Windows 11, version 22H2, and MDT using WinGet
.LINK
https://www.osdcloud.com/osdcloud/setup
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
# Microsoft ADK Windows 11 22H2 10.1.22621.1
winget show --id Microsoft.WindowsADK --versions
winget install --id Microsoft.WindowsADK --version 10.1.22621.1 --exact

winget show --id Microsoft.ADKPEAddon --versions
winget install --id Microsoft.ADKPEAddon --version 10.1.22621.1 --exact

New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force

# Microsoft Deployment Toolkit
winget install --id Microsoft.DeploymentToolkit --version 6.3.8456.1000 --exact
}
else {
    Write-Error -Message 'WinGet is not installed.'
}