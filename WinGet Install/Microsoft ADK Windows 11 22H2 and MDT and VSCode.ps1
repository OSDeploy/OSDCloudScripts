#Requires -RunAsAdministrator
#WPNinjaS
<#
.DESCRIPTION
Install Package using WinGet
.LINK
https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Microsoft ADK Windows 11 22H2 10.1.22621.1
    winget show --id Microsoft.WindowsADK --versions
    winget install --id Microsoft.WindowsADK --version 10.1.22621.1 --exact

    winget show --id Microsoft.ADKPEAddon --versions
    winget install --id Microsoft.ADKPEAddon --version 10.1.22621.1 --exact

    New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force

    # Microsoft Deployment Toolkit
    winget install --id Microsoft.DeploymentToolkit --version 6.3.8456.1000 --exact

    # Microsoft Visual Studio Code
    winget install --id Microsoft.VisualStudioCode --scope machine --override '/SILENT /mergetasks="!runcode,addcontextmenufiles,addcontextmenufolders"' --accept-source-agreements --accept-package-agreements
}
else {
    Write-Error -Message 'WinGet is not installed.'
}