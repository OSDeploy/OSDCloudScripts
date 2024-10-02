#Requires -RunAsAdministrator
<#
.DESCRIPTION
Install Microsoft Deployment Toolkit
.LINK
https://learn.microsoft.com/en-us/mem/configmgr/mdt/
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Show all available versions
    winget show --id Microsoft.DeploymentToolkit --versions

    # Microsoft Deployment Toolkit
    winget install --id Microsoft.DeploymentToolkit --version 6.3.8456.1000 --exact --accept-source-agreements --accept-package-agreements

    # Fix MDT x86 Boot Image Properties error
    if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
        New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
    }
}
else {
    Write-Error -Message 'WinGet is not installed.'
}