#Requires -RunAsAdministrator
<#
.SYNOPSIS
Bugfix for MDT Windows PE x86 MMC snap-in error
.LINK
https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install
#>
if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
    New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
}