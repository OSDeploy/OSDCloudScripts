#Requires -RunAsAdministrator
<#
.DESCRIPTION
Install Microsoft ADK Windows 11 23H2 10.1.25398.1
.LINK
https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install
#>
# Fix MDT x86 Boot Image Properties error
if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
    New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
}