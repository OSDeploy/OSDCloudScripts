#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs PowerShell 7 using WinGet.

.DESCRIPTION
This script installs PowerShell 7 using the WinGet package manager.
If WinGet is not installed, an error message is displayed.

.PARAMETER id
The package ID of the PowerShell 7 package. The default value is 'Microsoft.PowerShell'.

.EXAMPLE
Install-PowerShell7-WinGet.ps1 -id 'Microsoft.PowerShell'

This example installs the Microsoft.PowerShell package using WinGet.

.LINK
https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3

.NOTES
PowerShell 7 default installation
winget install --id Microsoft.PowerShell --exact --accept-source-agreements --accept-package-agreements

PowerShell 7 installation parameters.  The first three are used in this installation script.
ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL - This property controls the option for adding the Open PowerShell item to the context menu in Windows Explorer.
ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL - This property controls the option for adding the Run with PowerShell item to the context menu in Windows Explorer.
ADD_PATH - This property controls the option for adding PowerShell to the Windows PATH environment variable.
ENABLE_PSREMOTING - This property controls the option for enabling PowerShell remoting during installation.
REGISTER_MANIFEST - This property controls the option for registering the Windows Event Logging manifest.
DISABLE_TELEMETRY - This property controls the option for disabling PowerShell's telemetry by setting the POWERSHELL_TELEMETRY_OPTOUT environment variable.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$id = 'Microsoft.PowerShell'
)

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Show package information
    # winget show --id $id
    
    # Show version information
    # winget show --id $id --versions
    
    # Install
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements --scope machine --override '/Passive ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ADD_PATH=1'
}
else {
    Write-Error -Message 'WinGet is not installed.'
}