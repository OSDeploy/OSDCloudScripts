#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs PowerShell 7 from the Microsoft Store using WinGet.

.DESCRIPTION
This script installs PowerShell 7 from the Microsoft Store using WinGet.
If WinGet is not installed, an error message is displayed.

.PARAMETER id
The ID of the PowerShell 7 package in the Microsoft Store. The default value is '9MZ1SNWT0N5D'.

.LINK
https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3

.NOTES
Benefits of the Microsoft Store package:

Automatic updates built right into Windows
Integrates with other software distribution mechanisms like Intune and Configuration Manager
Can install on Windows systems using x86, x64, or Arm64 processors
Known limitations
By default, Windows Store packages run in an application sandbox that virtualizes access to some filesystem and registry locations.
Changes to virtualized file and registry locations don't persist outside of the application sandbox.

This sandbox all blocks any changes to the application's root folder. Any system-level configuration settings stored in $PSHOME can't be modified.
This includes the WSMAN configuration. This prevents remote sessions from connecting to Store-based installs of PowerShell. User-level configurations and SSH remoting are supported.

The following commands need write to $PSHOME. These commands aren't supported in a Microsoft Store instance of PowerShell.

Register-PSSessionConfiguration
Update-Help -Scope AllUsers
Enable-ExperimentalFeature -Scope AllUsers
Set-ExecutionPolicy -Scope LocalMachine
For more information, see Understanding how packaged desktop apps run on Windows.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$id = '9MZ1SNWT0N5D'
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