#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs WinGet Preview

.DESCRIPTION
Installs WinGet Preview

.LINK
https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    Write-Host 'WinGet is already installed.'
}
else {
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -Verbose
    }
    catch {
        Write-Error 'WinGet could not be installed.'
    }
}