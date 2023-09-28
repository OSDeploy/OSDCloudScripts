#Requires -RunAsAdministrator
#WPNinjaS
<#
.SYNOPSIS
Installs WinGet Preview

.LINK
https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget
#>
[CmdletBinding()]
param()

$progressPreference = 'silentlyContinue'
$WinGetPreviewUri = 'https://aka.ms/getwingetpreview'
$WinGetPreview = 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle'
Invoke-WebRequest -Uri $WinGetPreviewUri -OutFile "./$WinGetPreview"
Add-AppxPackage $WinGetPreview