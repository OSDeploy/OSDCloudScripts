#Requires -RunAsAdministrator
#WPNinjaS
<#
.SYNOPSIS
Installs WinGet

.DESCRIPTION
Installs WinGet

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

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    $WingetVersion = & winget.exe --version
    [string]$WingetVersion = $WingetVersion -replace '[a-zA-Z\-]'

    if ($WingetVersion -lt '1.3.1251') {
        Write-Host -ForegroundColor Cyan 'Downloading WinGet and its dependencies...'
        Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
        Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
        Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx -OutFile Microsoft.UI.Xaml.2.7.x64.appx
        Write-Host -ForegroundColor Cyan 'Installing WinGet and its dependencies...'
        Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
        Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx
        Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
    }
}