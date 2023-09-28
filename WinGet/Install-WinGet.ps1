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
    Write-Host -ForegroundColor Green "[+] WinGet is installed"
}
else {
    if (Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue) {
        Write-Host -ForegroundColor Yellow "[-] Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
        try {
            Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -ErrorAction Stop
        }
        catch {
            Write-Host -ForegroundColor Red '[!] Could not install Microsoft.DesktopAppInstaller AppxPackage'
            Break
        }
    }
}

if (Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge '1.21.2701.0' }) {
    Write-Host -ForegroundColor Green '[+] WinGet is current'
}
else {
    if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
        $WingetVersion = & winget.exe --version
        [string]$WingetVersion = $WingetVersion -replace '[a-zA-Z\-]'

        Write-Host -ForegroundColor Yellow "[-] WinGet $WingetVersion requires an update"
    }
    else {
        Write-Host -ForegroundColor Yellow "[-] Installing WinGet"
    }

    $progressPreference = 'silentlyContinue'
    Write-Host -ForegroundColor Yellow "[-] Downloading Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
    Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle

    Write-Host -ForegroundColor Yellow '[-] Downloading Microsoft.VCLibs.x64.14.00.Desktop.appx'
    Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
    
    Write-Host -ForegroundColor Yellow '[-] Downloading Microsoft.UI.Xaml.2.7.x64.appx'
    Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx -OutFile Microsoft.UI.Xaml.2.7.x64.appx

    Write-Host -ForegroundColor Yellow '[-] Installing WinGet and its dependencies'
    Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
    Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx
    Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
}

winget --info