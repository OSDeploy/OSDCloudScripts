#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs Microsoft ADK and the Windows PE add-on for Windows 11, version 24H2, and MDT using WinGet
.LINK
https://www.osdcloud.com/osdcloud/setup
#>

#region Install Microsoft ADK Windows 11 24H2 10.1.26100.1
# Windows ADK 10.1.26100.1 (May 2024)
$ADKUri = 'https://go.microsoft.com/fwlink/?linkid=2271337'
Write-Host -ForegroundColor Green '[+] Downloading Windows ADK 10.1.26100.1 (May 2024) Setup from' $ADKUri

if ($host.name -match 'ConsoleHost') {
    Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adksetup.exe`" --url `"$ADKUri`""
}
else {
    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
    $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adksetup.exe`" --url `"$ADKUri`" 2>&1"
}
Write-Host -ForegroundColor Green '[+] Downloading and Installing Windows ADK 10.1.26100.1 (May 2024)'
Start-Process -FilePath "$env:TEMP\adksetup.exe" -ArgumentList '/features', 'OptionId.DeploymentTools', '/quiet', '/ceip', 'off', '/norestart' -Wait


# Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024)
$WinPEUri = 'https://go.microsoft.com/fwlink/?linkid=2271338'
Write-Host -ForegroundColor Green '[+] Downloading Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024) Setup from' $WinPEUri

if ($host.name -match 'ConsoleHost') {
    Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adkwinpesetup.exe`" --url `"$WinPEUri`""
}
else {
    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
    $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adkwinpesetup.exe`" --url `"$WinPEUri`" 2>&1"
}
Write-Host -ForegroundColor Green '[+] Downloading and Installing Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024)'
Start-Process -FilePath "$env:TEMP\adkwinpesetup.exe" -ArgumentList '/features', 'OptionId.WindowsPreinstallationEnvironment', '/quiet', '/ceip', 'off', '/norestart' -Wait

# Bugfix for MDT Windows PE x86 MMC snap-in error
if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
    New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
}

# Complete
Write-Host -ForegroundColor Green '[+] Windows ADK 10.1.26100.1 (May 2024) has been installed'
#endregion

#region Install Microsoft MDT 6.3.8456.1000
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    Write-Host -Message 'WinGet is already installed.'
}
else {
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -Verbose
    }
    catch {
        Write-Error -Message 'WinGet could not be installed.'
    }
}

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Show all available versions
    winget show --id Microsoft.DeploymentToolkit --versions

    # Microsoft Deployment Toolkit
    winget install --id Microsoft.DeploymentToolkit --version 6.3.8456.1000 --exact --accept-source-agreements --accept-package-agreements

    # Bugfix for MDT Windows PE x86 MMC snap-in error
    if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
        New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
    }
}
else {
    Write-Error -Message 'WinGet is not installed.'
}
#endregion

#region Install OSD
$params = @{
    Name        = 'OSD'
    Scope       = 'CurrentUser'
    ErrorAction = 'SilentlyContinue'
    Force       = $true
    Verbose     = $true
}
Install-Module @params
#endregion
