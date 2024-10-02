#Requires -RunAsAdministrator
<#
.DESCRIPTION
Install Microsoft ADK Windows 11 24H2 10.1.26100.1
.LINK
https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install
#>

$ADKInstallLocation = [System.Environment]::ExpandEnvironmentVariables('%ProgramFiles(x86)%\Windows Kits\10')

# Windows ADK 10.1.26100.1 (May 2024)
$ADKUri = 'https://go.microsoft.com/fwlink/?linkid=2271337'
Write-Host -ForegroundColor Green '[+] Downloading Windows ADK 10.1.26100.1 (May 2024) Setup from ' $ADKUri

if ($host.name -match 'ConsoleHost') {
    Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adksetup.exe`" --url `"$ADKUri`""
}
else {
    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
    $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adksetup.exe`" --url `"$ADKUri`" 2>&1"
}
Write-Host -ForegroundColor Green '[+] Downloading and Installing Windows ADK 10.1.26100.1 (May 2024) to ' $ADKInstallLocation
Start-Process -FilePath "$env:TEMP\adksetup.exe" -ArgumentList '/features', 'OptionId.DeploymentTools', '/ceip', 'off', '/installpath', """$ADKInstallLocation""", '/norestart' -Wait


# Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024)
$WinPEUri = 'https://go.microsoft.com/fwlink/?linkid=2271338'
Write-Host -ForegroundColor Green '[+] Downloading Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024) Setup from ' $WinPEUri

if ($host.name -match 'ConsoleHost') {
    Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adkwinpesetup.exe`" --url `"$WinPEUri`""
}
else {
    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
    $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adkwinpesetup.exe`" --url `"$WinPEUri`" 2>&1"
}
Write-Host -ForegroundColor Green '[+] Downloading and Installing Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024) to ' $ADKInstallLocation
Start-Process -FilePath "$env:TEMP\adkwinpesetup.exe" -ArgumentList '/features', 'OptionId.WindowsPreinstallationEnvironment', '/ceip', 'off', '/installpath', """$ADKInstallLocation""", '/norestart' -Wait

# Fix MDT x86 Boot Image Properties error
if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
    New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
}

# Complete
Write-Host -ForegroundColor Green '[+] Windows ADK 10.1.26100.1 (May 2024) has been installed'