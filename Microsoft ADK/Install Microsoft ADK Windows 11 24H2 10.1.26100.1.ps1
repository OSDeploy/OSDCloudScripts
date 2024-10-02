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
if ($host.name -match 'ConsoleHost') {
    Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adksetup.exe`" --url `"$ADKUri`""
}
else {
    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
    $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adksetup.exe`" --url `"$ADKUri`" 2>&1"
}
Start-Process -FilePath "$env:TEMP\adksetup.exe" -ArgumentList '/features', 'OptionId.DeploymentTools', '/q', '/ceip', 'off', '/installpath', """$ADKInstallLocation""", '/norestart' -Wait


# Windows PE add-on for the Windows ADK 10.1.26100.1 (May 2024)
$WinPEUri = 'https://go.microsoft.com/fwlink/?linkid=2271338'
if ($host.name -match 'ConsoleHost') {
    Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adkwinpesetup.exe`" --url `"$WinPEUri`""
}
else {
    #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
    $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$env:TEMP\adkwinpesetup.exe`" --url `"$WinPEUri`" 2>&1"
}
Start-Process -FilePath "$env:TEMP\adkwinpesetup.exe" -ArgumentList '/features', 'OptionId.WindowsPreinstallationEnvironment', '/q', '/ceip', 'off', '/installpath', """$ADKInstallLocation""", '/norestart' -Wait