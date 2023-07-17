<#
.DESCRIPTION
    Configure Windows Terminal with PowerShell as default shell

.LINK
    https://support.microsoft.com/en-us/windows/command-prompt-and-windows-powershell-for-windows-11-6453ce98-da91-476f-8651-5c14d5777c20

.NOTES
    Author: David Segura
    Modified: 2023-07-16
#>
$Url = 'https://nuget.org/nuget.exe'
$FileName = 'NuGet.exe'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($isAdmin) {
    $installPath = Join-Path -Path $env:ProgramData -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
}
else {
    $installPath = Join-Path -Path $env:LOCALAPPDATA -ChildPath 'Microsoft\Windows\PowerShell\PowerShellGet\'
}

if (-not (Test-Path -Path $installPath)) {
    $null = New-Item -Path $installPath -ItemType Directory -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}

$installFile = Join-Path -Path $installPath -ChildPath $FileName
$null = Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $installFile