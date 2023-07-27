<#PSScriptInfo
.VERSION 23.7.27.5
.GUID 2b8c910c-6a09-4b82-b95e-f676511a2277
.AUTHOR David Segura
.COMPANYNAME David Segura
.COPYRIGHT (c) 2023 David Segura. All rights reserved.
.TAGS WinGet
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/PwshHub
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.DESCRIPTION
This script will install NuGet
.LINK

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