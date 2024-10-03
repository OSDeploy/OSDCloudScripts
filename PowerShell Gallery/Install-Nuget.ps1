<#
.SYNOPSIS
Install NuGet package provider and download the NuGet.exe
.LINK
https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
#>
$params = @{
    Name           = 'NuGet'
    MinimumVersion = '2.8.5.201'
    ErrorAction    = 'SilentlyContinue'
    Force          = $true
    Verbose        = $true
}
Install-PackageProvider @params

$params = @{
    Uri         = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
    OutFile     = "$env:LOCALAPPDATA\Microsoft\Windows\PowerShell\PowerShellGet\NuGet.exe"
    ErrorAction = 'SilentlyContinue'
    Verbose     = $true
}
Invoke-WebRequest @params