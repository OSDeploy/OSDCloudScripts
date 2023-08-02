#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs PowerShell 7 using DotNet Core SDK.

.DESCRIPTION
This script installs PowerShell 7 using DotNet Core SDK on the local machine.

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3

.NOTES
If you already have the .NET Core SDK installed, you can install PowerShell as a .NET Global tool.
The dotnet tool installer adds $HOME\.dotnet\tools to your $env:PATH environment variable.
However, the currently running shell doesn't have the updated $env:PATH.
You can start PowerShell from a new shell by typing pwsh.
#>
[CmdletBinding()]
param()

if (Get-Command 'dotnet' -ErrorAction SilentlyContinue) {
    dotnet tool install --global PowerShell
}
else {
    Write-Error -Message 'DotNet Core SDK is not installed.'
}