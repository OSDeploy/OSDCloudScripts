#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs PowerShell 7 using the official Microsoft installer.

.DESCRIPTION
This script installs PowerShell 7 on the local machine using the official Microsoft installer.
The installer is downloaded from the Microsoft website and executed using the Invoke-Expression cmdlet.

.PARAMETER UseMSI
Specifies whether to use the MSI installer instead of the EXE installer. By default, the EXE installer is used.

.EXAMPLE
Install-PowerShell.ps1
Installs PowerShell 7 using the default EXE installer.

.EXAMPLE
Install-PowerShell.ps1 -UseMSI
Installs PowerShell 7 using the MSI installer.

.LINK
https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3
#>
iex "& { $(irm https://aka.ms/install-powershell.ps1) } -UseMSI"