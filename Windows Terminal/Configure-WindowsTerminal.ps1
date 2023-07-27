#Requires -RunAsAdministrator
<#
.DESCRIPTION
    Configure Windows Terminal with PowerShell as default shell

.LINK
    https://support.microsoft.com/en-us/windows/command-prompt-and-windows-powershell-for-windows-11-6453ce98-da91-476f-8651-5c14d5777c20

.NOTES
    Author: Jérôme Bezet-Torres
    Information: requires Windows 11 22H2
    Modified: 2023-07-27
#>
New-Item -Path HKCU:\Console\%%Startup | out-null

New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name "DelegationConsole" -Value "{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}" -force | out-null
New-ItemProperty -Path "HKCU:\Console\%%Startup" -Name "DelegationTerminal" -Value "{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}" -force | out-null