#Requires -RunAsAdministrator
<#
.DESCRIPTION
Installs Visual C++ Redistributables
.LINK
https://vcredist.com/quick/
.NOTES
Author:  Aaron Parker, Stealthpuppy.com
#>

Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://vcredist.com/install.ps1'))