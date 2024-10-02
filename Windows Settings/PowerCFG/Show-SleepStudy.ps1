#Requires -RunAsAdministrator
<#
.DESCRIPTION
    Creates a Modern Standby Sleep Study Report using Powercfg.exe

.LINK
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/modern-standby-sleepstudy

.NOTES
    Author: David Segura
    Modified: 2023-07-16
#>
powercfg.exe /sleepstudy /output "$env:TEMP\SleepStudy.html"
Invoke-Item "$env:TEMP\SleepStudy.html"