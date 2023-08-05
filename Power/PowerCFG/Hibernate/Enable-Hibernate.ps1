#Requires -RunAsAdministrator
<#
.DESCRIPTION
    Enable Hibernate support using Powercfg.exe

.LINK
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#option_hibernate

.NOTES
    Author: David Segura
    Modified: 2023-07-16

    Make sure your device supports Hibernate with powercfg /availablesleepstates
#>
powercfg.exe /Hibernate on