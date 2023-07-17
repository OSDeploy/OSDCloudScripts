#Requires -RunAsAdministrator
<#
.DESCRIPTION
Disable Hibernate support using Powercfg.exe
.LINK
https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#option_hibernate
.NOTES
Make sure your device supports Hibernate with powercfg /availablesleepstates
#>
powercfg /hibernate off