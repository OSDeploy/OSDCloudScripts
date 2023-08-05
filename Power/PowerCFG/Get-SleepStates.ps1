<#
.DESCRIPTION
    Reports the sleep states available on the system. Attempts to report reasons why sleep states are unavailable.

.LINK
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#option_availablesleepstates
    
.NOTES
    Author: David Segura
    Modified: 2023-07-16
#>
powercfg.exe /AvailableSleepStates