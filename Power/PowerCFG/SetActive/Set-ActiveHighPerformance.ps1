<#
.SYNOPSIS
Makes the specified power scheme active on the system.

.DESCRIPTION
Makes the specified power scheme active on the system.

.LINK
https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#setactive-or-s
    
.NOTES
powercfg.exe /SetActive SCHEME_MIN
powercfg.exe /SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
#>
powercfg.exe /S SCHEME_MIN