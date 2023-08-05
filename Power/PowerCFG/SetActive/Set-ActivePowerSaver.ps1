<#
.SYNOPSIS
Makes the specified power scheme active on the system.

.DESCRIPTION
Makes the specified power scheme active on the system.

.LINK
https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#setactive-or-s
    
.NOTES
powercfg.exe /SetActive SCHEME_MAX
powercfg.exe /SetActive a1841308-3541-4fab-bc81-f71556f20b4a
#>
powercfg.exe /S SCHEME_MAX