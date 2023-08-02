<#
.DESCRIPTION
    Makes the specified power scheme active on the system.

.LINK
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#setactive-or-s
    
.NOTES
    Author: David Segura
    Modified: 2023-07-16

    This power plan may not exist on all computers
#>
powercfg /setactive 80f744fe-9c02-4a5e-8ea2-cfee24d3cffc