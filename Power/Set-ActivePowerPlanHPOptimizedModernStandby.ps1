<#
.DESCRIPTION
    Makes the specified power scheme active on the system.

.LINK
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#setactive-or-s
    
.NOTES
    Author: David Segura
    Modified date: 2023-07-16

    This power plan may not exist on all computers
#>
powercfg /setactive fb5220ff-7e1a-47aa-9a42-50ffbf45c673