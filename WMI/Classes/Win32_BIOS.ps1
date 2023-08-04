<#
.SYNOPSIS
This script retrieves the BIOS information of a computer using the Windows Management Instrumentation (WMI) class Win32_BIOS.
#>
Get-WmiObject -Class Win32_BIOS | Select-Object -Property *