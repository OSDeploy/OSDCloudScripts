<#
.SYNOPSIS
This script retrieves information about power classes.

.DESCRIPTION
The Get-PowerClasses.ps1 script uses WMI to retrieve information about power classes, including battery, current probe, portable battery, power management event, and voltage probe.

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_Battery | Select-Object -Property *
Get-WmiObject -Class Win32_CurrentProbe | Select-Object -Property *
Get-WmiObject -Class Win32_PortableBattery | Select-Object -Property *
Get-WmiObject -Class Win32_PowerManagementEvent	 | Select-Object -Property *
Get-WmiObject -Class Win32_VoltageProbe | Select-Object -Property *