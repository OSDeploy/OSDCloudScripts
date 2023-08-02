<#
.SYNOPSIS
This script retrieves information about networking devices on the local computer.

.DESCRIPTION
The Get-NetworkingDeviceClasses.ps1 script uses WMI to retrieve information about the following networking device classes:
- Win32_NetworkAdapter
- Win32_NetworkAdapterConfiguration
- Win32_NetworkAdapterSetting

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_NetworkAdapter | Select-Object -Property *
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property *
Get-WmiObject -Class Win32_NetworkAdapterSetting | Select-Object -Property *