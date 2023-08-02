<#
.SYNOPSIS
    This script retrieves information about cooling devices on the local computer.

.DESCRIPTION
    The Get-CoolingDeviceClasses script uses WMI to retrieve information about cooling devices on the local computer. The script retrieves information about the following classes: Win32_Fan, Win32_HeatPipe, Win32_Refrigeration, and Win32_TemperatureProbe.

.PARAMETER None
    This script does not accept any parameters.

.EXAMPLE
    Get-CoolingDeviceClasses
    Retrieves information about cooling devices on the local computer.

.LINK
    https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_Fan | Select-Object -Property *
Get-WmiObject -Class Win32_HeatPipe | Select-Object -Property *
Get-WmiObject -Class Win32_Refrigeration | Select-Object -Property *
Get-WmiObject -Class Win32_TemperatureProbe | Select-Object -Property *