<#
.SYNOPSIS
This script retrieves information about input devices on the local computer.

.DESCRIPTION
The Get-InputDeviceClasses script uses WMI to retrieve information about input devices on the local computer. 
It retrieves information about both keyboards and pointing devices.

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_Keyboard | Select-Object -Property *
Get-WmiObject -Class Win32_PointingDevice | Select-Object -Property *