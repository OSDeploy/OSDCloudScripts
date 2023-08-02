<#
.SYNOPSIS
This script retrieves information about video monitors and controllers on the local computer.

.DESCRIPTION
The Get-VideoMonitorClasses.ps1 script uses WMI to retrieve information about the video monitors and controllers on the local computer. The script outputs the following information:
- Win32_DesktopMonitor: Information about the desktop monitors.
- Win32_DisplayControllerConfiguration: Information about the display controller configuration.
- Win32_VideoController: Information about the video controllers.
- Win32_VideoSettings: Information about the video settings.

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_DesktopMonitor | Select-Object -Property *
Get-WmiObject -Class Win32_DisplayControllerConfiguration | Select-Object -Property *
Get-WmiObject -Class Win32_VideoController | Select-Object -Property *
Get-WmiObject -Class Win32_VideoSettings | Select-Object -Property *