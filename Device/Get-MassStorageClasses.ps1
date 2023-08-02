<#
.SYNOPSIS
Retrieves information about mass storage classes on the local computer.

.DESCRIPTION
This script uses WMI to retrieve information about mass storage classes on the local computer. The following classes are queried:
- Win32_AutochkSetting
- Win32_CDROMDrive
- Win32_DiskDrive
- Win32_PhysicalMedia
- Win32_TapeDrive

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_AutochkSetting | Select-Object -Property *
Get-WmiObject -Class Win32_CDROMDrive | Select-Object -Property *
Get-WmiObject -Class Win32_DiskDrive | Select-Object -Property *
Get-WmiObject -Class Win32_PhysicalMedia | Select-Object -Property *
Get-WmiObject -Class Win32_TapeDrive | Select-Object -Property *