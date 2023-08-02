<#
.SYNOPSIS
    This script retrieves information about different types of controllers on a device.

.DESCRIPTION
    This script uses WMI to retrieve information about the following types of controllers:
    - Win32_1394Controller
    - Win32_1394ControllerDevice
    - Win32_ControllerHasHub
    - Win32_FloppyController
    - Win32_IDEController
    - Win32_IDEControllerDevice
    - Win32_PCMCIAController
    - Win32_SCSIController
    - Win32_SCSIControllerDevice
    - Win32_USBController
    - Win32_USBControllerDevice

.PARAMETER None
    This script does not accept any parameters.

.LINK
    https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_1394Controller | Select-Object -Property *
Get-WmiObject -Class Win32_1394ControllerDevice | Select-Object -Property *
Get-WmiObject -Class Win32_ControllerHasHub | Select-Object -Property *
Get-WmiObject -Class Win32_FloppyController | Select-Object -Property *
Get-WmiObject -Class Win32_IDEController | Select-Object -Property *
Get-WmiObject -Class Win32_IDEControllerDevice | Select-Object -Property *
Get-WmiObject -Class Win32_PCMCIAController | Select-Object -Property *
Get-WmiObject -Class Win32_SCSIController | Select-Object -Property *
Get-WmiObject -Class Win32_SCSIControllerDevice | Select-Object -Property *
Get-WmiObject -Class Win32_USBController | Select-Object -Property *
Get-WmiObject -Class Win32_USBControllerDevice | Select-Object -Property *