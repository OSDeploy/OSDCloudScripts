<#
.SYNOPSIS
This script retrieves information about the different types of ports available on a device.

.DESCRIPTION
The Get-PortClasses.ps1 script uses WMI to retrieve information about the following types of ports:
- Parallel ports
- Port connectors
- Port resources
- Serial ports
- Serial port configurations
- Serial port settings

.PARAMETER None
This script does not accept any parameters.

.LINK
https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_ParallelPort | Select-Object -Property *
Get-WmiObject -Class Win32_PortConnector | Select-Object -Property *
Get-WmiObject -Class Win32_PortResource | Select-Object -Property *
Get-WmiObject -Class Win32_SerialPort | Select-Object -Property *
Get-WmiObject -Class Win32_SerialPortConfiguration | Select-Object -Property *
Get-WmiObject -Class Win32_SerialPortSetting | Select-Object -Property *