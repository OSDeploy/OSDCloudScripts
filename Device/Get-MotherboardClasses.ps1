<#
.SYNOPSIS
    This script retrieves information about the motherboard classes of a device.

.DESCRIPTION
    This script uses WMI to retrieve information about the motherboard classes of a device. It retrieves information about the following classes:
    - Win32_AllocatedResource
    - Win32_AssociatedProcessorMemory
    - Win32_BaseBoard
    - Win32_BIOS
    - Win32_Bus
    - Win32_CacheMemory
    - Win32_DeviceBus
    - Win32_DeviceMemoryAddress
    - Win32_DeviceSettings
    - Win32_DMAChannel
    - Win32_InfraredDevice
    - Win32_IRQResource
    - Win32_MemoryArray
    - Win32_MemoryArrayLocation
    - Win32_MemoryDevice
    - Win32_MemoryDeviceArray
    - Win32_MemoryDeviceLocation
    - Win32_MotherboardDevice
    - Win32_OnBoardDevice
    - Win32_PhysicalMemory
    - Win32_PhysicalMemoryArray
    - Win32_PhysicalMemoryLocation
    - Win32_PNPAllocatedResource
    - Win32_PNPDevice
    - Win32_PNPEntity
    - Win32_Processor
    - Win32_SMBIOSMemory
    - Win32_SoundDevice
    - Win32_SystemBIOS
    - Win32_SystemDriverPNPEntity
    - Win32_SystemEnclosure
    - Win32_SystemMemoryResource
    - Win32_SystemSlot
    - Win32_USBHub

.PARAMETER None
    This script does not accept any parameters.

.EXAMPLE
    PS C:\> .\Get-MotherboardClasses.ps1
    This command retrieves information about the motherboard classes of the local device.

.LINK
    https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/computer-system-hardware-classes
#>
Get-WmiObject -Class Win32_AllocatedResource | Select-Object -Property *
Get-WmiObject -Class Win32_AssociatedProcessorMemory | Select-Object -Property *
Get-WmiObject -Class Win32_BaseBoard | Select-Object -Property *
Get-WmiObject -Class Win32_BIOS | Select-Object -Property *
Get-WmiObject -Class Win32_Bus | Select-Object -Property *
Get-WmiObject -Class Win32_CacheMemory | Select-Object -Property *
Get-WmiObject -Class Win32_DeviceBus | Select-Object -Property *
Get-WmiObject -Class Win32_DeviceMemoryAddress | Select-Object -Property *
Get-WmiObject -Class Win32_DeviceSettings | Select-Object -Property *
Get-WmiObject -Class Win32_DMAChannel | Select-Object -Property *
Get-WmiObject -Class Win32_InfraredDevice | Select-Object -Property *
Get-WmiObject -Class Win32_IRQResource | Select-Object -Property *
Get-WmiObject -Class Win32_MemoryArray | Select-Object -Property *
Get-WmiObject -Class Win32_MemoryArrayLocation | Select-Object -Property *
Get-WmiObject -Class Win32_MemoryDevice | Select-Object -Property *
Get-WmiObject -Class Win32_MemoryDeviceArray | Select-Object -Property *
Get-WmiObject -Class Win32_MemoryDeviceLocation | Select-Object -Property *
Get-WmiObject -Class Win32_MotherboardDevice | Select-Object -Property *
Get-WmiObject -Class Win32_OnBoardDevice | Select-Object -Property *
Get-WmiObject -Class Win32_PhysicalMemory | Select-Object -Property *
Get-WmiObject -Class Win32_PhysicalMemoryArray | Select-Object -Property *
Get-WmiObject -Class Win32_PhysicalMemoryLocation | Select-Object -Property *
Get-WmiObject -Class Win32_PNPAllocatedResource | Select-Object -Property *
Get-WmiObject -Class Win32_PNPDevice | Select-Object -Property *
Get-WmiObject -Class Win32_PNPEntity | Select-Object -Property *
Get-WmiObject -Class Win32_Processor | Select-Object -Property *
Get-WmiObject -Class Win32_SMBIOSMemory | Select-Object -Property *
Get-WmiObject -Class Win32_SoundDevice | Select-Object -Property *
Get-WmiObject -Class Win32_SystemBIOS | Select-Object -Property *
Get-WmiObject -Class Win32_SystemDriverPNPEntity | Select-Object -Property *
Get-WmiObject -Class Win32_SystemEnclosure | Select-Object -Property *
Get-WmiObject -Class Win32_SystemMemoryResource | Select-Object -Property *
Get-WmiObject -Class Win32_SystemSlot | Select-Object -Property *
Get-WmiObject -Class Win32_USBHub | Select-Object -Property *