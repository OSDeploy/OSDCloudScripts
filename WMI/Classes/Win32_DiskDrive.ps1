Get-WmiObject -Class Win32_DiskDrive | Select-Object -Property *
<#
RunspaceId                  : bb8cbfb9-e328-4ef2-835d-486c9c6fec75
__GENUS                     : 2
__CLASS                     : Win32_DiskDrive
__SUPERCLASS                : CIM_DiskDrive
__DYNASTY                   : CIM_ManagedSystemElement
__RELPATH                   : Win32_DiskDrive.DeviceID="\\\\.\\PHYSICALDRIVE0"
__PROPERTY_COUNT            : 51
__DERIVATION                : {CIM_DiskDrive, CIM_MediaAccessDevice, CIM_LogicalDevice, CIM_LogicalElement…}
__SERVER                    : HPFIREFLY16P
__NAMESPACE                 : root\cimv2
__PATH                      : \\HPFIREFLY16P\root\cimv2:Win32_DiskDrive.DeviceID="\\\\.\\PHYSICALDRIVE0"
Availability                : 
BytesPerSector              : 512
Capabilities                : {3, 4}
CapabilityDescriptions      : {Random Access, Supports Writing}
Caption                     : Samsung SSD 990 PRO 2TB
CompressionMethod           : 
ConfigManagerErrorCode      : 0
ConfigManagerUserConfig     : False
CreationClassName           : Win32_DiskDrive
DefaultBlockSize            : 
Description                 : Disk drive
DeviceID                    : \\.\PHYSICALDRIVE0
ErrorCleared                : 
ErrorDescription            : 
ErrorMethodology            : 
FirmwareRevision            : 3B2QJXD7
Index                       : 0
InstallDate                 : 
InterfaceType               : SCSI
LastErrorCode               : 
Manufacturer                : (Standard disk drives)
MaxBlockSize                : 
MaxMediaSize                : 
MediaLoaded                 : True
MediaType                   : Fixed hard disk media
MinBlockSize                : 
Model                       : Samsung SSD 990 PRO 2TB
Name                        : \\.\PHYSICALDRIVE0
NeedsCleaning               : 
NumberOfMediaSupported      : 
Partitions                  : 3
PNPDeviceID                 : SCSI\DISK&VEN_NVME&PROD_SAMSUNG_SSD_990\5&2D57C2A1&0&000000
PowerManagementCapabilities : 
PowerManagementSupported    : 
SCSIBus                     : 0
SCSILogicalUnit             : 0
SCSIPort                    : 0
SCSITargetId                : 0
SectorsPerTrack             : 63
SerialNumber                : 0025_3846_3140_F11C.
Signature                   : 
Size                        : 2000396321280
Status                      : OK
StatusInfo                  : 
SystemCreationClassName     : Win32_ComputerSystem
SystemName                  : HPFIREFLY16P
TotalCylinders              : 243201
TotalHeads                  : 255
TotalSectors                : 3907024065
TotalTracks                 : 62016255
TracksPerCylinder           : 255
#>
Get-CimInstance -ClassName Win32_DiskDrive | Select-Object -Property *
<#
ConfigManagerErrorCode      : 0
LastErrorCode               : 
NeedsCleaning               : 
Status                      : OK
DeviceID                    : \\.\PHYSICALDRIVE0
StatusInfo                  : 
Partitions                  : 3
BytesPerSector              : 512
ConfigManagerUserConfig     : False
DefaultBlockSize            : 
Index                       : 0
InstallDate                 : 
InterfaceType               : SCSI
MaxBlockSize                : 
MaxMediaSize                : 
MinBlockSize                : 
NumberOfMediaSupported      : 
SectorsPerTrack             : 63
Size                        : 2000396321280
TotalCylinders              : 243201
TotalHeads                  : 255
TotalSectors                : 3907024065
TotalTracks                 : 62016255
TracksPerCylinder           : 255
Caption                     : Samsung SSD 990 PRO 2TB
Description                 : Disk drive
Name                        : \\.\PHYSICALDRIVE0
Availability                : 
CreationClassName           : Win32_DiskDrive
ErrorCleared                : 
ErrorDescription            : 
PNPDeviceID                 : SCSI\DISK&VEN_NVME&PROD_SAMSUNG_SSD_990\5&2D57C2A1&0&000000
PowerManagementCapabilities : 
PowerManagementSupported    : 
SystemCreationClassName     : Win32_ComputerSystem
SystemName                  : HPFIREFLY16P
Capabilities                : {3, 4}
CapabilityDescriptions      : {Random Access, Supports Writing}
CompressionMethod           : 
ErrorMethodology            : 
FirmwareRevision            : 3B2QJXD7
Manufacturer                : (Standard disk drives)
MediaLoaded                 : True
MediaType                   : Fixed hard disk media
Model                       : Samsung SSD 990 PRO 2TB
SCSIBus                     : 0
SCSILogicalUnit             : 0
SCSIPort                    : 0
SCSITargetId                : 0
SerialNumber                : 0025_3846_3140_F11C.
Signature                   : 
PSComputerName              : 
CimClass                    : root/cimv2:Win32_DiskDrive
CimInstanceProperties       : {Caption, Description, InstallDate, Name…}
CimSystemProperties         : Microsoft.Management.Infrastructure.CimSystemProperties
#>