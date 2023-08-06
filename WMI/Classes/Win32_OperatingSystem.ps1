Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property *
<#
RunspaceId                                : bb8cbfb9-e328-4ef2-835d-486c9c6fec75
__GENUS                                   : 2
__CLASS                                   : Win32_OperatingSystem
__SUPERCLASS                              : CIM_OperatingSystem
__DYNASTY                                 : CIM_ManagedSystemElement
__RELPATH                                 : Win32_OperatingSystem=@
__PROPERTY_COUNT                          : 64
__DERIVATION                              : {CIM_OperatingSystem, CIM_LogicalElement, CIM_ManagedSystemElement}
__SERVER                                  : HPFIREFLY16P
__NAMESPACE                               : root\cimv2
__PATH                                    : \\HPFIREFLY16P\root\cimv2:Win32_OperatingSystem=@
BootDevice                                : \Device\HarddiskVolume1
BuildNumber                               : 22621
BuildType                                 : Multiprocessor Free
Caption                                   : Microsoft Windows 11 Pro
CodeSet                                   : 1252
CountryCode                               : 1
CreationClassName                         : Win32_OperatingSystem
CSCreationClassName                       : Win32_ComputerSystem
CSDVersion                                : 
CSName                                    : HPFIREFLY16P
CurrentTimeZone                           : -300
DataExecutionPrevention_32BitApplications : True
DataExecutionPrevention_Available         : True
DataExecutionPrevention_Drivers           : True
DataExecutionPrevention_SupportPolicy     : 2
Debug                                     : False
Description                               : 
Distributed                               : False
EncryptionLevel                           : 256
ForegroundApplicationBoost                : 2
FreePhysicalMemory                        : 38813944
FreeSpaceInPagingFiles                    : 9428448
FreeVirtualMemory                         : 47105820
InstallDate                               : 20230727013400.000000-300
LargeSystemCache                          : 
LastBootUpTime                            : 20230804230321.499708-300
LocalDateTime                             : 20230805203550.546000-300
Locale                                    : 0409
Manufacturer                              : Microsoft Corporation
MaxNumberOfProcesses                      : 4294967295
MaxProcessMemorySize                      : 137438953344
MUILanguages                              : {en-US}
Name                                      : Microsoft Windows 11 Pro|C:\Windows|\Device\Harddisk0\Partition3
NumberOfLicensedUsers                     : 
NumberOfProcesses                         : 312
NumberOfUsers                             : 0
OperatingSystemSKU                        : 48
Organization                              : HP Inc.
OSArchitecture                            : 64-bit
OSLanguage                                : 1033
OSProductSuite                            : 256
OSType                                    : 18
OtherTypeDescription                      : 
PAEEnabled                                : 
PlusProductID                             : 
PlusVersionNumber                         : 
PortableOperatingSystem                   : False
Primary                                   : True
ProductType                               : 1
RegisteredUser                            : HP Inc.
SerialNumber                              : 00355-61019-04327-AAOEM
ServicePackMajorVersion                   : 0
ServicePackMinorVersion                   : 0
SizeStoredInPagingFiles                   : 9437184
Status                                    : OK
SuiteMask                                 : 272
SystemDevice                              : \Device\HarddiskVolume3
SystemDirectory                           : C:\Windows\system32
SystemDrive                               : C:
TotalSwapSpaceSize                        : 
TotalVirtualMemorySize                    : 75710776
TotalVisibleMemorySize                    : 66273592
Version                                   : 10.0.22621
WindowsDirectory                          : C:\Windows
#>
Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property *
<#
Status                                    : OK
Name                                      : Microsoft Windows 11 Pro|C:\Windows|\Device\Harddisk0\Partition3
FreePhysicalMemory                        : 38708564
FreeSpaceInPagingFiles                    : 9428448
FreeVirtualMemory                         : 47005528
Caption                                   : Microsoft Windows 11 Pro
Description                               : 
InstallDate                               : 7/27/2023 1:34:00 AM
CreationClassName                         : Win32_OperatingSystem
CSCreationClassName                       : Win32_ComputerSystem
CSName                                    : HPFIREFLY16P
CurrentTimeZone                           : -300
Distributed                               : False
LastBootUpTime                            : 8/4/2023 11:03:21 PM
LocalDateTime                             : 8/5/2023 8:36:08 PM
MaxNumberOfProcesses                      : 4294967295
MaxProcessMemorySize                      : 137438953344
NumberOfLicensedUsers                     : 
NumberOfProcesses                         : 311
NumberOfUsers                             : 0
OSType                                    : 18
OtherTypeDescription                      : 
SizeStoredInPagingFiles                   : 9437184
TotalSwapSpaceSize                        : 
TotalVirtualMemorySize                    : 75710776
TotalVisibleMemorySize                    : 66273592
Version                                   : 10.0.22621
BootDevice                                : \Device\HarddiskVolume1
BuildNumber                               : 22621
BuildType                                 : Multiprocessor Free
CodeSet                                   : 1252
CountryCode                               : 1
CSDVersion                                : 
DataExecutionPrevention_32BitApplications : True
DataExecutionPrevention_Available         : True
DataExecutionPrevention_Drivers           : True
DataExecutionPrevention_SupportPolicy     : 2
Debug                                     : False
EncryptionLevel                           : 256
ForegroundApplicationBoost                : 2
LargeSystemCache                          : 
Locale                                    : 0409
Manufacturer                              : Microsoft Corporation
MUILanguages                              : {en-US}
OperatingSystemSKU                        : 48
Organization                              : HP Inc.
OSArchitecture                            : 64-bit
OSLanguage                                : 1033
OSProductSuite                            : 256
PAEEnabled                                : 
PlusProductID                             : 
PlusVersionNumber                         : 
PortableOperatingSystem                   : False
Primary                                   : True
ProductType                               : 1
RegisteredUser                            : HP Inc.
SerialNumber                              : 00355-61019-04327-AAOEM
ServicePackMajorVersion                   : 0
ServicePackMinorVersion                   : 0
SuiteMask                                 : 272
SystemDevice                              : \Device\HarddiskVolume3
SystemDirectory                           : C:\Windows\system32
SystemDrive                               : C:
WindowsDirectory                          : C:\Windows
PSComputerName                            : 
CimClass                                  : root/cimv2:Win32_OperatingSystem
CimInstanceProperties                     : {Caption, Description, InstallDate, Name…}
CimSystemProperties                       : Microsoft.Management.Infrastructure.CimSystemProperties
#>