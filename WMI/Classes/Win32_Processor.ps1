Get-WmiObject -Class Win32_Processor | Select-Object -Property *

<#
RunspaceId                              : 9847c798-6a8f-4d88-8d87-51487297bd29
__GENUS                                 : 2
__CLASS                                 : Win32_Processor
__SUPERCLASS                            : CIM_Processor
__DYNASTY                               : CIM_ManagedSystemElement
__RELPATH                               : Win32_Processor.DeviceID="CPU0"
__PROPERTY_COUNT                        : 57
__DERIVATION                            : {CIM_Processor, CIM_LogicalDevice, CIM_LogicalElement, CIM_ManagedSystemElement}
__SERVER                                : HPFIREFLY16P
__NAMESPACE                             : root\cimv2
__PATH                                  : \\HPFIREFLY16P\root\cimv2:Win32_Processor.DeviceID="CPU0"
AddressWidth                            : 64
Architecture                            : 9
AssetTag                                : To Be Filled By O.E.M.
Availability                            : 3
Caption                                 : Intel64 Family 6 Model 186 Stepping 2
Characteristics                         : 252
ConfigManagerErrorCode                  : 
ConfigManagerUserConfig                 : 
CpuStatus                               : 1
CreationClassName                       : Win32_Processor
CurrentClockSpeed                       : 1900
CurrentVoltage                          : 8
DataWidth                               : 64
Description                             : Intel64 Family 6 Model 186 Stepping 2
DeviceID                                : CPU0
ErrorCleared                            : 
ErrorDescription                        : 
ExtClock                                : 100
Family                                  : 198
InstallDate                             : 
L2CacheSize                             : 4096
L2CacheSpeed                            : 
L3CacheSize                             : 24576
L3CacheSpeed                            : 0
LastErrorCode                           : 
Level                                   : 6
LoadPercentage                          : 0
Manufacturer                            : GenuineIntel
MaxClockSpeed                           : 1900
Name                                    : 13th Gen Intel(R) Core(TM) i7-1370P
NumberOfCores                           : 14
NumberOfEnabledCore                     : 14
NumberOfLogicalProcessors               : 20
OtherFamilyDescription                  : 
PartNumber                              : To Be Filled By O.E.M.
PNPDeviceID                             : 
PowerManagementCapabilities             : 
PowerManagementSupported                : False
ProcessorId                             : BFEBFBFF000B06A2
ProcessorType                           : 3
Revision                                : 
Role                                    : CPU
SecondLevelAddressTranslationExtensions : False
SerialNumber                            : To Be Filled By O.E.M.
SocketDesignation                       : U3E1
Status                                  : OK
StatusInfo                              : 3
Stepping                                : 
SystemCreationClassName                 : Win32_ComputerSystem
SystemName                              : HPFIREFLY16P
ThreadCount                             : 20
UniqueId                                : 
UpgradeMethod                           : 65
Version                                 : 
VirtualizationFirmwareEnabled           : False
VMMonitorModeExtensions                 : False
VoltageCaps                             : 
#>