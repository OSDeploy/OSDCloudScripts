Get-WmiObject -Class Win32_ComputerSystem | Select-Object -Property *
<#
RunspaceId                  : 9847c798-6a8f-4d88-8d87-51487297bd29
__GENUS                     : 2
__CLASS                     : Win32_ComputerSystem
__SUPERCLASS                : CIM_UnitaryComputerSystem
__DYNASTY                   : CIM_ManagedSystemElement
__RELPATH                   : Win32_ComputerSystem.Name="HPFIREFLY16P"
__PROPERTY_COUNT            : 64
__DERIVATION                : {CIM_UnitaryComputerSystem, CIM_ComputerSystem, CIM_System, CIM_LogicalElement…}
__SERVER                    : HPFIREFLY16P
__NAMESPACE                 : root\cimv2
__PATH                      : \\HPFIREFLY16P\root\cimv2:Win32_ComputerSystem.Name="HPFIREFLY16P"
AdminPasswordStatus         : 0
AutomaticManagedPagefile    : True
AutomaticResetBootOption    : True
AutomaticResetCapability    : True
BootOptionOnLimit           : 
BootOptionOnWatchDog        : 
BootROMSupported            : True
BootStatus                  : {0, 0, 0, 11…}
BootupState                 : Normal boot
Caption                     : HPFIREFLY16P
ChassisBootupState          : 3
ChassisSKUNumber            : 
CreationClassName           : Win32_ComputerSystem
CurrentTimeZone             : -300
DaylightInEffect            : True
Description                 : AT/AT COMPATIBLE
DNSHostName                 : hpFirefly16P
Domain                      : WORKGROUP
DomainRole                  : 0
EnableDaylightSavingsTime   : True
FrontPanelResetStatus       : 0
HypervisorPresent           : True
InfraredSupported           : False
InitialLoadInfo             : 
InstallDate                 : 
KeyboardPasswordStatus      : 0
LastLoadInfo                : 
Manufacturer                : HP
Model                       : HP ZBook Firefly 16 inch G10 Mobile Workstation PC
Name                        : HPFIREFLY16P
NameFormat                  : 
NetworkServerModeEnabled    : True
NumberOfLogicalProcessors   : 20
NumberOfProcessors          : 1
OEMLogoBitmap               : 
OEMStringArray              : {FBYTE#476J6S6b7B7M7Q7U7W7m7saBapaqauawb8bUcAeMfDfPguhKhWhkjhk8mE, BUILDID#23WWWGBZ601#SABA#DABA;, EDK2_1,   
                              Buff=2…}
PartOfDomain                : False
PauseAfterReset             : -1
PCSystemType                : 2
PCSystemTypeEx              : 2
PowerManagementCapabilities : 
PowerManagementSupported    : 
PowerOnPasswordStatus       : 0
PowerState                  : 0
PowerSupplyState            : 3
PrimaryOwnerContact         : 
PrimaryOwnerName            : HP Inc.
ResetCapability             : 1
ResetCount                  : -1
ResetLimit                  : -1
Roles                       : {LM_Workstation, LM_Server, NT}
Status                      : OK
SupportContactDescription   : 
SystemFamily                : 103C_5336AN HP ZBook
SystemSKUNumber             : 740K6AV
SystemStartupDelay          : 
SystemStartupOptions        : 
SystemStartupSetting        : 
SystemType                  : x64-based PC
ThermalState                : 3
TotalPhysicalMemory         : 67864158208
UserName                    : AzureAD\DavidSegura
WakeUpType                  : 6
Workgroup                   : WORKGROUP
#>
Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -Property *
<#
AdminPasswordStatus         : 0
BootupState                 : Normal boot
ChassisBootupState          : 3
KeyboardPasswordStatus      : 0
PowerOnPasswordStatus       : 0
PowerSupplyState            : 3
PowerState                  : 0
FrontPanelResetStatus       : 0
ThermalState                : 3
Status                      : OK
Name                        : HPFIREFLY16P
PowerManagementCapabilities : 
PowerManagementSupported    : 
Caption                     : HPFIREFLY16P
Description                 : AT/AT COMPATIBLE
InstallDate                 : 
CreationClassName           : Win32_ComputerSystem
NameFormat                  : 
PrimaryOwnerContact         : 
PrimaryOwnerName            : HP Inc.
Roles                       : {LM_Workstation, LM_Server, NT}
InitialLoadInfo             : 
LastLoadInfo                : 
ResetCapability             : 1
AutomaticManagedPagefile    : True
AutomaticResetBootOption    : True
AutomaticResetCapability    : True
BootOptionOnLimit           : 
BootOptionOnWatchDog        : 
BootROMSupported            : True
BootStatus                  : {0, 0, 0, 11…}
ChassisSKUNumber            : 
CurrentTimeZone             : -300
DaylightInEffect            : True
DNSHostName                 : hpFirefly16P
Domain                      : WORKGROUP
DomainRole                  : 0
EnableDaylightSavingsTime   : True
HypervisorPresent           : True
InfraredSupported           : False
Manufacturer                : HP
Model                       : HP ZBook Firefly 16 inch G10 Mobile Workstation PC
NetworkServerModeEnabled    : True
NumberOfLogicalProcessors   : 20
NumberOfProcessors          : 1
OEMLogoBitmap               : 
OEMStringArray              : {FBYTE#476J6S6b7B7M7Q7U7W7m7saBapaqauawb8bUcAeMfDfPguhKhWhkjhk8mE, BUILDID#23WWWGBZ601#SABA#DABA;, EDK2_1, Buff=2…}
PartOfDomain                : False
PauseAfterReset             : -1
PCSystemType                : 2
PCSystemTypeEx              : 2
ResetCount                  : -1
ResetLimit                  : -1
SupportContactDescription   : 
SystemFamily                : 103C_5336AN HP ZBook
SystemSKUNumber             : 740K6AV
SystemStartupDelay          : 
SystemStartupOptions        : 
SystemStartupSetting        : 
SystemType                  : x64-based PC
TotalPhysicalMemory         : 67864158208
UserName                    : AzureAD\DavidSegura
WakeUpType                  : 6
Workgroup                   : WORKGROUP
PSComputerName              : 
CimClass                    : root/cimv2:Win32_ComputerSystem
CimInstanceProperties       : {Caption, Description, InstallDate, Name…}
CimSystemProperties         : Microsoft.Management.Infrastructure.CimSystemProperties
#>