Get-CimInstance -ClassName CIM_ComputerSystem | Select-Object -Property *
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