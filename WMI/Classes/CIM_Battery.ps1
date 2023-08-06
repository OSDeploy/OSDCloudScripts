Get-CimInstance -ClassName CIM_Battery | Select-Object -Property *
<#
Caption                     : Portable Battery
Description                 : Portable Battery
InstallDate                 : 
Name                        : WP06076XL
Status                      : 
Availability                : 
ConfigManagerErrorCode      : 
ConfigManagerUserConfig     : 
CreationClassName           : Win32_PortableBattery
DeviceID                    : Portable Battery 0
ErrorCleared                : 
ErrorDescription            : 
LastErrorCode               : 
PNPDeviceID                 : 
PowerManagementCapabilities : 
PowerManagementSupported    : 
StatusInfo                  : 
SystemCreationClassName     : Win32_ComputerSystem
SystemName                  : HPFIREFLY16P
BatteryStatus               : 
Chemistry                   : 2
DesignCapacity              : 76020
DesignVoltage               : 11580
EstimatedChargeRemaining    : 
EstimatedRunTime            : 
ExpectedLife                : 
FullChargeCapacity          : 
MaxRechargeTime             : 
SmartBatteryVersion         : 1.1
TimeOnBattery               : 
TimeToFullCharge            : 
CapacityMultiplier          : 10
Location                    : Primary
ManufactureDate             : 
Manufacturer                : 333-17-25-A
MaxBatteryError             : 0
PSComputerName              : 
CimClass                    : root/cimv2:Win32_PortableBattery
CimInstanceProperties       : {Caption, Description, InstallDate, Name…}
CimSystemProperties         : Microsoft.Management.Infrastructure.CimSystemProperties

Caption                     : Internal Battery
Description                 : Internal Battery
InstallDate                 : 
Name                        : Primary
Status                      : OK
Availability                : 3
ConfigManagerErrorCode      : 
ConfigManagerUserConfig     : 
CreationClassName           : Win32_Battery
DeviceID                    : 02678 2023/06/12Hewlett-PackardPrimary
ErrorCleared                : 
ErrorDescription            : 
LastErrorCode               : 
PNPDeviceID                 : 
PowerManagementCapabilities : {1}
PowerManagementSupported    : False
StatusInfo                  : 
SystemCreationClassName     : Win32_ComputerSystem
SystemName                  : HPFIREFLY16P
BatteryStatus               : 1
Chemistry                   : 2
DesignCapacity              : 
DesignVoltage               : 11400
EstimatedChargeRemaining    : 46
EstimatedRunTime            : 145
ExpectedLife                : 
FullChargeCapacity          : 
MaxRechargeTime             : 
SmartBatteryVersion         : 
TimeOnBattery               : 
TimeToFullCharge            : 
BatteryRechargeTime         : 
ExpectedBatteryLife         : 
PSComputerName              : 
CimClass                    : root/cimv2:Win32_Battery
CimInstanceProperties       : {Caption, Description, InstallDate, Name…}
CimSystemProperties         : Microsoft.Management.Infrastructure.CimSystemProperties
#>