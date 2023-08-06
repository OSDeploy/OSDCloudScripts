Get-WmiObject -Class Win32_Battery | Select-Object -Property *
<#
RunspaceId                  : 9847c798-6a8f-4d88-8d87-51487297bd29
__GENUS                     : 2
__CLASS                     : Win32_Battery
__SUPERCLASS                : CIM_Battery
__DYNASTY                   : CIM_ManagedSystemElement
__RELPATH                   : Win32_Battery.DeviceID="02678 2023/06/12Hewlett-PackardPrimary"
__PROPERTY_COUNT            : 33
__DERIVATION                : {CIM_Battery, CIM_LogicalDevice, CIM_LogicalElement, CIM_ManagedSystemElement}
__SERVER                    : HPFIREFLY16P
__NAMESPACE                 : root\cimv2
__PATH                      : \\HPFIREFLY16P\root\cimv2:Win32_Battery.DeviceID="02678 2023/06/12Hewlett-PackardPrimary"
Availability                : 3
BatteryRechargeTime         : 
BatteryStatus               : 1
Caption                     : Internal Battery
Chemistry                   : 2
ConfigManagerErrorCode      : 
ConfigManagerUserConfig     : 
CreationClassName           : Win32_Battery
Description                 : Internal Battery
DesignCapacity              : 
DesignVoltage               : 11742
DeviceID                    : 02678 2023/06/12Hewlett-PackardPrimary
ErrorCleared                : 
ErrorDescription            : 
EstimatedChargeRemaining    : 59
EstimatedRunTime            : 213
ExpectedBatteryLife         : 
ExpectedLife                : 
FullChargeCapacity          : 
InstallDate                 : 
LastErrorCode               : 
MaxRechargeTime             : 
Name                        : Primary
PNPDeviceID                 : 
PowerManagementCapabilities : {1}
PowerManagementSupported    : False
SmartBatteryVersion         : 
Status                      : OK
StatusInfo                  : 
SystemCreationClassName     : Win32_ComputerSystem
SystemName                  : HPFIREFLY16P
TimeOnBattery               : 
TimeToFullCharge            : 
#>
Get-CimInstance -ClassName Win32_Battery | Select-Object -Property *
<#
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
DesignVoltage               : 11383
EstimatedChargeRemaining    : 44
EstimatedRunTime            : 139
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