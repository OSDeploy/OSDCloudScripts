Get-WmiObject -Class Win32_BaseBoard | Select-Object -Property *
<#
RunspaceId              : 9847c798-6a8f-4d88-8d87-51487297bd29
__GENUS                 : 2
__CLASS                 : Win32_BaseBoard
__SUPERCLASS            : CIM_Card
__DYNASTY               : CIM_ManagedSystemElement
__RELPATH               : Win32_BaseBoard.Tag="Base Board"
__PROPERTY_COUNT        : 29
__DERIVATION            : {CIM_Card, CIM_PhysicalPackage, CIM_PhysicalElement, CIM_ManagedSystemElement}
__SERVER                : HPFIREFLY16P
__NAMESPACE             : root\cimv2
__PATH                  : \\HPFIREFLY16P\root\cimv2:Win32_BaseBoard.Tag="Base Board"
Caption                 : Base Board
ConfigOptions           : 
CreationClassName       : Win32_BaseBoard
Depth                   : 
Description             : Base Board
Height                  : 
HostingBoard            : True
HotSwappable            : False
InstallDate             : 
Manufacturer            : HP
Model                   : 
Name                    : Base Board
OtherIdentifyingInfo    : 
PartNumber              : 
PoweredOn               : True
Product                 : 8B41
Removable               : False
Replaceable             : False
RequirementsDescription : 
RequiresDaughterBoard   : False
SerialNumber            : PRTUD00WBIB1R5
SKU                     : 
SlotLayout              : 
SpecialRequirements     : 
Status                  : OK
Tag                     : Base Board
Version                 : KBC Version 51.2B.00
Weight                  : 
Width                   : 
#>
Get-CimInstance -ClassName Win32_BaseBoard | Select-Object -Property *
<#
Status                  : OK
Name                    : Base Board
PoweredOn               : True
Caption                 : Base Board
Description             : Base Board
InstallDate             : 
CreationClassName       : Win32_BaseBoard
Manufacturer            : HP
Model                   : 
OtherIdentifyingInfo    : 
PartNumber              : 
SerialNumber            : PRTUD00WBIB1R5
SKU                     : 
Tag                     : Base Board
Version                 : KBC Version 51.2B.00
Depth                   : 
Height                  : 
HotSwappable            : False
Removable               : False
Replaceable             : False
Weight                  : 
Width                   : 
HostingBoard            : True
RequirementsDescription : 
RequiresDaughterBoard   : False
SlotLayout              : 
SpecialRequirements     : 
ConfigOptions           : 
Product                 : 8B41
PSComputerName          : 
CimClass                : root/cimv2:Win32_BaseBoard
CimInstanceProperties   : {Caption, Description, InstallDate, Name…}
CimSystemProperties     : Microsoft.Management.Infrastructure.CimSystemProperties
#>