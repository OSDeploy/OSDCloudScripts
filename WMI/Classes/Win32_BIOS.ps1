Get-WmiObject -Class Win32_BIOS | Select-Object -Property *

<#
RunspaceId                     : 9847c798-6a8f-4d88-8d87-51487297bd29
__GENUS                        : 2
__CLASS                        : Win32_BIOS
__SUPERCLASS                   : CIM_BIOSElement
__DYNASTY                      : CIM_ManagedSystemElement
__RELPATH                      : Win32_BIOS.Name="V70 Ver. 01.01.08",SoftwareElementID="V70 Ver.
                                 01.01.08",SoftwareElementState=3,TargetOperatingSystem=0,Version="HPQOEM - 0"
__PROPERTY_COUNT               : 31
__DERIVATION                   : {CIM_BIOSElement, CIM_SoftwareElement, CIM_LogicalElement, CIM_ManagedSystemElement}
__SERVER                       : HPFIREFLY16P
__NAMESPACE                    : root\cimv2
__PATH                         : \\HPFIREFLY16P\root\cimv2:Win32_BIOS.Name="V70 Ver. 01.01.08",SoftwareElementID="V70 Ver.
                                 01.01.08",SoftwareElementState=3,TargetOperatingSystem=0,Version="HPQOEM - 0"
BiosCharacteristics            : {7, 8, 11, 12…}
BIOSVersion                    : {HPQOEM - 0, V70 Ver. 01.01.08, HP - 1010800}
BuildNumber                    : 
Caption                        : V70 Ver. 01.01.08
CodeSet                        : 
CurrentLanguage                : enUS
Description                    : V70 Ver. 01.01.08
EmbeddedControllerMajorVersion : 81
EmbeddedControllerMinorVersion : 43
IdentificationCode             : 
InstallableLanguages           : 15
InstallDate                    : 
LanguageEdition                : 
ListOfLanguages                : {enUS, deDE, esES, itIT…}
Manufacturer                   : HP
Name                           : V70 Ver. 01.01.08
OtherTargetOS                  : 
PrimaryBIOS                    : True
ReleaseDate                    : 20230530000000.000000+000
SerialNumber                   : 5CG3281NM4
SMBIOSBIOSVersion              : V70 Ver. 01.01.08
SMBIOSMajorVersion             : 3
SMBIOSMinorVersion             : 4
SMBIOSPresent                  : True
SoftwareElementID              : V70 Ver. 01.01.08
SoftwareElementState           : 3
Status                         : OK
SystemBiosMajorVersion         : 1
SystemBiosMinorVersion         : 8
TargetOperatingSystem          : 0
Version                        : HPQOEM - 0
#>

Get-CimInstance -ClassName Win32_BIOS | Select-Object -Property *
<#
Status                         : OK
Name                           : V70 Ver. 01.01.08
Caption                        : V70 Ver. 01.01.08
SMBIOSPresent                  : True
Description                    : V70 Ver. 01.01.08
InstallDate                    : 
BuildNumber                    : 
CodeSet                        : 
IdentificationCode             : 
LanguageEdition                : 
Manufacturer                   : HP
OtherTargetOS                  : 
SerialNumber                   : 5CG3281NM4
SoftwareElementID              : V70 Ver. 01.01.08
SoftwareElementState           : 3
TargetOperatingSystem          : 0
Version                        : HPQOEM - 0
PrimaryBIOS                    : True
BiosCharacteristics            : {7, 8, 11, 12…}
BIOSVersion                    : {HPQOEM - 0, V70 Ver. 01.01.08, HP - 1010800}
CurrentLanguage                : enUS
EmbeddedControllerMajorVersion : 81
EmbeddedControllerMinorVersion : 43
InstallableLanguages           : 15
ListOfLanguages                : {enUS, deDE, esES, itIT…}
ReleaseDate                    : 5/29/2023 7:00:00 PM
SMBIOSBIOSVersion              : V70 Ver. 01.01.08
SMBIOSMajorVersion             : 3
SMBIOSMinorVersion             : 4
SystemBiosMajorVersion         : 1
SystemBiosMinorVersion         : 8
PSComputerName                 : 
CimClass                       : root/cimv2:Win32_BIOS
CimInstanceProperties          : {Caption, Description, InstallDate, Name…}
CimSystemProperties            : Microsoft.Management.Infrastructure.CimSystemProperties
#>