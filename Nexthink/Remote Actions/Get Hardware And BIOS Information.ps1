<#
.SYNOPSIS
Returns information about device hardware e.g. GPU, RAM, disks and BIOS.

.DESCRIPTION
Returns detailed information concerning the Graphics Processing Unit (GPU) and RAM installed on the device. Additionally, the script obtains the serial numbers and types of the installed disks, as well as the BIOS version and release date.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   GPUName                         StringList      Name of the graphics card installed on the device
2   GPUDriverVendor                 StringList      Provider of the graphics card driver
3   GPUDriverVersion                StringList      Version of the graphics card driver
4   DiskSerialNumberAndType         StringList      For each installed disk drive, the number allocated by the manufacturer to identify the physical media and its type (HDD/SDD)
5   TotalRAMSlots                   Int             Total number of memory slots available on the device
6   MaximumRAM                      Size            Maximum total amount of RAM that can be installed on the device
7   UsedRAMSlots                    Int             Number of memory slots currently used
8   InstalledRAM                    Size            Amount of RAM currently installed
9   RAMBankCapacity                 StringList      Capacity of each installed memory bank
10  RAMBankDeviceLocator            StringList      For each installed memory bank, label of the socket or circuit board that holds the memory
11  RAMBankFormFactor               StringList      For each installed memory bank, implementation form factor for the chip
12  RAMBankManufacturer             StringList      For each installed bank, name of the organization responsible for producing the physical element
13  RAMBankPartNumber               StringList      For each installed bank, part number assigned by the organization responsible for producing or manufacturing the physical element
14  RAMBankSerialNumber             StringList      For each installed bank, manufacturer-allocated number to identify the physical element
15  RAMBankSpeed                    StringList      For each installed memory bank, speed of the physical memory, in nanoseconds
16  RAMBankVoltage                  StringList      For each installed memory bank, configured voltage for this device, in millivolts
17  RAMBankTotalWidth               StringList      For each installed memory bank, total width, in bits, of the physical memory, including check or error correction bits
18  RegistryBIOSVersion             String          BIOS version installed on the device obtained from the registry
19  ManagementBiosVersion           String          BIOS version installed on the device obtained from the WMI Object 'Win32_BIOS'
20  BIOSDate                        String          BIOS release date installed on the device

.FURTHER INFORMATION
Disk type functionality is only available for Windows 10 systems. When not possible to retrieve such information, 'Unknown' will be displayed.

.NOTES
Context:            LocalSystem
Version:            3.0.1.0 - Fixed bug in RegistryBIOSVersion output
                    3.0.0.2 - Updated to fix delivery issues
                    3.0.0.1 - Fixed typo in Test-MinimumWindowsVersion
                    3.0.0.0 - Replaced management data retrieval functions
                    2.2.0.0 - Updated BIOSDate output type from date to string
                    2.1.0.0 - New functionality to get the BIOS info from the WMI Object 'win32_bios' in addition to the registry one
                    2.0.0.0 - Major refactoring performed and disk type functionality added
                    1.0.0.0 - Initial release
Last Generated:     09 Jun 2022 - 10:44:31
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#

# End of parameters definition

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0"

#
# Constants definition
#
New-Variable -Name 'DEFAULT_DATE' `
    -Value ([datetime]::ParseExact('01/01/1970 00:00:00.000Z',
                                   'dd/MM/yyyy HH:mm:ss.fffK',
                                   [globalization.cultureinfo]::InvariantCulture,
                                   [globalization.datetimestyles]::None)) `
    -Option ReadOnly -Scope Script
New-Variable -Name 'ERROR_EXCEPTION_TYPE' `
    -Value @{Environment = '[Environment error]'
             Input = '[Input error]'
             Internal = '[Internal error]'} `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'WINDOWS_VERSIONS' `
    -Value @{Windows7 = '6.1'
             Windows8 = '6.2'
             Windows81 = '6.3'
             Windows10 = '10.0'
             Windows11 = '10.0'} `
    -Option ReadOnly -Scope Script

New-Variable -Name 'UNKNOWN_MEDIA_TYPE' `
    -Value 'Unknown' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'DEFAULT_DATE' `
    -Value ([datetime]::ParseExact('01/01/1970 00:00:00.000Z',
                                   'dd/MM/yyyy HH:mm:ss.fffK',
                                   [globalization.cultureinfo]::InvariantCulture,
                                   [globalization.datetimestyles]::None)) `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'BIOS_DATE_STRING_FORMAT' `
    -Value 'yyyy\/MM\/dd HH:mm:ssK' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'CIM_NAMESPACE' `
    -Value 'root\cimv2' `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main {
    $exitCode = 0
    [hashtable]$HardwareAndBIOSInfo = Initialize-HardwareAndBIOSInfo

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows7' -SupportedWindowsServer

        Get-HardwareAndBIOSInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    }

    return $exitCode
}

#
# Template functions
#
function Add-NexthinkRemoteActionDLL {

    if (-not (Test-Path -Path $REMOTE_ACTION_DLL_PATH)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink Remote Action DLL not found. "
    }
    Add-Type -Path $REMOTE_ACTION_DLL_PATH
}

function Test-RunningAsLocalSystem {

    if (-not (Confirm-CurrentUserIsLocalSystem)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script must be run as LocalSystem. "
    }
}

function Confirm-CurrentUserIsLocalSystem {

    $currentIdentity = Get-CurrentIdentity
    return $currentIdentity -eq $LOCAL_SYSTEM_IDENTITY
}

function Get-CurrentIdentity {

    return [security.principal.windowsidentity]::GetCurrent().User.ToString()
}

function Test-MinimumSupportedOSVersion ([string]$WindowsVersion, [switch]$SupportedWindowsServer) {
    $currentOSInfo = Get-OSVersionType
    $OSVersion = $currentOSInfo.Version -as [version]

    $supportedWindows = $WINDOWS_VERSIONS.$WindowsVersion -as [version]

    if (-not ($currentOSInfo)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script could not return OS version. "
    }

    if ( $SupportedWindowsServer -eq $false -and $currentOSInfo.ProductType -ne 1) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is not compatible with Windows Servers. "
    }

    if ( $OSVersion -lt $supportedWindows) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is compatible with $WindowsVersion and later only. "
    }
}

function Get-OSVersionType {

    return Get-WindowsManagementData -Class Win32_OperatingSystem | Select-Object -Property Version,ProductType
}

function Get-WindowsManagementData ([string]$Class, [string]$Namespace = 'root/cimv2') {
    try {
        $query = [wmisearcher] "Select * from $Class"
        $query.Scope.Path = "$Namespace"
        $query.Get()
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Error getting CIM/WMI information. Verify WinMgmt service status and WMI repository consistency. "
    }
}

function Write-StatusMessage ([psobject]$Message) {
    $exceptionMessage = $Message.ToString()

    if ($Message.InvocationInfo.ScriptLineNumber) {
        $version = Get-ScriptVersion
        if (-not [string]::IsNullOrEmpty($version)) {
            $scriptVersion = "Version: $version. "
        }

        $errorMessageLine = $scriptVersion + "Line '$($Message.InvocationInfo.ScriptLineNumber)': "
    }

    $host.ui.WriteErrorLine($errorMessageLine + $exceptionMessage)
}

function Get-ScriptVersion {

    $scriptContent = Get-Content $MyInvocation.ScriptName | Out-String
    if ($scriptContent -notmatch '<#[\r\n]{2}.SYNOPSIS[^\#\>]*(.NOTES[^\#\>]*)\#>') { return }

    $helpBlock = $Matches[1].Split([environment]::NewLine)

    foreach ($line in $helpBlock) {
        if ($line -match 'Version:') {
            return $line.Split(':')[1].Split('-')[0].Trim()
        }
    }
}

function Initialize-HardwareAndBIOSInfo {
    return @{
        BIOSDate = $DEFAULT_DATE
        RegistryBIOSVersion = '-'
        ManagementBiosVersion = '-'

        DiskSerialNumberAndType = [string[]]@()

        TotalRAMSlots = 0
        MaximumRAM = 0
        UsedRAMSlots = 0
        InstalledRAM = 0
        RAMBankCapacity = [string[]]@()
        RAMBankDeviceLocator = [string[]]@()
        RAMBankFormFactor = [string[]]@()
        RAMBankManufacturer = [string[]]@()
        RAMBankPartNumber = [string[]]@()
        RAMBankSerialNumber = [string[]]@()
        RAMBankSpeed = [string[]]@()
        RAMBankVoltage = [string[]]@()
        RAMBankTotalWidth = [string[]]@()

        GPUName = [string[]]@()
        GPUDriverVendor = [string[]]@()
        GPUDriverVersion = [string[]]@()
    }
}

function Get-HardwareAndBIOSInfo ([hashtable]$HardwareAndBIOSInfo) {
    Get-BIOSInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    Get-DiskInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    Get-RAMInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    Get-GPUsInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
}

# BIOS Info management

function Get-BIOSInfo ([hashtable]$HardwareAndBIOSInfo) {
    Get-RegistryBIOSInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    Get-ManagementBiosInfo -HardwareAndBIOSInfo $HardwareAndBIOSInfo
}

function Get-RegistryBIOSInfo ([hashtable]$HardwareAndBIOSInfo) {
    Get-RegistryBIOSDate -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    Get-RegistryBIOSVersion -HardwareAndBIOSInfo $HardwareAndBIOSInfo
}

function Get-RegistryBIOSDate ([hashtable]$HardwareAndBIOSInfo) {
    $BIOSKey = 'BiosReleaseDate'
    [version]$OSVersion = (Get-OSVersionType).Version

    if ( $OSVersion.Major -lt 10) {
        $BIOSKey = 'SystemBiosDate'
    }

    $BIOSInfo = Get-RegistryBIOSData -BiosValue $BIOSKey

    if ($null -ne $BIOSInfo) {
        $HardwareAndBIOSInfo.BIOSDate = $BIOSInfo
    }
}

function Get-RegistryBIOSData ($BIOSValue) {
    $dateFormated = $DEFAULT_DATE
    $BIOSRawData = Get-ChildItem -Recurse 'HKLM:\HARDWARE' |
                                 Where-Object { $_.Name -like '*BIOS' } |
                                 Get-ItemProperty

    if ($null -ne $BIOSRawData.$BIOSValue) {
        $BIOSInfo = $BIOSRawData.$BIOSValue
    }

    if ([datetime]::TryParse($BIOSInfo, [ref]$dateFormated)) {
            $BIOSInfo = $dateFormated
    }

    return $BIOSInfo
}

function Get-RegistryBIOSVersion ([hashtable]$HardwareAndBIOSInfo) {
    $BIOSVendorKey = 'BiosVendor'
    $BIOSVersionKey = 'BiosVersion'

    $BIOSVendorValue = Get-RegistryBIOSData -BiosValue $BIOSVendorKey
    $BIOSVersionValue = Get-RegistryBIOSData -BiosValue $BIOSVersionKey

    if (-not ([string]::IsNullOrEmpty($BIOSVendorValue)) -or `
        -not ([string]::IsNullOrEmpty($BIOSVersionValue))) {

        $HardwareAndBIOSInfo.RegistryBIOSVersion = `
                Format-StringItem $("$BIOSVendorValue $BIOSVersionValue".Trim())
    }
}

function Format-StringItem ([string]$Item) {
    return $(if([string]::IsNullOrEmpty($Item)) { '-' } else { $Item.Trim() })
}

function Get-ManagementBiosInfo ([hashtable]$HardwareAndBIOSInfo) {
    $BIOSInfo = Get-WindowsManagementData -Class Win32_BIOS
    if ($null -ne $BIOSInfo) {
        if ($HardwareAndBIOSInfo.BIOSDate -eq $DEFAULT_DATE) {
            Update-BIOSDateWithManagement -BIOSInfo $BIOSInfo `
                                          -HardwareAndBIOSInfo $HardwareAndBIOSInfo
        }
        Get-ManagementBiosVersion -BIOSInfo $BIOSInfo `
                                  -HardwareAndBIOSInfo $HardwareAndBIOSInfo
    } else {
        Write-StatusMessage -Message 'Management object Win32_BIOS could not be retrieved. '
    }
}

function Update-BIOSDateWithManagement ([object]$BIOSInfo, [hashtable]$HardwareAndBIOSInfo) {
    if ($null -ne $BIOSInfo.ReleaseDate) {
        $HardwareAndBIOSInfo.BIOSDate = $BIOSInfo.ConvertToDateTime($BIOSInfo.ReleaseDate)
    }
}

function Get-ManagementBiosVersion ([object]$BIOSInfo, [hashtable]$HardwareAndBIOSInfo) {
    $CompleteVersion = (($BIOSInfo.Version, `
                         $BIOSInfo.SMBIOSBIOSVersion, `
                         $BIOSInfo.Manufacturer) | Where-Object {$_.Trim()}) -Join ' '
    $HardwareAndBIOSInfo.ManagementBiosVersion = Format-StringItem -Item $CompleteVersion
}

#Disk Info management

function Get-DiskInfo ([hashtable]$HardwareAndBIOSInfo) {
    $disksInfo = @{}

    Update-DisksSerialNumbers -DisksInfo $disksInfo

    if (Test-DiskTypeAvailable) {
        Update-DisksTypes -DisksInfo $disksInfo
    }

    Export-DisksSerialNumberAndTypes -DisksInfo $disksInfo `
                                     -HardwareAndBIOSInfo $HardwareAndBIOSInfo
}

function Update-DisksSerialNumbers ([hashtable]$DisksInfo) {
    $disks = @(Get-DisksSerialNumbers)
    foreach ($d in $disks) {
        $serialNumber = $d.SerialNumber
        $DisksInfo.$serialNumber = $UNKNOWN_MEDIA_TYPE
    }
}

function Get-DisksSerialNumbers {
    $CIMParameters = @{
        Class = 'Win32_DiskDrive'
        Namespace = $CIM_NAMESPACE
    }
    $disks = Get-WindowsManagementData @CIMParameters |
        Where-Object {
            $_.MediaType -eq 'Fixed hard disk media' -and
            -not [string]::IsNullOrEmpty($_.SerialNumber)
        } | Select-Object SerialNumber

    return $(if ($null -eq $disks) { @() } else { $disks })
}

function Test-DiskTypeAvailable {
    return $null -ne (Get-Command 'Get-PhysicalDisk' -ErrorAction SilentlyContinue)
}

function Update-DisksTypes ([hashtable]$DisksInfo) {
    $physicalDisks = @(Get-WindowsManagementData -Class 'Win32_DiskDrive' -Namespace $CIM_NAMESPACE |
        Select-Object SerialNumber, MediaType)

    foreach ($disk in $physicalDisks) {
        $serialNumber = $disk.SerialNumber

        if (-not [string]::IsNullOrEmpty($serialNumber) -and $DisksInfo.ContainsKey($serialNumber)) {
            $mediaType = $disk.MediaType

            if (-not ([string]::IsNullOrEmpty($mediaType))) {
                $DisksInfo.$serialNumber = $mediaType
            }
        }
    }
}

function Export-DisksSerialNumberAndTypes ([hashtable]$DisksInfo,
                                           [hashtable]$HardwareAndBIOSInfo) {
    foreach ($serialNumber in $DisksInfo.Keys) {
        $mediaType = $DisksInfo.$serialNumber
        $output = Format-StringItem -Item "$serialNumber ($mediaType)"
        [string[]]$HardwareAndBIOSInfo.DiskSerialNumberAndType += $output
    }
}

#RAM Info management

function Get-RAMInfo ([hashtable]$HardwareAndBIOSInfo) {
    $memorySlot = Get-MemorySlotInfo
    if ($null -ne $memorySlot) {
        $HardwareAndBIOSInfo.MaximumRAM = $memorySlot.MaxCapacity * 1024
        $HardwareAndBIOSInfo.TotalRAMSlots = $memorySlot.MemoryDevices
    }

    $memoryBanks = @(Get-MemoryBanksInfo)
    foreach ($memory in $memoryBanks) {
        [string[]]$HardwareAndBIOSInfo.RAMBankCapacity += `
            Format-StringItem -Item ([uint32]($memory.Capacity / 1024 / 1024))
        [string[]]$HardwareAndBIOSInfo.RAMBankDeviceLocator += `
            Format-StringItem -Item $memory.DeviceLocator
        [string[]]$HardwareAndBIOSInfo.RAMBankFormFactor += `
            Get-FormFactor -Code $memory.FormFactor
        [string[]]$HardwareAndBIOSInfo.RAMBankManufacturer += `
            Format-StringItem -Item $memory.Manufacturer
        [string[]]$HardwareAndBIOSInfo.RAMBankPartNumber += `
            Format-StringItem -Item $memory.PartNumber
        [string[]]$HardwareAndBIOSInfo.RAMBankSerialNumber += `
            Format-StringItem -Item $memory.SerialNumber
        [string[]]$HardwareAndBIOSInfo.RAMBankSpeed += `
            Format-StringItem -Item $memory.Speed
        [string[]]$HardwareAndBIOSInfo.RAMBankVoltage += `
            Format-StringItem -Item $memory.ConfiguredVoltage
        [string[]]$HardwareAndBIOSInfo.RAMBankTotalWidth += `
            Format-StringItem -Item $memory.TotalWidth
    }

    $memoryMeasure = Get-MemoryMetrics
    if ($null -ne $memoryMeasure) {
        $HardwareAndBIOSInfo.UsedRAMSlots = $memoryMeasure.Count
        $HardwareAndBIOSInfo.InstalledRAM = $memorymeasure.Sum
    }
}

function Get-MemorySlotInfo {
    return Get-WindowsManagementData -Class Win32_PhysicalMemoryArray -Namespace $CIM_NAMESPACE
}

function Get-MemoryBanksInfo {
    $banks = Get-WindowsManagementData -Class Win32_PhysicalMemory -Namespace $CIM_NAMESPACE

    return $(if ($null -eq $banks) { @() } else { $banks })
}

function Get-FormFactor ([uint16]$Code) {
    if ($Code -lt 0 -or $Code -gt 22) { return "$Code - Undefined value" }

    $result = switch ($Code) {
        0    { 'Unknown' }
        1    { 'Other' }
        2    { 'SIP' }
        3    { 'DIP' }
        4    { 'ZIP' }
        5    { 'SOJ' }
        6    { 'Proprietary' }
        7    { 'SIMM' }
        8    { 'DIMM' }
        9    { 'TSOPO' }
        10   { 'PGA' }
        11   { 'RIM' }
        12   { 'SODIMM' }
        13   { 'SRIMM' }
        14   { 'SMD' }
        15   { 'SSMP' }
        16   { 'QFP' }
        17   { 'TQFP' }
        18   { 'SOIC' }
        19   { 'LCC' }
        20   { 'PLCC' }
        21   { 'FPGA' }
        22   { 'LGA' }
    }

    return '{0} - {1}' -f $Code.ToString('00'), $result
}

function Get-MemoryMetrics {
    return Get-WindowsManagementData -Class Win32_PhysicalMemory -Namespace $CIM_NAMESPACE |
               Measure-Object -Property Capacity -Sum -ErrorAction SilentlyContinue
}

# GPU Info management

function Get-GPUsInfo ([hashtable]$HardwareAndBIOSInfo) {
    $GPUsInfo = @(Get-DisplayInfo)

    if ($null -ne $GPUsInfo) {
        foreach ($Gpu in $GPUsInfo) {
            [string[]]$HardwareAndBIOSInfo.GPUName += Format-StringItem -Item $Gpu.DeviceName
            [string[]]$HardwareAndBIOSInfo.GPUDriverVendor += Format-StringItem -Item $Gpu.DriverProviderName
            [string[]]$HardwareAndBIOSInfo.GPUDriverVersion += Format-StringItem -Item $Gpu.DriverVersion
        }
    }
}

function Get-DisplayInfo {
    $displayInfo = @()

    $displayInfo = Get-WindowsManagementData -Class Win32_PnPSignedDriver -Namespace $CIM_NAMESPACE |
        Where-Object { $_.DeviceClass -like 'Display' } |
        Select-Object DeviceName, DriverVersion, DriverProviderName

    return $displayInfo
}
#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$HardwareAndBIOSInfo) {
    [nxt]::WriteOutputString('RegistryBIOSVersion', $HardwareAndBIOSInfo.RegistryBIOSVersion)
    [nxt]::WriteOutputString('ManagementBiosVersion', $HardwareAndBIOSInfo.ManagementBiosVersion)
    [nxt]::WriteOutputString('BIOSDate', $HardwareAndBIOSInfo.BIOSDate.ToString($BIOS_DATE_STRING_FORMAT))
    [nxt]::WriteOutputStringList('DiskSerialNumberAndType', $HardwareAndBIOSInfo.DiskSerialNumberAndType)
    [nxt]::WriteOutputUInt32('TotalRAMSlots', $HardwareAndBIOSInfo.TotalRAMSlots);
    [nxt]::WriteOutputSize('MaximumRAM', $HardwareAndBIOSInfo.MaximumRAM);
    [nxt]::WriteOutputUInt32('UsedRAMSlots', $HardwareAndBIOSInfo.UsedRAMSlots);
    [nxt]::WriteOutputSize('InstalledRAM', $HardwareAndBIOSInfo.InstalledRAM);
    [nxt]::WriteOutputStringList('RAMBankCapacity', $HardwareAndBIOSInfo.RAMBankCapacity)
    [nxt]::WriteOutputStringList('RAMBankDeviceLocator', $HardwareAndBIOSInfo.RAMBankDeviceLocator)
    [nxt]::WriteOutputStringList('RAMBankFormFactor', $HardwareAndBIOSInfo.RAMBankFormFactor)
    [nxt]::WriteOutputStringList('RAMBankManufacturer', $HardwareAndBIOSInfo.RAMBankManufacturer)
    [nxt]::WriteOutputStringList('RAMBankPartNumber', $HardwareAndBIOSInfo.RAMBankPartNumber)
    [nxt]::WriteOutputStringList('RAMBankSerialNumber', $HardwareAndBIOSInfo.RAMBankSerialNumber)
    [nxt]::WriteOutputStringList('RAMBankSpeed', $HardwareAndBIOSInfo.RAMBankSpeed)
    [nxt]::WriteOutputStringList('RAMBankVoltage', $HardwareAndBIOSInfo.RAMBankVoltage)
    [nxt]::WriteOutputStringList('RAMBankTotalWidth', $HardwareAndBIOSInfo.RAMBankTotalWidth)
    [nxt]::WriteOutputStringList('GPUName', $HardwareAndBIOSInfo.GPUName)
    [nxt]::WriteOutputStringList('GPUDriverVendor', $HardwareAndBIOSInfo.GPUDriverVendor)
    [nxt]::WriteOutputStringList('GPUDriverVersion', $HardwareAndBIOSInfo.GPUDriverVersion)
}
#
# Main script flow
#
[environment]::Exit((Invoke-Main))
# SIG # Begin signature block
# MIImzgYJKoZIhvcNAQcCoIImvzCCJrsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD/vxEp3QBPUom5
# HvoL2LPO/41TzXsXU8oj33kWuANWhaCCETswggPFMIICraADAgECAhACrFwmagtA
# m48LefKuRiV3MA0GCSqGSIb3DQEBBQUAMGwxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xKzApBgNV
# BAMTIkRpZ2lDZXJ0IEhpZ2ggQXNzdXJhbmNlIEVWIFJvb3QgQ0EwHhcNMDYxMTEw
# MDAwMDAwWhcNMzExMTEwMDAwMDAwWjBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQD
# EyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxszlc+b71LvlLS0ypt/lgT/JzSVJtnEqw9WU
# NGeiChywX2mmQLHEt7KP0JikqUFZOtPclNY823Q4pErMTSWC90qlUxI47vNJbXGR
# fmO2q6Zfw6SE+E9iUb74xezbOJLjBuUIkQzEKEFV+8taiRV+ceg1v01yCT2+OjhQ
# W3cxG42zxyRFmqesbQAUWgS3uhPrUQqYQUEiTmVhh4FBUKZ5XIneGUpX1S7mXRxT
# LH6YzRoGFqRoc9A0BBNcoXHTWnxV215k4TeHMFYE5RG0KYAS8Xk5iKICEXwnZreI
# t3jyygqoOKsKZMK/Zl2VhMGhJR6HXRpQCyASzEG7bgtROLhLywIDAQABo2MwYTAO
# BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUsT7DaQP4
# v0cB1JgmGggC72NkK8MwHwYDVR0jBBgwFoAUsT7DaQP4v0cB1JgmGggC72NkK8Mw
# DQYJKoZIhvcNAQEFBQADggEBABwaBpfc15yfPIhmBghXIdshR/gqZ6q/GDJ2QBBX
# wYrzetkRZY41+p78RbWe2UwxS7iR6EMsjrN4ztvjU3lx1uUhlAHaVYeaJGT2imbM
# 3pw3zag0sWmbI8ieeCIrcEPjVUcxYRnvWMWFL04w9qAxFiPI5+JlFjPLvxoboD34
# yl6LMYtgCIktDAZcUrfE+QqY0RVfnxK+fDZjOL1EpH/kJisKxJdpDemM4sAQV7jI
# dhKRVfJIadi8KgJbD0TUIDHb9LpwJl2QYJ68SxcJL7TLHkNoyQcnwdJc9+ohuWgS
# nDycv578gFybY83sR6olJ2egN/MAgn1U16n46S4To3foH0owggauMIIFlqADAgEC
# AhAKGg0bco+UuLdwFCB8KgrEMA0GCSqGSIb3DQEBCwUAMGwxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xKzApBgNVBAMTIkRpZ2lDZXJ0IEVWIENvZGUgU2lnbmluZyBDQSAoU0hBMikw
# HhcNMjAwODE3MDAwMDAwWhcNMjMwODIyMTIwMDAwWjCBwDETMBEGCysGAQQBgjc8
# AgEDEwJDSDEVMBMGCysGAQQBgjc8AgECEwRWYXVkMR0wGwYDVQQPDBRQcml2YXRl
# IE9yZ2FuaXphdGlvbjEYMBYGA1UEBRMPQ0hFLTExMi4wMDAuNTc5MQswCQYDVQQG
# EwJDSDEPMA0GA1UEBxMGUHJpbGx5MRYwFAYDVQQKEw1ORVhUaGluayBTLkEuMQsw
# CQYDVQQLEwJSRDEWMBQGA1UEAxMNTkVYVGhpbmsgUy5BLjCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBALMbr8k5B4UT7E9+6Skoa3Ihy8v6vSHWa5TfptPn
# B1JQ7Bgsw6EDCI/HrIlcRRF+feXGYPYakJ5ng1ckM22u/FtAmrlhb5VLFOeMiub/
# R5cPQ6IhjdCnTiVPrBbYevCmyHOTdqc74GFygBK+g/ZLZqOWJDkhwVimTNTP1RO/
# Bec3JI3rr0CuIqqGvCt/TucPszVyuKRViw5gvMkawQvfwT8MmLfFkr98lt4BlTZG
# SkoPumES+bJdWMTtdTfZIk+KQv60oWmsWlI/Lxe+m1qInCEDLFnSsQIN+HGkabW5
# UiEJ6bDjZCIB5PhQXjv0WXLTGZqTcbBeBLIAn06L9TIH6oCG87QlrXdysODcaqiQ
# SkAJ7bXQscfWsRHWPrRzU36A2mOxDKERGxH3iPDxfV9NAEb8hdFTfxJRMa+hEAqt
# 6qx4PuUZbu7m8Trh+fHKo5S9bwXkYmi0TDONpYEQmb7+lefcHqLNaIgpfdK5h/0V
# lUlpDwlNGXMfE2aBhNR6L5O99r11Y2qJA1OmMBcPNoY7ljXmdMHu1V9/DE0JK4OY
# VxbnUVMqTf3/VgZxGecYMMfamjv42sPFvMdaCj8C3N4c0d4sWOltJkjCmi5fKw9y
# UGLzUzWOfx9y0aTQn9Sd/y68cBP/Jl/1kws3xP4Orszl5vAFenTQwtOHLgsok0EF
# FuaLAgMBAAGjggH1MIIB8TAfBgNVHSMEGDAWgBSP6H7wbTJqAAUjx3CXajqQ/2vq
# 1DAdBgNVHQ4EFgQUUluozPCIoYByuD4dVBcClbw4638wMgYDVR0RBCswKaAnBggr
# BgEFBQcIA6AbMBkMF0NILVZBVUQtQ0hFLTExMi4wMDAuNTc5MA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzB7BgNVHR8EdDByMDegNaAzhjFodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRVZDb2RlU2lnbmluZ1NIQTItZzEuY3JsMDeg
# NaAzhjFodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRVZDb2RlU2lnbmluZ1NIQTIt
# ZzEuY3JsMEsGA1UdIAREMEIwNwYJYIZIAYb9bAMCMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwBwYFZ4EMAQMwfgYIKwYBBQUHAQEE
# cjBwMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSAYIKwYB
# BQUHMAKGPGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEVWQ29k
# ZVNpZ25pbmdDQS1TSEEyLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUA
# A4IBAQAY6IB4PnNczhdemVVidtT8XT0P+/Ej9bbaMImR6HELTcYX19gjksFNUrR6
# /XUPgaj/nSplr5Oj3DJ5JCPo2AVKwY1mUWS2uYoZRinEAodDfESqfTiR1982xp72
# go347GTMnppk2EpduIioi+dcwbbw1Df2nFzI3FcX7H1UIPd8M4p3UAt5WCiVMPHW
# XxrQt5n8jxgLcusvORXZqZOsdTl7HZpsVHnGUY787Ou0IJxuFsiUM64bKGzvNqqt
# YyFyR99ErCTqdZ66uraFilAgjPwaLFzJUw6+aK/wWxKB7Q0piICpeX1X0ILZu56G
# R206VEcmxWILYjQE2NZcT+7vbUzmMIIGvDCCBaSgAwIBAgIQA/G04V86gvEUlniz
# 19hHXDANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJE
# aWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTEyMDQxODEyMDAw
# MFoXDTI3MDQxODEyMDAwMFowbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGln
# aUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEyKTCCASIwDQYJKoZIhvcNAQEB
# BQADggEPADCCAQoCggEBAKdT+g+ytRPxZM+EgPyugDXRttfHoyysGiys8YSsOjUS
# OpKRulfkxMnzL6hIPLfWbtyXIrpReWGvQy8Nt5u0STGuRFg+pKGWp4dPI37DbGUk
# kFU+ocojfMVC6cR6YkWbfd5jdMueYyX4hJqarUVPrn0fyBPLdZvJ4eGK+AsMmPTK
# PtBFqnoepViTNjS+Ky4rMVhmtDIQn53wUqHv6D7TdvJAWtz6aj0bS612sIxc7ja6
# g+owqEze8QsqWEGIrgCJqwPRFoIgInbrXlQ4EmLh0nAk2+0fcNJkCYAt4radzh/y
# uyHzbNvYsxl7ilCf7+w2Clyat0rTCKA5ef3dvz06CSUCAwEAAaOCA1gwggNUMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMH8GCCsGAQUFBwEBBHMwcTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3Au
# ZGlnaWNlcnQuY29tMEkGCCsGAQUFBzAChj1odHRwOi8vY2FjZXJ0cy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3J0MIGPBgNVHR8E
# gYcwgYQwQKA+oDyGOmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEhp
# Z2hBc3N1cmFuY2VFVlJvb3RDQS5jcmwwQKA+oDyGOmh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEhpZ2hBc3N1cmFuY2VFVlJvb3RDQS5jcmwwggHEBgNV
# HSAEggG7MIIBtzCCAbMGCWCGSAGG/WwDAjCCAaQwOgYIKwYBBQUHAgEWLmh0dHA6
# Ly93d3cuZGlnaWNlcnQuY29tL3NzbC1jcHMtcmVwb3NpdG9yeS5odG0wggFkBggr
# BgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAA
# QwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAA
# YQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUA
# cgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4A
# ZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAA
# bABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAA
# aQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIA
# ZQBmAGUAcgBlAG4AYwBlAC4wHQYDVR0OBBYEFI/ofvBtMmoABSPHcJdqOpD/a+rU
# MB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBCwUA
# A4IBAQAZM0oMgTM32602yeTJOru1Gy56ouL0Q0IXnr9OoU3hsdvpgd2fAfLkiNXp
# /gn9IcHsXYDS8NbBQ8L+dyvb+deRM85s1bIZO+Yu1smTT4hAjs3h9X7xD8ZZVnLo
# 62pBvRzVRtV8ScpmOBXBv+CRcHeH3MmNMckMKaIz7Y3ih82JjT8b/9XgGpeLfNpt
# +6jGsjpma3sBs83YpjTsEgGrlVilxFNXqGDm5wISoLkjZKJNu3yBJWQhvs/uQhhD
# l7ulNwavTf8mpU1hS+xGQbhlzrh5ngiWC4GMijuPx5mMoypumG1eYcaWt4q5YS2T
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIU6TCCFOUCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCv1bpEMdpK
# yNJkOXvhdCbe2Uzo7MP65vXryH6BRrXB2jANBgkqhkiG9w0BAQEFAASCAgB5UtWB
# NqVBdCfW3mxqi7Tsb7bMZDcz6snCqakp5EyVcQR1xFV0v1Qeu5hbMm2A/2kh5Z8x
# FxVOF+wjHTU8KSuaPhW4UBf86MbyQaUcX7QZm3pZz5XZrQkAUQaOjfgoszcEmSib
# bLI4hCHU9NOUnP2xLiudZw+2p7jIHD3MYdqNvh2x4U6hfFnh0s/QBY/0MhrS8IHB
# xJneo2ooLBH1b55oL23Aeq+iK+ZPyXoy5ihI9JHds/NmHD35dGn5CVFO8lwgU0zB
# uNKnXE+YAfobsiiqEtFkNC7NfKhauXMXoEKhNlXBHqy9dIe4KvCRH8s1xE0QNu9X
# NbafjbdPSrWQ5S8f7ar0si1/09Vb/gdhp3jDOnlv6s64sRRsCtiBRX2cIAldYE0u
# Git5GJk72d/18gw64/b0Wu1MdFhxiiZWXJl6bq0tIMVe8m+hT25zldafBgZk9c6V
# Wj8pcyFNebYHbdZEmd4sc2LeIOWdWVQJPvBU62IPWEH3/rf8PN4Rm6/D7wf1YlxI
# HW6LZ6w00LxGR7cTTnu7ak98cGjN4CmOPinlv5KaQRrU9rciEvglpf1/n4oMILDO
# eSmMyl4dlylPVhw4zGb+rMTs7Yg9qUYfDj7MxkII1obGXd5Pdu/2iIuCojwSIHzi
# vXuiWjrrIXWsUJ4ldBaupHxD+SmZ4pcZxqiP8qGCEbIwghGuBgorBgEEAYI3AwMB
# MYIRnjCCEZoGCSqGSIb3DQEHAqCCEYswghGHAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCC4aNztpeNfXAf6qqMmkplROsKLm0qdG0rmMHvDuPdOEQIQRqmcEbOAWCY3
# P5owoVhAiRgPMjAyMjA2MDkwODQ0MzdaoIINfDCCBsYwggSuoAMCAQICEAp6Soie
# yZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0
# IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBa
# Fw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7M
# XGzj4CUu0jHkPECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumj
# S0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD
# 0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De
# 1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D
# 7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/
# KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+
# X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DN
# kdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr
# 5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV
# 6J67m0uy4rZBPeevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIsp
# QnL3ebLdhOon7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYG
# Z4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGog
# j57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBP
# oE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMw
# gYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEF
# BQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d
# 5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC
# 6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8R
# yTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bem
# h2RPPkaJFmMga8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkw
# NuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+
# VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGuk
# zp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTm
# tQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qX
# sdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvT
# nMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwwggauMIIElqAD
# AgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAz
# MjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBS
# U0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDM
# g/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOx
# s+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09ns
# ad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtA
# rF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149z
# k6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6
# OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qh
# HGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1
# KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX
# 6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0
# sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQID
# AQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2F
# L3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEB
# BGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsG
# AQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+Y
# qUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjY
# C+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0
# FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6
# WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGj
# VoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzp
# SwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwd
# eDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o
# 08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n
# +2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y
# 3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIO
# K+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MYIDdjCCA3ICAQEwdzBjMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0
# IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqI
# nsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjIwNjA5MDg0NDM3WjArBgsqhkiG
# 9w0BCRACDDEcMBowGDAWBBSFCPOGUVyz0wd9trS3wH8bSl5B3jAvBgkqhkiG9w0B
# CQQxIgQgvjyYhExXDWG6wj5/vp8cWlpoSMETAJpWer0w9nTeAokwNwYLKoZIhvcN
# AQkQAi8xKDAmMCQwIgQgnaaQFcNJxsGJeEW6NYKtcMiPpCk722q+nCvSU5J55jsw
# DQYJKoZIhvcNAQEBBQAEggIAF+uQMEG3a/TNOHYu02n+ernJiOrXiU/TCbnOk0zV
# SWPLvcIGPsDWQNtTi4qjbcQhvHX4KsvRHe/8pT9AsLHMowUyKTnsgIijFbp8mFU+
# xwz2ZLXXRPjMaxKXhx4peQdCgAbos4x23LqhgIaUD0skiLHr3jH0YhpmROqmShEn
# 0zL7TwVauNrnNZybiIcRnZUIYt+VePSoJr7b4XpJ4ikG1kKbKcdMJ5gaTQDJykBe
# qO31yyDMFPzpn7ZQOMFssPVDfDopJvCGfm+eW/1BmgGDlk3COPV0Ac2prC8RiM4Z
# UXvt8jC4ghI7Ozzy4h9Wh+tIu+mtDqDGiqpqrS2fPWdSy4OHyL/1BUNpW4W/Xxom
# 5wBwYNlxKcsmdPrpKsMXRkyVeKZj4CtTkrOrtm0Mk0u75Dk5QxXv+DefcoPUVDX7
# YnmAQlVE6LUtRsTO1JJD7QuOHa3VIrijkejXniH7Xo4InE/vNlNh5bey/S4I+1lo
# 49u25U9mgKKTyvZ+7I8kHZ9U/yIqEoHzyC32pRSSwIxK0dhlAbdF2vRwChec1VG3
# V0ZwH9PkTQw/f9V1f4qUR/lN/gNdhnkoA7CMkZ2uhciiM7fAZa/k44eix/rlOxWo
# KZLIOphR2hRL1g7ohHyz1twwH9sFJrYOF/fsUUoziRdLL75upK/eVLjlIuUJ3olo
# Rmw=
# SIG # End signature block
