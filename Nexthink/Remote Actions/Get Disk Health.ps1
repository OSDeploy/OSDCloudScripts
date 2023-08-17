<#
.SYNOPSIS
Obtains health information about the disk where a given drive is located.

.DESCRIPTION
Gets physical disk health details where the drive is located (identified by a given drive letter).

.FUNCTIONALITY
On-demand

.INPUTS
ID  Label                           Description
1   DriveLetter                     Drive letter which you want drive and disk information from. It must be a single letter from A to Z (English alphabet)
2   DiskMinimumTemperature          Temperature (in Celsius degrees) from which the disk will be considered to be heating ("DiskHot" output)

.OUTPUTS
ID  Label                           Type            Description
1   PredictiveFailureSupport        Bool            Whether the disk supports Predictive Failure feature or not
2   SMARTStatus                     String          The current SMART status of the disk. More information about the possible statuses can be found [https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-diskdrive here] ("Status" section)
3   DiskTemperature                 Int             Current disk temperature (in Celsius degrees)
4   DiskHot                         Bool            Whether the disk is heating (current temperature higher than 'DiskMinimumTemperature' input parameter value)
5   WriteErrorsCorrected            Int             The number of disk errors that have been corrected
6   WriteErrorsUncorrected          Int             Number of uncorrected disk errors
7   WriteErrorsTotal                Int             Total number of disk errors

.NOTES
Context:            LocalSystem
Version:            1.1.0.0 - Removed DiskWearLevel output
                    1.0.0.0 - Initial release
Last Generated:     12 Nov 2020 - 13:11:51
Copyright (C) 2020 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$DriveLetter,
    [Parameter(Mandatory = $true)][string]$DiskMinimumTemperature
)
# End of parameters definition

#
# Constants definition
#
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script

New-Variable -Name 'DRIVE_LETTER_REGEX' `
    -Value '^[aA-zZ]$' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'DISK_MAX_TEMPERATURE' `
    -Value 120 `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    [hashtable]$outputData = Initialize-OutputData

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-RunningOnWindows10
        Test-InputParameters -InputParameters $InputParameters

        Update-OutputData -InputParameters $InputParameters `
                          -OutputData $outputData
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -OutputData $outputData
    }

    return $exitCode
}

function Initialize-OutputData {
    return @{PredictiveFailureSupport = $false
             SMARTStatus = '-'
             DiskTemperature = 0
             DiskHot = $false
             WriteErrorsCorrected = 0
             WriteErrorsUncorrected = 0
             WriteErrorsTotal = 0}
}

#
# Template functions
#
function Add-NexthinkRemoteActionDLL {

    if (-not (Test-Path -Path $REMOTE_ACTION_DLL_PATH)) {
        throw 'Nexthink Remote Action DLL not found. '
    }
    Add-Type -Path $REMOTE_ACTION_DLL_PATH
}

function Test-RunningAsLocalSystem {

    if (-not (Confirm-CurrentUserIsLocalSystem)) {
        throw 'This script must be run as LocalSystem. '
    }
}

function Confirm-CurrentUserIsLocalSystem {

    $currentIdentity = Get-CurrentIdentity
    return $currentIdentity -eq $LOCAL_SYSTEM_IDENTITY
}

function Get-CurrentIdentity {

    return [security.principal.windowsidentity]::GetCurrent().User.ToString()
}

function Test-RunningOnWindows10 {

    $OSVersion = (Get-OSVersion) -as [version]
    if (-not ($OSVersion)) {
        throw 'This script could not return OS version. '
    }
    if ($OSVersion.Major -ne 10) {
        throw 'This script is compatible with Windows 10 only. '
    }
}

function Get-OSVersion {

    return Get-WmiObject -Class Win32_OperatingSystem `
                         -Filter 'ProductType = 1' -ErrorAction Stop | `
               Select-Object -ExpandProperty Version
}

function Write-StatusMessage ([psobject]$Message) {
    $exception = $Message.ToString()

    if ($Message.InvocationInfo.ScriptLineNumber) {
        $version = Get-ScriptVersion
        if(-not [string]::IsNullOrEmpty($version)) {
            $version = "Version: $version. "
        }

        $errorMessage = $version + "Line '$($Message.InvocationInfo.ScriptLineNumber)'. "
    }

    $host.ui.WriteErrorLine($errorMessage + $exception)
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

function Test-ParamInAllowedRange ([string]$ParamName, [string]$ParamValue, [int]$LowerLimit, [int]$UpperLimit) {
    Test-ParamIsInteger -ParamName $ParamName -ParamValue $ParamValue
    $intValue = $ParamValue -as [int]
    if ($intValue -lt $LowerLimit -or $intValue -gt $UpperLimit) {
        throw "Error on parameter '$ParamName'. It must be between [$LowerLimit, $UpperLimit]. "
    }
}

function Test-ParamIsInteger ([string]$ParamName, [string]$ParamValue) {
    $intValue = $ParamValue -as [int]
    if ([string]::IsNullOrEmpty($ParamValue) -or $null -eq $intValue) {
        throw "Error on parameter '$ParamName'. '$ParamValue' is not an integer. "
    }
}

function Confirm-StringIsNotEmpty ([string]$Value) {
    return -not [string]::IsNullOrEmpty((Format-StringValue -Value $Value))
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-DriveLetterInputParam -ParamName 'DriveLetter' `
                               -ParamValue $InputParameters.DriveLetter
    Test-ParamInAllowedRange -ParamName 'DiskMinimumTemperature' `
                             -ParamValue $InputParameters.DiskMinimumTemperature `
                             -LowerLimit 0 `
                             -UpperLimit $DISK_MAX_TEMPERATURE
}

function Test-DriveLetterInputParam ([string]$ParamName, [string]$ParamValue) {
    if ($ParamValue -notmatch $DRIVE_LETTER_REGEX) {
        throw "Error in '$ParamName' input parameter. '$ParamValue' is not a valid drive letter. "
    }
}

function Update-OutputData ([hashtable]$InputParameters, [hashtable]$OutputData) {
    $diskData = Get-DiskData -DriveLetter $InputParameters.DriveLetter

    $OutputData.PredictiveFailureSupport = Get-DiskPredictiveFailureStatus `
                                               -DiskInstanceName $diskData.InstanceName

    if (Confirm-StringIsNotEmpty -Value $diskData.Status) {
        $OutputData.SMARTStatus = $diskData.Status
    } else {
        Write-StatusMessage -Message 'Could not obtain disk SMART Status. '
    }

    $OutputData.DiskTemperature = ($diskData.Temperature -as [int])
    $OutputData.DiskHot = ($diskData.Temperature -ge $InputParameters.DiskMinimumTemperature)
    $OutputData.WriteErrorsCorrected = ($diskData.WriteErrorsCorrected -as [int])
    $OutputData.WriteErrorsUncorrected = ($diskData.WriteErrorsUncorrected -as [int])
    $OutputData.WriteErrorsTotal = ($diskData.WriteErrorsTotal -as [int])
}

#
# Disk information management
#
function Get-DiskData ([string]$DriveLetter) {
    $driveDeviceID = "${DriveLetter}:"
    $disks = Get-WmiObject -Class 'Win32_DiskDrive'
    foreach ($d in $disks) {
        $partitions = Get-PartitionsByDiskId -DiskId $d.DeviceID
        foreach ($p in $partitions) {
            $drive = Get-DriveByPartitionId -PartitionId $p.DeviceID
            if ($drive.DeviceID -eq $driveDeviceID) {
                return New-DiskData -DiskDrive $d
            }
        }
    }
    throw "No physical disks found for drive letter '$DriveLetter'. "
}

function Get-PartitionsByDiskId ([string]$DiskId) {
    $partitionsQuery = "ASSOCIATORS OF " +
                       "{Win32_DiskDrive.DeviceID='$($DiskId)'} " +
                       "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
    return Get-WmiObject -Query $partitionsQuery -ErrorAction SilentlyContinue
}

function Get-DriveByPartitionId ([string]$PartitionId) {
    $drivesQuery = "ASSOCIATORS OF " +
                   "{Win32_DiskPartition.DeviceID='$($PartitionId)'} " +
                   "WHERE AssocClass = Win32_LogicalDiskToPartition"
    return Get-WmiObject -Query $drivesQuery -ErrorAction SilentlyContinue
}

function New-DiskData ([object]$DiskDrive) {
    $diskPerformanceData = Get-Disk -Number $DiskDrive.Index `
                                    -ErrorAction SilentlyContinue |
                               Get-StorageReliabilityCounter -ErrorAction SilentlyContinue

    if ($null -eq $diskPerformanceData) {
        throw 'Could not obtain disk health data. '
    }

    return @{InstanceName = $DiskDrive.PNPDeviceID
             Status = $DiskDrive.Status
             Temperature = $diskPerformanceData.Temperature -as [int]
             WearLevel = $diskPerformanceData.Wear -as [int]
             WriteErrorsCorrected = $diskPerformanceData.WriteErrorsCorrected -as [int]
             WriteErrorsUncorrected = $diskPerformanceData.WriteErrorsUncorrected -as [int]
             WriteErrorsTotal = $diskPerformanceData.WriteErrorsTotal -as [int]}
}

function Get-DiskPredictiveFailureStatus ([string]$DiskInstanceName) {
    Get-WmiObject -Namespace 'root\wmi' `
                  -Class 'MSStorageDriver_FailurePredictStatus' `
                  -Filter "InstanceName='$($DiskInstanceName)'" `
                  -ErrorAction SilentlyContinue
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$OutputData) {
    [nxt]::WriteOutputBool('PredictiveFailureSupport', $OutputData.PredictiveFailureSupport)
    [nxt]::WriteOutputString('SMARTStatus', $OutputData.SMARTStatus)
    [nxt]::WriteOutputUInt32('DiskTemperature', $OutputData.DiskTemperature)
    [nxt]::WriteOutputBool('DiskHot', $OutputData.DiskHot)
    [nxt]::WriteOutputUInt32('WriteErrorsCorrected', $OutputData.WriteErrorsCorrected)
    [nxt]::WriteOutputUInt32('WriteErrorsUncorrected', $OutputData.WriteErrorsUncorrected)
    [nxt]::WriteOutputUInt32('WriteErrorsTotal', $OutputData.WriteErrorsTotal)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))
# SIG # Begin signature block
# MIIj5AYJKoZIhvcNAQcCoIIj1TCCI9ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDx8Ixl0gwavFNs
# UU/4zvg15/3zTyBbC64mFFQ8BXzor6CCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIR/zCCEfsCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCgJytxxthZ
# k3d6spdWOwP/rYHZ6auTPe+H0L63LAJsvzANBgkqhkiG9w0BAQEFAASCAgAIqzJu
# yJZBZNQQK8iMW2aPMxh80LG535SHxUpo8+7ww3+Qhlk+5dzTVmiUJSzqbgGhZUsw
# 5h2ggb2qt+Rd96ezJ725IBU1dLspRQEhA3OJSLkPkiuOhCeGJI3W1/N3emL+Wubt
# lTG+yNEKwLWc+Am0cZ3JDAP/GzilEjE9NtsKEDRw8Oa1FiZmt+K5eOKwSbwFB+ey
# F4sbeIfCFqyEw6NflC1ba1D+Tx+M/GTNnenVLWssPZcmhIFFMk6CoTTVXrRJHBh7
# KMsrrgePyEZIGxizdO27CL2SjZYpAyxEmDG2q8n1+PXmPjGyVBLN9bIb9C4OFCOy
# d/UgEobrGkgURep0NNKaWe0zD854akr/R5k8nIsIYIlVf4FuAQeVbv5/9w0/+dwx
# TviURk1WGIGSfuYlfS2pxSUXRBwp6lRmljFq1ObDTi7Q7SUZ0DhWWF/xewS3ZvtQ
# XWf+JlNfijdb5yZueluBuABQf/mAV5uMMz/ohtyVFWMwPzT4/6DCqY6KyOLZUQpy
# OsCbWjeBl5wo37Z3CZCEGwoZXIUgAw6Is3qViMo6H5ncF073lAyyw489O7nqYl9c
# oJyDV8niXJzFZzNH4BNayOpXLTkSTcgFJfYwNbMO7CrT8HSC+LSpLqvWYY0EBKu2
# iCI3EiKgo3yV5K/4ypfpwtPRJmHOaDcw/jqbqaGCDsgwgg7EBgorBgEEAYI3AwMB
# MYIOtDCCDrAGCSqGSIb3DQEHAqCCDqEwgg6dAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCA/dsaX7jPUuYQ+KID+IPCGo3HL5NQSzpAR0bH7CJFG3QIQUVEEjK0pyvHm
# 8StvA1LOvxgPMjAyMDExMTIxMjExNTNaoIILuzCCBoIwggVqoAMCAQICEATNP4Vo
# rnbGG7D+cWDMp20wDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTAe
# Fw0xOTEwMDEwMDAwMDBaFw0zMDEwMTcwMDAwMDBaMEwxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEkMCIGA1UEAxMbVElNRVNUQU1QLVNIQTI1
# Ni0yMDE5LTEwLTE1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6WQ1
# nPqpmGVkG+QX3LgpNsxnCViFTTDgyf/lOzwRKFCvBzHiXQkYwvaJjGkIBCPgdy2d
# FeW46KFqjv/UrtJ6Fu/4QbUdOXXBzy+nrEV+lG2sAwGZPGI+fnr9RZcxtPq32UI+
# p1Wb31pPWAKoMmkiE76Lgi3GmKtrm7TJ8mURDHQNsvAIlnTE6LJIoqEUpfj64Ylw
# RDuN7/uk9MO5vRQs6wwoJyWAqxBLFhJgC2kijE7NxtWyZVkh4HwsEo1wDo+KyuDT
# 17M5d1DQQiwues6cZ3o4d1RA/0+VBCDU68jOhxQI/h2A3dDnK3jqvx9wxu5CFlM2
# RZtTGUlinXoCm5UUowIDAQABo4IDODCCAzQwDgYDVR0PAQH/BAQDAgeAMAwGA1Ud
# EwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwggG/BgNVHSAEggG2MIIB
# sjCCAaEGCWCGSAGG/WwHATCCAZIwKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEAbgB5ACAAdQBz
# AGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEAdABlACAAYwBv
# AG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMAZQAgAG8AZgAg
# AHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMAIABhAG4AZAAg
# AHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEAZwByAGUAZQBt
# AGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEAYgBpAGwAaQB0
# AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEAdABlAGQAIABo
# AGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4wCwYJYIZIAYb9
# bAMVMB8GA1UdIwQYMBaAFPS24SAd/imu0uRhpbKiJbLIFzVuMB0GA1UdDgQWBBRW
# Uw/BxgenTdfYbldygFBM5OyewTBxBgNVHR8EajBoMDKgMKAuhixodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDAyoDCgLoYsaHR0cDov
# L2NybDQuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwgYUGCCsGAQUF
# BwEBBHkwdzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME8G
# CCsGAQUFBzAChkNodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRT
# SEEyQXNzdXJlZElEVGltZXN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4IB
# AQAug6FEBUoE47kyUvrZgfAau/gJjSO5PdiSoeZGHEovbno8Y243F6Mav1gjskOc
# lINOOQmwLOjH4eLM7ct5a87eIwFH7ZVUgeCAexKxrwKGqTpzav74n8GN0SGM5CmC
# w4oLYAACnR9HxJ+0CmhTf1oQpvgi5vhTkjFf2IKDLW0TQq6DwRBOpCT0R5zeDyJy
# d1x/T+k5mCtXkkTX726T2UPHBDNjUTdWnkcEEcOjWFQh2OKOVtdJP1f8Cp8jXnv0
# lI3dnRq733oqptJFplUMj/ZMivKWz4lG3DGykZCjXzMwYFX1/GswrKHt5EdOM55n
# aii1TcLtW5eC+MupCGxTCbT3MIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfC
# FTANBgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdp
# Q2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3
# MTIwMDAwWjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEy
# IEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAvdAy7kvNj3/dqbqCmcU5VChXtiNKxA4HRTNREH3Q+X1NaH7n
# tqD0jbOI5Je/YyGQmL8TvFfTw+F+CNZqFAA49y4eO+7MpvYyWf5fZT/gm+vjRkcG
# GlV+Cyd+wKL1oODeIj8O/36V+/OjuiI+GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr
# 4M8iEA91z3FyTgqt30A6XLdR4aF5FMZNJCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZu
# VmEnKYmEUeaC50ZQ/ZQqLKfkdT66mA+Ef58xFNat1fJky3seBdCEGXIX8RcG7z3N
# 1k3vBkL9olMqT4UdxB08r8/arBD13ays6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0O
# BBYEFPS24SAd/imu0uRhpbKiJbLIFzVuMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1R
# i6enIZ3zbcgPMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGB
# BgNVHR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
# cnRBc3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMFAGA1UdIARJMEcwOAYK
# YIZIAYb9bAACBDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j
# b20vQ1BTMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN
# 793afKpjerN4zwY3QITvS4S/ys8DAv3Fp8MOIEIsr3fzKx8MIVoqtwU0HWqumfgn
# oma/Capg33akOpMP+LLR2HwZYuhegiUexLoceywh4tZbLBQ1QwRostt1AuByx5jW
# PGTlH0gQGF+JOGFNYkYkh2OMkVIsrymJ5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tT
# YYmo9WuWwPRYaQ18yAGxuSh1t5ljhSKMYcp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhg
# m7oMLSttosR+u8QlK0cCCHxJrhO24XxCQijGGFbPQTS2Zl22dHv1VjMiLyI2skui
# SpXY9aaOUjGCAk0wggJJAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMT
# KERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0ECEATNP4Vo
# rnbGG7D+cWDMp20wDQYJYIZIAWUDBAIBBQCggZgwGgYJKoZIhvcNAQkDMQ0GCyqG
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMDExMTIxMjExNTNaMCsGCyqGSIb3
# DQEJEAIMMRwwGjAYMBYEFAMlvVBe2pYwLcIvT6AeTCi+KDTFMC8GCSqGSIb3DQEJ
# BDEiBCBMnTaTV87VnXEtZ6YLaObMln9YP4z/8W3h7Z3TAe6RazANBgkqhkiG9w0B
# AQEFAASCAQBITp5HDb6dPmCnYsn4RrvPCdxjGtQ+WixKmxc/VyQy9lsa8b+5+Edo
# Armh2ca8LFrBbMuicOHdJ8FMmM+iYNtdgqWbubOYBNj+M6dnhez/2oLmix9ajoHe
# ngiCXT+mLeuJr2rycNIh7U5vRXjIK7q6YVkOtOFKSEtx+2TH1gIKAVT984GYlky/
# 5AIa+Yu/Z4OLu+f9j6DgpUSAmipvOSmLP7ca7eREiEeUuCiGoatvwlyPjOqryVGU
# HGCjVzmjIERoKI7/ZWM80NhyinZXiSZeFpPJa8CiHN08aSW/ryOSZ3w4fg5ZH/dL
# FoLMgy0r8vvixduyNGwr0YGxRAqV229w
# SIG # End signature block
