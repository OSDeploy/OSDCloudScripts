<#
.SYNOPSIS
Cleans the unused files in WinSxS, SCCM cache folders, and memory dump files unused for a provided number of days.

.DESCRIPTION
Performs cleanup of unused files in WinSxS folder using DISM Windows tool.
Deletes SCCM cached files that are older than a certain numbers of days provided as input parameters.


.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   MaximumDelayInSeconds           Maximum random delay set to avoid overloading server hosting virtual machines. Provide number of seconds less than 600
2   SCCMCacheFilesCreationAgeInDays File age threshold to delete Configuration Manager cache older or equal age. Provide 0 to ignore
3   DumpFilesOlderThanDays          File age threshold to remove older or equal age. Provide 0 to ignore

.OUTPUTS
ID  Label                           Type            Description
1   CleanupSpace                    Size            Space freed

.FURTHER INFORMATION
Parameter 'MaximumDelayInSeconds' can be used to add random script execution delay. It should be used in virtualized environments to spread over time number of I/O requests on server hosting virtual machines.
SCCM cache cleanup does not work with Configuration Manager older than 2012.
The freed space shown in CleanupSpace output is calculated by accessing the 'FreeSpace' property of the [https://docs.microsoft.com/en-us/previous-versions/windows/desktop/vdswmi/win32-volume Win32_Volume WMI Class] before and after the execution.
Please consider this output as an orientation. It may be inaccurate or report 0 in certain situations due to the fact that external applications or services could be occupying the free space by downloading, creating or unzipping files.

.RESTRICTIONS
- The script is designed to remove memory dumps only from default locations (%SystemRoot%\MEMORY.DMP and %SystemRoot%\Minidump).
- The deletion of old user profiles is only supported on Windows 10.

.NOTES
Context:            LocalSystem
Version:            4.0.1.0 - Fixed PATH vulnerability and changed documentation
                    4.0.0.0 - Removed unused profile removal
                    3.1.4.0 - Fixed empty folders removal
                    3.1.3.0 - Fixed user profile deletion
                    3.1.2.0 - Fixed system drive free space inaccuracy and improved messaging
                    3.1.1.0 - Fixed documentation about space freed
                    3.1.0.1 - Updated template functions
                    3.1.0.0 - Fixed the deletion of files inside folders and empty folders + minor refactoring
                    3.0.0.0 - Added 'Remove Memory Dump Files' functionality
                    2.0.2.0 - Fixed wrong SCCM cache path
                    2.0.1.0 - Fixed user profiles with null LastUseTime property
                    2.0.0.0 - Added SCCM cache cleanup and removal of unused user profiles
                    1.0.0.0 - Initial release
Last Generated:     25 Mar 2022 - 11:12:12
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param (
    [Parameter(Mandatory = $true)][string]$MaximumDelayInSeconds,
    [Parameter(Mandatory = $true)][string]$SCCMCacheFilesCreationAgeInDays,
    [Parameter(Mandatory = $true)][string]$DumpFilesOlderThanDays
)
# End of parameters definition

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"

#
# Constants definition
#
New-Variable -Name 'ERROR_EXCEPTION_TYPE' `
    -Value @{Environment = '[Environment error]'
             Input = '[Input error]'
             Internal = '[Internal error]'} `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'MAX_SCRIPT_DELAY_SEC' `
    -Value 600 `
    -Option ReadOnly -Scope Script
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script

New-Variable -Name 'ALPHA_NUMERIC_COMMA_REGEX' `
    -Value '^[\w,]+((,\s|-)[\w,]+)*[\w,]+$' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'DISM_EXE' `
    -Value "$env:SystemRoot\System32\Dism.exe" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'DISM_EXE_PARAMS' `
    -Value @('/Online', '/Cleanup-Image', '/StartComponentCleanup') `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SCCM_CACHE_PATH' `
    -Value "$env:SystemRoot\ccmcache" `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'MEMORY_DUMP_FILES_LOCATIONS' `
    -Value @("$env:SystemRoot\memory.dmp",
             "$env:SystemRoot\Minidump") `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    [int]$exitCode = 0
    [long]$cleanupSpace = 0
    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-SupportedOSVersion
        Test-InputParameters -InputParameters $InputParameters

        Wait-RandomTime -MaximumDelayInSeconds $InputParameters.MaximumDelayInSeconds
        $cleanupSpace = Invoke-SystemCleanup -InputParameters $InputParameters

        Write-StatusMessage -Message 'Disk cleanup successfully performed. '
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -CleanupSpace $cleanupSpace
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

function Test-SupportedOSVersion {

    $OSVersion = (Get-OSVersion) -as [version]
    if (-not ($OSVersion)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script could not return OS version. "
    }
    if (($OSVersion.Major -ne 6 -or $OSVersion.Minor -ne 1) -and `
        ($OSVersion.Major -ne 10)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is compatible with Windows 7 and 10 only. "
    }
}

function Get-OSVersion {

    return Get-WmiObject -Class Win32_OperatingSystem `
                         -Filter 'ProductType = 1' -ErrorAction Stop | `
               Select-Object -ExpandProperty Version
}

function Wait-RandomTime ([int]$MaximumDelayInSeconds) {
    if ($MaximumDelayInSeconds -gt 0) {
        $seconds = Get-Random -Minimum 0 -Maximum $MaximumDelayInSeconds
        Start-Sleep -Seconds $seconds
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

function Test-ParamInAllowedRange ([string]$ParamName, [string]$ParamValue, [int]$LowerLimit, [int]$UpperLimit) {
    Test-ParamIsInteger -ParamName $ParamName -ParamValue $ParamValue
    $intValue = $ParamValue -as [int]
    if ($intValue -lt $LowerLimit -or $intValue -gt $UpperLimit) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It must be between [$LowerLimit, $UpperLimit]. "
    }
}

function Test-ParamIsInteger ([string]$ParamName, [string]$ParamValue) {
    $intValue = $ParamValue -as [int]
    if ([string]::IsNullOrEmpty($ParamValue) -or $null -eq $intValue) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. '$ParamValue' is not an integer. "
    }
}

#
# Input parameters validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    [int]$daysThreshold = [math]::truncate(((Get-Date) - [datetime]::MinValue).TotalDays)

    Test-ParamInAllowedRange `
        -ParamName 'MaximumDelayInSeconds' `
        -ParamValue $InputParameters.MaximumDelayInSeconds `
        -LowerLimit 0 `
        -UpperLimit $MAX_SCRIPT_DELAY_SEC
    Test-ParamInAllowedRange `
        -ParamName 'SCCMCacheFilesCreationAgeInDays' `
        -ParamValue $InputParameters.SCCMCacheFilesCreationAgeInDays `
        -LowerLimit 0 `
        -UpperLimit $daysThreshold
    Test-ParamInAllowedRange `
        -ParamName 'DumpFilesOlderThanDays' `
        -ParamValue $InputParameters.DumpFilesOlderThanDays `
        -LowerLimit 0 `
        -UpperLimit $daysThreshold
}

#
# Disk cleaning management
#
function Invoke-SystemCleanup ([hashtable]$InputParameters) {
    [long]$freeSpaceBefore = Get-FreeSpace

    Invoke-DismTool
    Remove-SCCMCacheFilesOlderThanDays -Days $InputParameters.SCCMCacheFilesCreationAgeInDays
    Remove-MemoryDumpFiles -Days $InputParameters.DumpFilesOlderThanDays

    return Get-FreeSpaceAfter -FreeSpaceBefore $freeSpaceBefore
}

function Invoke-DismTool {
    try { [void](Start-Process -FilePath $DISM_EXE -ArgumentList $DISM_EXE_PARAMS -NoNewWindow) }
    catch { throw 'DISM tool execution failed. ' }
}

function Remove-SCCMCacheFilesOlderThanDays ([int]$Days) {
    if ($Days -eq 0 -or -not (Test-SCCMCachePath)) { return }

    Remove-LegacyFiles -Path $SCCM_CACHE_PATH -FileAgeThreshold $Days
    Remove-EmptyFolders -Path $SCCM_CACHE_PATH
}

function Test-SCCMCachePath {
    return Test-Path -Path $SCCM_CACHE_PATH
}

function Remove-LegacyFiles ([string]$Path, [int]$FileAgeThreshold) {
    [datetime]$cutoffDate = Get-CutoffDate -FileAgeThreshold $FileAgeThreshold

    if (-not (Test-FolderIsEmpty -Path $Path)) {
        Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | `
            Where-Object { -not $_.PSIsContainer -and $_.LastWriteTime -le $cutOffDate } | `
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

function Get-CutoffDate ([int]$FileAgeThreshold) {
    return (Get-Date).AddDays(-$FileAgeThreshold)
}

function Test-FolderIsEmpty ([string]$Path) {
    return $null -eq (Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue)
}

function Remove-EmptyFolders ([string]$Path) {
    [string[]]$foldersPathsCollection = Get-ChildItem -LiteralPath $Path `
                                                      -ErrorAction SilentlyContinue `
                                                      -Force -Recurse | `
                                            Where-Object { $_.PSIsContainer } | `
                                            Select-Object -ExpandProperty FullName | `
                                            Sort-Object -Property FullName -Descending

    if ($null -eq $foldersPathsCollection ) { return }

    foreach ($folderPath in $foldersPathsCollection) {
        if (Test-FolderIsEmpty -Path $folderPath) {
            Remove-Item -LiteralPath $folderPath `
                        -ErrorAction SilentlyContinue `
                        -Force -Recurse `
        }
    }
}

function Remove-MemoryDumpFiles ([int]$Days) {
    if ($Days -eq 0) { return }

    foreach ($location in $MEMORY_DUMP_FILES_LOCATIONS) {
        if (Test-Path -Path $location) {
            Remove-LegacyFiles -Path $location -FileAgeThreshold $Days
            Remove-EmptyFolders -Path $location
        }
    }
}

#
# Free space management
#
function Get-FreeSpace {
    $free = (Get-WmiObject -Class 'Win32_Volume' `
                           -Filter "DriveLetter='$env:SystemDrive'" `
                           -ErrorAction SilentlyContinue |
                 Select-Object -ExpandProperty FreeSpace)

    if ($null -eq $free) {
        Write-StatusMessage -Message 'Unable to get free space from system drive. '
    }
    return ($free -as [long])
}

function Get-FreeSpaceAfter ([long]$FreeSpaceBefore) {
    [long]$cleanupSpace = (Get-FreeSpace) - $FreeSpaceBefore
    return $(if ($cleanupSpace -le 0) { 0 -as [long] } else { $cleanupSpace })
}

#
# Nexthink Engine update
#
function Update-EngineOutputVariables ([long]$CleanupSpace) {
    [nxt]::WriteOutputSize('CleanupSpace', $CleanupSpace)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

# SIG # Begin signature block
# MIIimgYJKoZIhvcNAQcCoIIiizCCIocCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCrfxEYnqLHngna
# 0Tc3anZGgEwFP8PePn0PLIyMCjxLi6CCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIQtTCCELECAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC6G7n3ttST
# fgyXtXfN+a2Vqo+KZF8kwc6oPQg+6eof5TANBgkqhkiG9w0BAQEFAASCAgBxj8pp
# joVDLwPj0zbigCvzlz16gb9rpwcNWj+sT5aDQIOgHnKeop+sm+XsJMuWbQTdICsv
# 8gDRhGmGDEy4d/qmW9vzbTfo98eHX1LI2SGnca9Am5w9DbMx6HwlE566iF6yKhvu
# xW6cCddX93T9VM0aGjyqUH2AscUsZYFo/Ao1XCsZnANc7o2N2EGwWR0S0uhI5QHa
# xcGLhQ52iaB5by1HC11D0YDcbdKw2Qo/Lg34e07/IBgknwFjYdetrxtHBs3gj0fv
# 5oS4cYculiziJ/1BF1ZANyOBfSR2R/3OdI0DIEr1N4pKJaHftFisZsqjIBnxRSWc
# GrmJN65fQlBYJ/XQHLpb9SYz/yKedJG8DiC6Cizyy9Uc2QfRj5aax+5O6TCZhFt6
# 3J8BGV4vHAE4u0MNVaK2X1wtZapWb5SoJoMtKWHrw7/DCFnpn+Yuu7x00IjS99JZ
# MQkHRazwNOVI0C/c7kM7ArBot5FQp58gzTeUZQbAYPy/a4FHzW0t+WTorcL+asuT
# qfhOqT3Kxx4lxCvHUruM2cumBclfvF1XvC/lMFR/ihl4xDSZ3HNLmNByKCKlNL6r
# +I9LotxOIdMpraguz8I2ubf+8mR+7oAqkApUhNRmy+C9oVXTSwGdGH/PCkJNwB9l
# fDo6Y9BpsW+Kka7vDHOIDP1AAq+vVclHTWtTDKGCDX4wgg16BgorBgEEAYI3AwMB
# MYINajCCDWYGCSqGSIb3DQEHAqCCDVcwgg1TAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCDgwxAD90/fPwfhbakDYNMveDQeyibyYn8E6hRk+yxUMwIRAJwJVaIsdDTg
# nMxLomQYEokYDzIwMjIwMzI1MTAxMjE2WqCCCjcwggT+MIID5qADAgECAhANQkrg
# vjqI/2BAIc4UAPDdMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAv
# BgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0Ew
# HhcNMjEwMTAxMDAwMDAwWhcNMzEwMTA2MDAwMDAwWjBIMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVz
# dGFtcCAyMDIxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwuZhhGfF
# ivUNCKRFymNrUdc6EUK9CnV1TZS0DFC1JhD+HchvkWsMlucaXEjvROW/m2HNFZFi
# Wrj/ZwucY/02aoH6KfjdK3CF3gIY83htvH35x20JPb5qdofpir34hF0edsnkxnZ2
# OlPR0dNaNo/Go+EvGzq3YdZz7E5tM4p8XUUtS7FQ5kE6N1aG3JMjjfdQJehk5t3T
# jy9XtYcg6w6OLNUj2vRNeEbjA4MxKUpcDDGKSoyIxfcwWvkUrxVfbENJCf0mI1P2
# jWPoGqtbsR0wwptpgrTb/FZUvB+hh6u+elsKIC9LCcmVp42y+tZji06lchzun3oB
# c/gZ1v4NSYS9AQIDAQABo4IBuDCCAbQwDgYDVR0PAQH/BAQDAgeAMAwGA1UdEwEB
# /wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwQQYDVR0gBDowODA2BglghkgB
# hv1sBwEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BT
# MB8GA1UdIwQYMBaAFPS24SAd/imu0uRhpbKiJbLIFzVuMB0GA1UdDgQWBBQ2RIaO
# pLqwZr68KC0dRDbd42p6vDBxBgNVHR8EajBoMDKgMKAuhixodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDAyoDCgLoYsaHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwgYUGCCsGAQUFBwEB
# BHkwdzAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME8GCCsG
# AQUFBzAChkNodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEy
# QXNzdXJlZElEVGltZXN0YW1waW5nQ0EuY3J0MA0GCSqGSIb3DQEBCwUAA4IBAQBI
# HNy16ZojvOca5yAOjmdG/UJyUXQKI0ejq5LSJcRwWb4UoOUngaVNFBUZB3nw0QTD
# htk7vf5EAmZN7WmkD/a4cM9i6PVRSnh5Nnont/PnUp+Tp+1DnnvntN1BIon7h6JG
# A0789P63ZHdjXyNSaYOC+hpT7ZDMjaEXcw3082U5cEvznNZ6e9oMvD0y0BvL9WH8
# dQgAdryBDvjA4VzPxBFy5xtkSdgimnUVQvUtMjiB2vRgorq0Uvtc4GEkJU+y38kp
# qHNDUdq9Y9YfW5v3LhtPEx33Sg1xfpe39D+E68Hjo0mh+s6nv1bPull2YYlffqe0
# jmd4+TaY4cso2luHpoovMIIFMTCCBBmgAwIBAgIQCqEl1tYyG35B5AXaNpfCFTAN
# BgkqhkiG9w0BAQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2Vy
# dCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMTYwMTA3MTIwMDAwWhcNMzEwMTA3MTIw
# MDAwWjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAvdAy7kvNj3/dqbqCmcU5VChXtiNKxA4HRTNREH3Q+X1NaH7ntqD0
# jbOI5Je/YyGQmL8TvFfTw+F+CNZqFAA49y4eO+7MpvYyWf5fZT/gm+vjRkcGGlV+
# Cyd+wKL1oODeIj8O/36V+/OjuiI+GKwR5PCZA207hXwJ0+5dyJoLVOOoCXFr4M8i
# EA91z3FyTgqt30A6XLdR4aF5FMZNJCMwXbzsPGBqrC8HzP3w6kfZiFBe/WZuVmEn
# KYmEUeaC50ZQ/ZQqLKfkdT66mA+Ef58xFNat1fJky3seBdCEGXIX8RcG7z3N1k3v
# BkL9olMqT4UdxB08r8/arBD13ays6Vb/kwIDAQABo4IBzjCCAcowHQYDVR0OBBYE
# FPS24SAd/imu0uRhpbKiJbLIFzVuMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MIGBBgNV
# HR8EejB4MDqgOKA2hjRodHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRB
# c3N1cmVkSURSb290Q0EuY3JsMDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMFAGA1UdIARJMEcwOAYKYIZI
# AYb9bAACBDAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAQEAcZUS6VGHVmnN793a
# fKpjerN4zwY3QITvS4S/ys8DAv3Fp8MOIEIsr3fzKx8MIVoqtwU0HWqumfgnoma/
# Capg33akOpMP+LLR2HwZYuhegiUexLoceywh4tZbLBQ1QwRostt1AuByx5jWPGTl
# H0gQGF+JOGFNYkYkh2OMkVIsrymJ5Xgf1gsUpYDXEkdws3XVk4WTfraSZ/tTYYmo
# 9WuWwPRYaQ18yAGxuSh1t5ljhSKMYcp5lH5Z/IwP42+1ASa2bKXuh1Eh5Fhgm7oM
# LSttosR+u8QlK0cCCHxJrhO24XxCQijGGFbPQTS2Zl22dHv1VjMiLyI2skuiSpXY
# 9aaOUjGCAoYwggKCAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0ECEA1CSuC+Ooj/
# YEAhzhQA8N0wDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMjAzMjUxMDEyMTZaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFOHXgqjhkb7va8oWkbWqtJSmJJvzMC8GCSqGSIb3DQEJBDEi
# BCCiAKU8f2ntf1WFzA8ODKoXTWcUxwE4mAU7+upaVJQxJjA3BgsqhkiG9w0BCRAC
# LzEoMCYwJDAiBCCzEJAGvArZgweRVyngRANBXIPjKSthTyaWTI01cez1qTANBgkq
# hkiG9w0BAQEFAASCAQBWCOop6L+ijlhEoyPBS59iVSHA1rquWBb+0aL2n4s8Icm5
# r0v2bdruBcqlCj+aIvwlz4+Irok5MW4y9rwjy+0wSb/Sg+QdoWae4kzsDnsVvuTy
# cpbyM464XKGskJGxtsuVljVezhmrMhlP9nkcRH6wIwOxoHrK/a7TXJsXE2pv9sYd
# AbDR/slePRcn4c5smGU2GCcHTiUmIZpGX6UPWbDplbNPQTfMMJAmgU0wmbclvgrL
# C5jnNYp7XU3sUOFXq/F3a1arYPQoxf6nhwZU1gypzAlDXbaKxGMkRTo8FBr8Pdvs
# cEyk5cJP1pHquHUjsJe+S3oRM1R7qVBpc30f+Vbr
# SIG # End signature block
