<#
.SYNOPSIS
Obtains information about user and computer GPOs applied during user logon and device startup.

.DESCRIPTION
Obtains information from Windows Event Log about user and computer GPOs applied during user logon and device startup.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   ComputerGpoDCName               String          Domain Controller DNS name and IP used during computer logon
2   ComputerGpoDCDiscoveryInSeconds Float           Elapsed seconds to discover a domain controller during computer logon
3   ComputerGpoAppliedTimeInSeconds Float           Elapsed seconds to apply all computer policies
4   UserGpoDCName                   String          Domain Controller DNS name and IP used during user logon
5   UserGpoDCDiscoveryInSeconds     Float           Elapsed seconds to discover a domain controller during user logon
6   UserGpoAppliedTimeInSeconds     Float           Elapsed seconds to apply all user policies

.FURTHER INFORMATION
The information fully relies on the Event Viewer information for events 4000 and 4001 from Windows-GroupPolicy provider.

In case that the event 4000 is not available, a message indicating it is not possible to obtain the computer information will be displayed and the outputs will be empty.
In case that the event 4001 is not available, a message indicating it is not possible to obtain the user information will be displayed and the outputs will be empty.
In case that the GPO application process finishes with an error (events 6000, 6001, 7000 and 7001), a message will be displayed and the outputs will be empty.

Note that when the value -1 is returned for the outputs, it indicates that the information could not be retrieved from the event logs.
If the output is 0, it means that the Group Policies have been processed in less than 1 second.

To avoid data loss, it is possible to increase the Event Viewer log size limit in /Microsoft/Windows/Microsoft-Windows-GroupPolicy/Operational log properties.

This remote action uses the following events ([https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749336(v=ws.10) Microsoft documentation]):

4000: The Group Policy service logs this event when an instance of computer Group Policy processing begins.
4001: The Group Policy service logs this event when an instance of user Group Policy processing begins.
7000: The Group Policy service logs this event when an instance of computer Group Policy processing fails to complete.
7001: The Group Policy service logs this event when an instance of user Group Policy processing fails to complete.
6000: The Group Policy service logs this event when an instance of computer Group Policy processing completes with one or more errors.
6001: The Group Policy service logs this event when an instance of user Group Policy processing completes with one or more errors.
8000: The Group Policy service logs this event when an instance of computer Group Policy processing completes successfully.
8001: The Group Policy service logs this event when an instance of user Group Policy processing completes successfully.
5308: Success DC interaction event: The interaction described in the paragraph before this table has completed successfully.
5326: Success DC discovery end event: The process of discovering a domain controller completed successfully.

.NOTES
Context:            LocalSystem
Version:            2.0.0.0 - Code refactored and outputs updated
                    1.0.1.0 - Added a proper message when information is not available in Event Viewer
                    1.0.0.0 - Initial release
Last Generated:     13 Sep 2022 - 13:56:40
Copyright (C) 2022 Nexthink SA, Switzerland
#>



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

$EVENT_GROUP_POLICY_PATH = 'Microsoft-Windows-GroupPolicy/Operational'
Set-Variable -Name 'EVENT_GROUP_POLICY_PATH' -Option ReadOnly -Scope Script -Force

$GpoEvents = @{
    Computer = @{
        Info = '4000'
        Error = '7000'
        Warning = '6000'
        Completed = '8000'
    }
    User = @{
        Info = '4001'
        Error = '7001'
        Warning = '6001'
        Completed = '8001'
    }
    DCName = @{
        Id = '5308'
        Property = 'DCName'
    }
    DiscoveryTime = @{
        Id = '5326'
        Property = 'DCDiscoveryTimeInMilliSeconds'
    }
    CompletedInSeconds = 'PolicyElaspedTimeInSeconds' # Microsoft' typo
}

#
# Invoke Main
#
function Invoke-Main {
    $exitCode = 0

    [hashtable]$Outputs = Initialize-Outputs

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows10'

        Get-GPOsImpact -Outputs $Outputs -Scope 'Computer'
        Get-GPOsImpact -Outputs $Outputs -Scope 'User'
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -Outputs $Outputs
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

#
# GPO functions
#
function Initialize-Outputs {
    return $Outputs = @{
                Computer = @{
                    DCName = '-'
                    DCDiscoveryInSeconds = '-1'
                    AppliedTimeInSeconds = '-1'
                }
                User = @{
                    DCName= '-'
                    DCDiscoveryInSeconds= '-1'
                    AppliedTimeInSeconds = '-1'
                }
        }
}

function Get-GPOsImpact ([hashtable]$Outputs, [string]$Scope) {
    if (-not ( Test-EventExists -ID $GpoEvents.$Scope.Info )) {
        Write-StatusMessage -Message "No $Scope GPO processing started info found in Event Viewer. "
    } elseif ( Test-CorrelatedEventExists -ID $GpoEvents.$Scope.Info -CorrelatedID $GpoEvents.$Scope.Error ) {
        Write-StatusMessage -Message "$Scope Group Policy processing failed to complete. "
    } elseif ( Test-CorrelatedEventExists -ID $GpoEvents.$Scope.Info -CorrelatedID $GpoEvents.$Scope.Warning ) {
        Write-StatusMessage -Message "$Scope Group Policy processing completed with one or more errors. "
    } else {
        Update-Outputs -Outputs $Outputs -Scope $Scope
    }
}

function Test-EventExists ([string]$ID) {
    $eventInfo = (Get-WinEvent -LogName $EVENT_GROUP_POLICY_PATH -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $ID })

    return $null -ne $eventInfo
}

function Test-CorrelatedEventExists ([string]$ID, [string]$CorrelatedID) {
    $xPath = Get-XPath -ID $ID
    $eventInfo = (Get-WinEvent -LogName $EVENT_GROUP_POLICY_PATH -FilterXPath $Xpath -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $CorrelatedID })

    return $null -ne $eventInfo
}

function Update-Outputs ([hashtable]$Outputs,[string]$Scope) {
    $xPath = Get-XPath -ID $GpoEvents.$Scope.Info
    $gpoDCName = Get-EventInfo -Xpath $xPath -ID $GpoEvents.DCName.Id -Scope $Scope -Property $GpoEvents.DCName.Property
    $gpoDCDiscoveryInMilliseconds = Get-EventInfo -Xpath $xPath -ID $GpoEvents.DiscoveryTime.Id -Scope $Scope -Property $GpoEvents.DiscoveryTime.Property
    $gpoAppliedTimeInSeconds = Get-EventInfo -Xpath $xPath -ID $GpoEvents.$Scope.Completed -Scope $Scope -Property $GpoEvents.CompletedInSeconds

    if ( $null -ne $gpoDCName ) {
        $Outputs.$Scope.DCName = $gpoDCName
    }

    if ( $null -ne $gpoDCDiscoveryInMilliseconds ) {
        $gpoDCDiscoveryInSeconds=$gpoDCDiscoveryInMilliseconds/1000
        $Outputs.$Scope.DCDiscoveryInSeconds = $gpoDCDiscoveryInSeconds
    }

    if ( $null -ne $gpoAppliedTimeInSeconds ) {
        $Outputs.$Scope.AppliedTimeInSeconds = $gpoAppliedTimeInSeconds
    }
}

function Get-XPath ([string]$ID) {
    $eventInfo = (Get-WinEvent -LogName $EVENT_GROUP_POLICY_PATH -ErrorAction SilentlyContinue | Where-Object { $_.Id -eq $ID })
    $LastEvent = ($eventInfo | Sort-Object -Property TimeCreated | Select-Object -Last 1)
    $timeCreated = $LastEvent.TimeCreated
    $startTime = Convert-TimeToString -Time $timeCreated
    $activityID = $LastEvent.ActivityId.Guid
    $xPath = "*[System[TimeCreated[@SystemTime >= '$startTime'] and Correlation[@ActivityID='{$activityID}']]]"

    return $xPath
}

function Convert-TimeToString ([datetime]$Time) {
    return $Time.ToUniversalTime().ToString('s')
}

function Get-EventInfo ([string]$Xpath,[string]$ID,[string]$Scope,[string]$Property) {
    $eventInfo = (Get-WinEvent -LogName $EVENT_GROUP_POLICY_PATH -FilterXPath $Xpath | Where-Object { $_.Id -eq $ID })

    if ($null -eq $eventInfo ) {
        Write-StatusMessage -Message "Event ID $ID is not available in the $Scope GPO scope. "
        return $null
    } else {
        [xml]$xmlObject = $eventInfo.ToXml()
        $result = ($xmlObject.Event.EventData.Data | Where-Object { $_.Name -eq $Property }).'#text'
        return $result
    }
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$Outputs) {
    [nxt]::WriteOutputString('ComputerGpoDCName', $Outputs.Computer.DCName)
    [nxt]::WriteOutputFloat('ComputerGpoDCDiscoveryInSeconds', $Outputs.Computer.DCDiscoveryInSeconds)
    [nxt]::WriteOutputFloat('ComputerGpoAppliedTimeInSeconds', $Outputs.Computer.AppliedTimeInSeconds)
    [nxt]::WriteOutputString('UserGpoDCName', $Outputs.User.DCName)
    [nxt]::WriteOutputFloat('UserGpoDCDiscoveryInSeconds', $Outputs.User.DCDiscoveryInSeconds)
    [nxt]::WriteOutputFloat('UserGpoAppliedTimeInSeconds', $Outputs.User.AppliedTimeInSeconds)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main))
# SIG # Begin signature block
# MIIu8AYJKoZIhvcNAQcCoIIu4TCCLt0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAe/TO3XkVfD1UO
# MLpiVg9UoK5z2lJ98NSgh/XEJVMOMqCCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIdCzCCHQcCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDxLN+XhOTQ
# BRdjz7nuvD/DWwb+ISgDjHbmYBQ2Q5eNojANBgkqhkiG9w0BAQEFAASCAgAFoiid
# ICA/eM9+zTMxbz+kjQlCBs0UoVzSRVmCVf8bCIrAchbCfutSJqdMaR5eef6CmAbq
# bqsZDZL680BxQQlmnUe9xrKz6ID5t6adEoRyj6fEjgQp2bwAzeC64RvRAi6RjVRR
# yjl+1aM6upDc+57Vk0QLQ+5gH2fmoXk0q6ktEKKEXoj6ggyrAwGE4tTH/KonuzQS
# o+IMglqYgyz6Fr3KWG5omGLv1cGsmLo9C/HVOaOvyg6k2pcJzTKwitqJy8hjfAX0
# rL5PKkev1WqmwuPc1ijXZY1a93aYq15gteIUCVWhcKmz5ht5vp2lqSZvKLxrV6N/
# 2RAgdb5A4nG8zVstMoraaT9VLxTYuYT0unW0GDgnqFZKX7sLMoHLrUNrH80jW0Sr
# Q4Wz0awmPjhAIiFU+szfINfUu8J/cgSCq7kCRYdIJ/NhA3wrw88L6Bluzl81i0rH
# 6OFojO+55O02l+D9sJ31gK5gUdWjq3R6kcz9Il1VySM4Gr092MPvcFaZDdckY//5
# vaBx2las9BmHgn1G/Hc0VVPD897JVWPjf++EjEnDIzPCZVN/mviP6lYpcIAX7LHN
# ADf3QXeH4Rk11Lcqs5VCb/Tq1qSJukWGzrdKRqewq1Qr6OJ+VNZvxYdEUGrvxUWe
# eSm2lbxQvm6977i2XtX3CFNeddrYc0bxYIIR8qGCGdQwghnQBgorBgEEAYI3AwMB
# MYIZwDCCGbwGCSqGSIb3DQEHAqCCGa0wghmpAgEDMQ0wCwYJYIZIAWUDBAIBMIHc
# BgsqhkiG9w0BCRABBKCBzASByTCBxgIBAQYJKwYBBAGgMgIDMDEwDQYJYIZIAWUD
# BAIBBQAEIA/R5eG9AsYwUZRtxvmyvzI8SrpvG0WWTvqBkAONFS9rAhRdU6FtgZe1
# eMnqHFOXgYI+K0fzFxgPMjAyMjA5MTMxMTU2NDlaMAMCAQGgV6RVMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDDCBHbG9i
# YWxzaWduIFRTQSBmb3IgQWR2YW5jZWQgLSBHNKCCFWcwggZYMIIEQKADAgECAhAB
# wpx69HqmAlgOrzKxI7EdMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRp
# bWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MB4XDTIyMDQwNjA3NDQxMloXDTMz
# MDUwODA3NDQxMlowUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24g
# bnYtc2ExKTAnBgNVBAMMIEdsb2JhbHNpZ24gVFNBIGZvciBBZHZhbmNlZCAtIEc0
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo96mIRIWErwo4AT3s9Sw
# 0wFoj1O2GFhbcaBe2NZMc+BX8LkMB/eHuSmD/vDVdaFI/z2wHEC8glVoSDoMRus/
# wyyYNM/EmJtwG4YRjV4VfKEN2tZ3fa/sfpwU7KW/KWrriika/g6fLLoWTVhaY3EM
# 2y60cArnRhBC7ntFfP5kRZSv4OtQslJnH3FDN/HiGINAEFeaFdfy8muem8lW22eD
# GHj3ZaQFzOYThRT+X4lnAWH72saDKNaNTt00LBgDAYRI3RZ4JeHWSGmtXDWWIR6g
# w08TABfLwl7ckk0EYsl49d6nsYQKnnQ6gtyAlLcBbauoOZ4aXcF8AQZdkHs+XUoo
# yikQsbNZzwG4ITDH2bX0lyw2rlLHszIjboOm+dQk91b4YXV0TvIGqyKEyP1k5V8V
# pdwndKrS0Om0SHjXmMy7H/jWRsN1dfqeRcaVdWsHB6hE3VZ2KM5KTQJ5a0+R4vys
# neu8iq96a2xkNEbxzHgcvCf0dWinM8k6F36KTkQ+g/O9AgMBAAGjggGeMIIBmjAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FEk7Z7VXopnmdBl6DFksPgjqIHuLMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEeMDQw
# MgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRv
# cnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEBBIGDMIGAMDkGCCsGAQUFBzAB
# hi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQw
# QwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgwFoAU6hbGaefjy1dFOTOk8EC+
# 0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWduLmNv
# bS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQAIiKTq
# hYgzWGt+/ABVItNvQ2lvfP6+Q4Y3Dp9T2lGe0DzjG5nXUVEZD1GQDtvumkbPfQrg
# xuwVgus+rswD+lntj6VKohk+wl/9FoMxVlIoS1/ERYNh65YMIDCifUXqlm2y/HS4
# /UxhlGqnsOqpvziOmHZ1B6b7pdwLb3V6ZOkw15GQYtDhyxnk6C8niECMh9s/2xWw
# SI3ijZWMJ/OsSYewfOnEpeDZ3L72DRW43mOdfZYrraSulGA30EiZqNu9L070AI+3
# /EjathBAxD8521V3vQs8rDagSpkU4NAxHonSJwpwUN2tb2T6b40a9lD0FhMwDBjO
# 2GhC1VXjWl/AoIG8GbxEsGOKfsArHlVu5x0eE2SZZmQJg+mB5j4r/eR87EO7m281
# YpNkmrtYuK8Ebii7CljjhTkl1OOLFXMBOh3LXZH8nkUuh7XwRpyUw2it+g7rR9mp
# JdaKCtie76yiXqYunFjRvVG/EnLQEZtMz5tSv6fqSpQi/Np0s0XUswnWaERAKh+K
# bNrlaXEAEvjJ3+qYqSpqj9Sa4B+smeHoXT55PEWkDgqGFKAV5ZIggfKCjvOqyZxf
# HEl0/CG1KOCBDf+3f5iDwGDTAcVmzGG8wqQLAzc2mjIlwsXmg5T80Hm/g9O8U7Xj
# /s/hcT4F22KPJL3vU6rynlMMP3xr8OolOF9yqjCCBlkwggRBoAMCAQICDQHsHJJA
# 3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBS
# b290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2Jh
# bFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBbMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFs
# U2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0s691g1+pR1LHYTpjfDkjeW10
# /DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuAZm3RKErBLLu5cPJyroz3mVpd
# dq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nuMc+8ijtuasSI8O6X9tzzGKBL
# mRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9sVRTB4uZbrhUmYqoMZI78np9
# /A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6HPXpl69FWqS69+1g9tYX6U5lN
# W3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3E1LZJTTtlu/4Z+oIvo9Jev+Q
# sdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8NubX2bVb+ih0JPiQOZybH/LIN
# oJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57UQgZvGxjVNupkrs799QXm4mbQ
# DgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9MwMB3pkl+XFu6ZxdAkxgPM8C
# jwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8yLJN22TwRZ+6wT9Uo9h2ApVs
# ao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W1j0ZsJfqjFCRba9Xhn4QNx1r
# GhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+0MO9ZZYwHwYDVR0jBBgwFoAU
# rmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzAB
# hiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDYGA1UdHwQvMC0w
# K6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yNi5jcmwwRwYD
# VR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
# bHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4ICAQB/4ojZV2cr
# Ql+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85xhZrGUBJJQge5Jv31qQNjx6W
# 8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs0LLP7MJWZR29f/begsi3n2HT
# tUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTtchBxdnDSD5bz6jdXlJEYr9yN
# mTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vckS3RafXKGNbMCVx+LnPy7rEze
# +t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghzn16h1pnO6X1LlizMFmsYzeRZ
# N4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzOe3ygxayvUQbwEccdMMVRVmDo
# fJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7ASvUh/mIQ7R0w/PbM6kgnfIt1
# Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmNtyUgDhtRoNRjqoPqbHJhSsn6
# Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aNbYy2ce1SIf4+9p+fORqurNIv
# eiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXEQ0H5JeIsEH6B+Q2Up33ytQn1
# 2GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBUcwggQvoAMCAQICDQHyQEJAzv0i
# 2+lscfwwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290
# IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNp
# Z24wHhcNMTkwMjIwMDAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAwHgYDVQQLExdH
# bG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEG
# A1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AJUH6HPKZvnsFMp7PPcNCPG0RQssgrRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ
# 0cay/xTOURQh7ErdG1rG1ofuTToVBu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJm
# L025eShNUhqKGoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm5
# 66qjuL++gmNQ0PAYid/kD3n16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqM
# PKq0pPbzlUoSB239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68
# UARjNN9rkxi+azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFy
# Vm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QK
# bNQCTXTAFO39OfuD8l4UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0a
# EYdwgQqomnUdnjqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXK
# bWQULHpYT9NLCEnFlWQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu
# 3GduyYsRtYQUigAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjggEmMIIBIjAO
# BgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUrmwFo5MT
# 4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7ww
# PgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFs
# c2lnbi5jb20vcm9vdHIzMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vcm9vdC1yMy5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYI
# KwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkv
# MA0GCSqGSIb3DQEBDAUAA4IBAQBJrF7Fg/Nay2EqTZdKFSmf5BSQqgn5xHqfNRiK
# CjMVbXKHIk5BP20Knhiu2+Jf/JXRLJgUO47B8DZZefONgc909hik5OFoz+9/ZVlC
# 6cpVObzTxSbucTj61yEDD7dO2VtgakO0fQnQYGHdqu0AXk4yHuCybJ48ssK7mNOQ
# dmpprRrcqInaWE/SwosySs5U+zjpOwcLdQoR2wt8JSfxrCbPEVPm3MbiYTUy9M7d
# g+MZOuvCaKNyAMgkPE64UzyxF6vmNSz500Ip5l9gA6xCYaaxV2ozQt81MYbKPjcr
# 2sTaJPVOEvK2ubdH6rsgrWEWt6Az4y2Jp7yzPAF/IxqACTTpMIIDXzCCAkegAwIB
# AgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFs
# U2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMT
# Ckdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAw
# HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs
# U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRfJMsu
# S+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpiLx9e
# +pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR5Z2K
# YVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hpsk+Q
# LjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Saer9f
# wRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAwDgYDVR0PAQH/BAQD
# AgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+oLkUkrk1Q+mOai97i
# 3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZURUm7lgAJQayzE4aG
# KAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMpjjM5RcOO5LlXbKr8
# EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK6fBdRoyV3XpYKBov
# Hd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQXmcIfeg7jLQitChws
# /zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecsMx86OyXShkDOOyyG
# eMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpHWD9fMYIDSTCCA0UC
# AQEwbzBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEx
# MC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBH
# NAIQAcKcevR6pgJYDq8ysSOxHTALBglghkgBZQMEAgGgggEtMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDArBgkqhkiG9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaEN
# BgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQxIgQg+oHgagibeoqObHc/CrSRm2n6
# gGR8vTUzv2gjzfnsBT4wgbAGCyqGSIb3DQEJEAIvMYGgMIGdMIGaMIGXBCCvgDHt
# bss5FERIlb0LHQzrEpWU214MLG32vnKxJUJH0DBzMF+kXTBbMQswCQYDVQQGEwJC
# RTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2ln
# biBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNAIQAcKcevR6pgJYDq8ysSOx
# HTANBgkqhkiG9w0BAQsFAASCAYCRaa0LyMb1vkDFjMdpHndYe+srZ0Z1qSRawzC0
# 8C5Hiu6jW518TtFPKZriE/KP2pXG+6ykaCs8QJqB5TmZvEGmVNetixT5pnhNiSlp
# jn5Sv7jCkbVgqeX9eywa33Nis3QqK68anfcaXGb8qsUpSMWll1NhtSVpMOF17lQr
# RBLhhVESdHMBvI98sSEhUXAa0WKONUaCEiYxthRcvid0jXMEp3TsD3ucwu/laTYZ
# cNMJEKx6AUDVa3XeYxHQ539ObtZDyySTKpBxXf8Z1LcqDeYTFpFeSETdIw77uLdd
# bnFTtqcBZuDVD9zJTu1Kyh3FtbeX/dO5jewD9Ihn30uzS9jREvMbBGDb4yVQpDil
# U8eCeh08Il8KzXbaltY4/7yZpZLSZ1ZMeNMJ9Q1WxTMzdGJsQUeFMQZsfo3qO6zg
# T7c7AEMMDV4PWmsfK4/IqzTzIALo1JahYR+q5MDojkS/Y7vTLWIghZkziy2kS8p0
# sslSjD4GRVwmTcp7R65s/LfiFnc=
# SIG # End signature block
