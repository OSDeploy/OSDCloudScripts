<#
.SYNOPSIS
Gets SCCM-related client services status.

.DESCRIPTION
Gets SCCM-related client services status (SMS Agent, BITS, WMI, etc.) and information about SCCM client on devices.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   SMSAgentStatus                  String          Status of the SMS Agent Service
2   BITSStatus                      String          Status of the Background Intelligent Transfer Service
3   WMIStatus                       String          Status of the Windows Management Instrumentation Service
4   RPCSubsystemStatus              String          Status of the Remote Procedure Call Subsystem Service
5   WindowsTimeServiceStatus        String          Status of the Windows Time Service
6   ClientInstalled                 Bool            If SCCM client is installed or is not
7   ManagementSite                  String          Site where the device is connecting to
8   LastAttemptedCommunication      DateTime        Last communication date with server
9   LastCumulativeUpdate            String          Last cumulative update installed on the device
10  MonthsSinceLastCumulativeUpdate Int             Months since last cumulative update installed on the device
11  LastScan                        DateTime        Last scan date
12  DaysSinceLastScan               Int             Days since last scan
13  MissingSoftwareUpdates          Int             Number of missing software updates

.NOTES
Context:            LocalSystem
Version:            4.0.1.0 - Fixed 'Update-SCCMClientInformation'. The 'DaysSinceLastScan' output will be set to zero when there is no Last Scan Date
                    4.0.0.0 - Renamed "LastCommunication" to "LastAttemptedCommunication", removed "DaysSinceLastCommunication" and improved LastCumulativeUpdate filter
                    3.0.0.0 - Added new output fields
                    2.0.0.1 - Modified default date constant to fix bug
                    2.0.0.0 - Added new output fields with information about SCCM client
                    1.0.0.0 - Initial release
Last Generated:     22 Dec 2020 - 17:23:59
Copyright (C) 2020 Nexthink SA, Switzerland
#>

# End of parameters definition

#
# Constants definition
#
New-Variable -Name 'DEFAULT_DATE' `
    -Value ([datetime]::ParseExact('01/01/1970 00:00:00.000Z',
                                   'dd/MM/yyyy HH:mm:ss.fffK',
                                   [globalization.cultureinfo]::InvariantCulture,
                                   [globalization.datetimestyles]::None)) `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script

New-Variable -Name 'SCCM_CLIENT_INSTALLATION_KEY' `
    -Value 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SCCM_LAST_CONNECTION_QUERY' `
    -Value "SELECT LastTriggerTime FROM CCM_Scheduler_History WHERE ScheduleID='{00000000-0000-0000-0000-000000000021}' and UserSID='Machine'" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_UPDATE_STATUS_QUERY' `
    -Value 'SELECT * FROM CCM_UpdateStatus' -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_UPDATE_SOFTWARE_QUERY' `
    -Value 'SELECT * FROM CCM_SoftwareUpdate' -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SCCM_SCHEDULER_NAMESPACE' `
    -Value 'Root\CCM\Scheduler' -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_UPDATES_STORE_NAMESPACE' `
    -Value 'Root\CCM\SoftwareUpdates\UpdatesStore' -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_CLIENTS_SDK_NAMESPACE' `
    -Value 'ROOT\ccm\ClientSDK' -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SCCM_CUMULATIVE_WINDOWS_PATTERN' `
    -Value '^[0-9]{4}-[0-9]{2}.*cumulati.*Windows.*' -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_SECURITY_PATTERN' `
    -Value '^[0-9]{4}-[0-9]{2}.*Security Monthly Quality Rollup.*Windows.*' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_EXCLUDE_PATTERN' -Value '(Internet Explorer|\.Net)' -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main {
    [hashtable[]]$services = Initialize-SCCMRelatedServicesStatus
    [hashtable]$SCCMClientInformation = Initialize-SCCMClientInformation
    $exitCode = 0
    try {
        Add-NexthinkRemoteActionDLL

        Test-RunningAsLocalSystem
        Test-SupportedOSVersion

        Update-SCCMServicesStatus -Services $services
        Update-SCCMClientInformation -SCCMClientInformation $SCCMClientInformation
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -Services $services -SCCMClientInformation $SCCMClientInformation
    }

    return $exitCode
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

function Test-SupportedOSVersion {

    $OSVersion = (Get-OSVersion) -as [version]
    if (-not ($OSVersion)) {
        throw 'This script could not return OS version. '
    }
    if (($OSVersion.Major -ne 6 -or $OSVersion.Minor -ne 1) -and `
        ($OSVersion.Major -ne 10)) {
        throw 'This script is compatible with Windows 7 and 10 only. '
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

#
# SCCM-related services status check
#
function Initialize-SCCMRelatedServicesStatus {
    return @(@{Name = 'ccmexec'; Description = 'SMS Agent'; Status = 'Not installed'}
             @{Name = 'bits'; Description = 'Background Intelligent Transfer Service'; Status = 'Not installed'}
             @{Name = 'winmgmt'; Description = 'Windows Management Instrumentation'; Status = 'Not installed'}
             @{Name = 'rpcss'; Description = 'Remote Procedure Call Subsystem'; Status = 'Not installed'}
             @{Name = 'w32time'; Description = 'Windows Time Service'; Status = 'Not installed'})
}

function Update-SCCMServicesStatus ([hashtable[]]$Services) {
    $servicesCount = $Services.Count
    for ($i = 0; $i -lt $servicesCount; $i++) {
        $status = Get-SCCMServiceStatus -Name $Services[$i].Name
        if (-not [string]::IsNullOrEmpty($status)) { $Services[$i].Status = $status }
    }
}

function Get-SCCMServiceStatus ([string]$Name) {
    return [string](Get-SCCMService -Name $Name).Status
}

function Get-SCCMService ([string]$Name) {
    return Get-Service -Name $Name -ErrorAction SilentlyContinue
}

#
# SCCM-Related Client Information
#
function Initialize-SCCMClientInformation {
    return @{ManagementSite = ''
             ClientInstalled = $false
             LastAttemptedCommunication = $DEFAULT_DATE
             LastCumulativeUpdate = ''
             MonthsSinceLastCumulativeUpdate = 999
             LastScan = $DEFAULT_DATE
             DaysSinceLastScan = 999
             MissingSoftwareUpdates = 0}
}

function Update-SCCMClientInformation ([hashtable]$SCCMClientInformation) {
    $SCCMClientInformation.ManagementSite = Get-SCCMManagementSite
    $SCCMClientInformation.ClientInstalled = Test-SCCMClientIsInstalled
    $SCCMClientInformation.LastAttemptedCommunication = Get-SCCMLastAttemptedCommunication

    $SCCMClientInformation.LastCumulativeUpdate = Get-SCCMLastCumulativeUpdate
    if (-not [string]::IsNullOrEmpty($SCCMClientInformation.LastCumulativeUpdate)) {
        $SCCMClientInformation.MonthsSinceLastCumulativeUpdate = Get-SCCMMonthsSinceLastCumulativeUpdate -LastCumulativeUpdate $SCCMClientInformation.LastCumulativeUpdate
    }

    $SCCMClientInformation.LastScan = Get-SCCMLastScan

    if ($DEFAULT_DATE -ne $SCCMClientInformation.LastScan) {
        $SCCMClientInformation.DaysSinceLastScan = Get-DaysDifferenceFromToday -DateTime $SCCMClientInformation.LastScan
    } else {
        $SCCMClientInformation.DaysSinceLastScan = 0
        Write-StatusMessage -Message 'No Last Scan Day available. '
    }
    $SCCMClientInformation.MissingSoftwareUpdates = Get-SCCMMissingSoftwareUpdates
}

function Get-SCCMManagementSite {
    try {
        $smsClient = New-Object -ComObject Microsoft.SMS.Client -Strict
        return $smsClient.GetAssignedSite()
    } catch {
        return ''
    }
}

function Test-SCCMClientIsInstalled {
    return $null -ne (Get-ItemProperty -Path $SCCM_CLIENT_INSTALLATION_KEY |
                          Where-Object { $_.DisplayName -eq 'Configuration Manager Client' } |
                          Select-Object -Unique)
}

function Get-SCCMLastAttemptedCommunication {
    $queryResult = Get-WmiObject -Query $SCCM_LAST_CONNECTION_QUERY -Namespace $SCCM_SCHEDULER_NAMESPACE -ErrorAction SilentlyContinue
    $result = $DEFAULT_DATE

    if ($null -ne $queryResult) {
        $lastTriggerTimeValue = Get-LastTriggerTimeValue -QueryResult $queryResult

        $result = [datetime]::ParseExact($lastTriggerTimeValue.Split('.')[0], 'yyyyMMddHHmmss', [system.globalization.cultureinfo]::InvariantCulture)
    }

    return $result
}

function Get-LastTriggerTimeValue ($QueryResult) {
    return $QueryResult.Properties.Item('LastTriggerTime').Value
}

function Get-DaysDifferenceFromTodayFormat ([string]$Date, [string]$Format) {
    $dateParsed = [datetime]::ParseExact($Date, $Format, [system.globalization.cultureinfo]::InvariantCulture)
    return (Get-DaysDifferenceFromToday -DateTime $dateParsed)
}

function Get-DaysDifferenceFromToday ([datetime]$DateTime) {
    return [int](((Get-Date) - $DateTime).TotalDays)
}

function Get-SCCMLastCumulativeUpdate {
    $queryResult = Get-WmiObject -Query $SCCM_UPDATE_STATUS_QUERY -Namespace $SCCM_UPDATES_STORE_NAMESPACE -ErrorAction SilentlyContinue
    [string]$lastCumulativeUpdate = $null
    if ($null -ne $queryResult) {
        $queryResult = $queryResult | Where-Object { ($_.Status -eq 'installed') -and `
                                                     ($_.Title -match $SCCM_CUMULATIVE_WINDOWS_PATTERN -or $_.Title -match $SCCM_SECURITY_PATTERN) -and `
                                                     ($_.Title -notmatch $SCCM_EXCLUDE_PATTERN) }

        if ($null -ne $queryResult) {
            $lastCumulativeUpdate = ($queryResult | Select-Object Title | Sort-Object Title -Descending | Get-Unique).Title
        }
    }

    if ([string]::IsNullOrEmpty($lastCumulativeUpdate)) {
        return Get-SCCMLastCumulativeUpdateFromUpdateSession
    }

    return $lastCumulativeUpdate.Split(' ')[0]
}

function Get-SCCMLastCumulativeUpdateFromUpdateSession {
    $queryResult = @(Get-SCCMHistory)

    if ($queryResult.Count -gt 0) {
        $queryResult = $queryResult | Where-Object { ($_.Title -match $SCCM_CUMULATIVE_WINDOWS_PATTERN -or `
                                                     $_.Title -match $SCCM_SECURITY_PATTERN) -and `
                                                     ($_.Title -notmatch $SCCM_EXCLUDE_PATTERN) -and `
                                                     ($_.Operation -eq 1) }

        if ($null -ne $queryResult) {
            $title = ($queryResult | Select-Object Title, Date | Sort-Object -Property Date -Descending | Get-Unique).Title

            if (-not [string]::IsNullOrEmpty($title)) {
                return $title.Split(' ')[0]
            }
        }
    }

    return ''
}

function Get-SCCMHistory {
    $result = @()
    try {
        $session = New-Object -ComObject "Microsoft.Update.Session"
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $result = $searcher.QueryHistory(0, $historyCount)
        }
    } catch {
        $result = @()
    }

    return $result
}

function Get-SCCMMonthsSinceLastCumulativeUpdate ([string]$LastCumulativeUpdate) {
    $daysLastCumulative = Get-DaysDifferenceFromTodayFormat -Date $LastCumulativeUpdate -Format 'yyyy-MM'
    return [math]::Truncate($daysLastCumulative / 30)
}

function Get-SCCMLastScan {
    $queryResult = Get-WmiObject -Query $SCCM_UPDATE_STATUS_QUERY -Namespace $SCCM_UPDATES_STORE_NAMESPACE -ErrorAction SilentlyContinue
    if ($null -ne $queryResult) {
        $lastScanTime = ($queryResult | Select-Object ScanTime | Sort-Object ScanTime -Descending | Get-Unique).ScanTime
        return [datetime]::ParseExact($lastScanTime.Split('.')[0], 'yyyyMMddHHmmss', [system.globalization.cultureinfo]::InvariantCulture)
    }

    return $DEFAULT_DATE
}

function Get-SCCMMissingSoftwareUpdates {
    $queryResult = Get-WmiObject -Query $SCCM_UPDATE_SOFTWARE_QUERY -Namespace $SCCM_CLIENTS_SDK_NAMESPACE -ErrorAction SilentlyContinue
    if ($null -ne $queryResult) { return ($queryResult | Measure-Object).Count }

    return 0
}

#
# Nexthink Engine update
#
function Update-EngineOutputVariables ([hashtable[]]$Services, [hashtable]$SCCMClientInformation) {
    foreach ($service in $Services) {
        switch ($service.Name) {
            'ccmexec' { [nxt]::WriteOutputString('SMSAgentStatus', $service.Status) }
            'bits' { [nxt]::WriteOutputString('BITSStatus', $service.Status) }
            'winmgmt' { [nxt]::WriteOutputString('WMIStatus', $service.Status) }
            'rpcss' { [nxt]::WriteOutputString('RPCSubsystemStatus', $service.Status) }
            'w32time' { [nxt]::WriteOutputString('WindowsTimeServiceStatus', $service.Status) }
        }
    }

    [nxt]::WriteOutputBool('ClientInstalled', $SCCMClientInformation.ClientInstalled)
    [nxt]::WriteOutputString('ManagementSite', $SCCMClientInformation.ManagementSite)
    [nxt]::WriteOutputDateTime('LastAttemptedCommunication', $SCCMClientInformation.LastAttemptedCommunication)
    [nxt]::WriteOutputString('LastCumulativeUpdate', $SCCMClientInformation.LastCumulativeUpdate)
    [nxt]::WriteOutputUInt32('MonthsSinceLastCumulativeUpdate', $SCCMClientInformation.MonthsSinceLastCumulativeUpdate)
    [nxt]::WriteOutputDateTime('LastScan', $SCCMClientInformation.LastScan)
    [nxt]::WriteOutputUInt32('DaysSinceLastScan', $SCCMClientInformation.DaysSinceLastScan)
    [nxt]::WriteOutputUInt32('MissingSoftwareUpdates', $SCCMClientInformation.MissingSoftwareUpdates)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main))
# SIG # Begin signature block
# MIIj5QYJKoZIhvcNAQcCoIIj1jCCI9ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCfB+yZ2jB3Saj0
# 4+Yb5Bx120S1oj0ytfCObW57UIw256CCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYISADCCEfwCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCbIyGu+NfN
# Q1zmWdl/ffaXZMgd2kxCAAhAIQBSNNGnnjANBgkqhkiG9w0BAQEFAASCAgAWF3q6
# cQ+YIJl/pof7BFdFTjHZJ3tkf9r/rWSWN7H/Art+Z0jy1VsiWHhl4QxqqGMmHygY
# gyPViDZS1yJYD3K+9D6dM4uM9RuCWJa6AKFFs+Fi0uEawgiptVndJ+k4ZG8gBjt+
# iFEsTLR6YFr4P3vRIdfigeYxbKKMBbQMka0ZgTUuxmoikBySpyJUrDpxzGgpr6t1
# xr99yNm8qTN0aknoMZvNEy/lHKxapr6vdC+9eVsDvJRQ9DJIrMaQEmSTpLgRP0L1
# rvjTekZjcktnWFoikCYU3d7KCxLNTjm4/NXL/5KIhOzN5CoKzD/I7iUn1hsptGUX
# vxiprGofMCWTViJR1Ewae0vK6bzIrA1HCqR8tvl+TcDNHQ4XFgfxbTIMaQ9yxZfM
# 5N31nzqtC7jrWed9aKWAuACtIWJJc5jV3noBpJNT8C50PNA0RMT5nUFHaSfs/tDd
# GRBRLyj4Fvq1ro1TPzfyQYQP8kX/HQCj0pp8h0CbnmF8dSQO8rlPcvvwkjhiqoKd
# jElsGO8f0JkoVpve20nes/Z9K1jw5UUJdUUMZTM/HtFUsrL/7mTJGnVsrpVcXjQn
# aw8xRcM1ez/3S6wHH6n/PnDTnu1uNC3U3TLLwZbM7Yldknuoc6erc9Mb31Pi6UMK
# bz9yEdpR5pzlUDy9XfonZip5OR8CXlXeiPS5zKGCDskwgg7FBgorBgEEAYI3AwMB
# MYIOtTCCDrEGCSqGSIb3DQEHAqCCDqIwgg6eAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCBDt17sRTOtB3rgjrLzzepo0tBDA+8RULI+3T2HiXRudAIRAO38eB8QZnBg
# hvX8DHnN72YYDzIwMjAxMjIyMTYyNDAyWqCCC7swggaCMIIFaqADAgECAhAEzT+F
# aK52xhuw/nFgzKdtMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAv
# BgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0Ew
# HhcNMTkxMDAxMDAwMDAwWhcNMzAxMDE3MDAwMDAwWjBMMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xJDAiBgNVBAMTG1RJTUVTVEFNUC1TSEEy
# NTYtMjAxOS0xMC0xNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOlk
# NZz6qZhlZBvkF9y4KTbMZwlYhU0w4Mn/5Ts8EShQrwcx4l0JGML2iYxpCAQj4Hct
# nRXluOihao7/1K7Sehbv+EG1HTl1wc8vp6xFfpRtrAMBmTxiPn56/UWXMbT6t9lC
# PqdVm99aT1gCqDJpIhO+i4Itxpira5u0yfJlEQx0DbLwCJZ0xOiySKKhFKX4+uGJ
# cEQ7je/7pPTDub0ULOsMKCclgKsQSxYSYAtpIoxOzcbVsmVZIeB8LBKNcA6Pisrg
# 09ezOXdQ0EIsLnrOnGd6OHdUQP9PlQQg1OvIzocUCP4dgN3Q5yt46r8fcMbuQhZT
# NkWbUxlJYp16ApuVFKMCAwEAAaOCAzgwggM0MA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIIBvwYDVR0gBIIBtjCC
# AbIwggGhBglghkgBhv1sBwEwggGSMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5k
# aWdpY2VydC5jb20vQ1BTMIIBZAYIKwYBBQUHAgIwggFWHoIBUgBBAG4AeQAgAHUA
# cwBlACAAbwBmACAAdABoAGkAcwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQAgAGMA
# bwBuAHMAdABpAHQAdQB0AGUAcwAgAGEAYwBjAGUAcAB0AGEAbgBjAGUAIABvAGYA
# IAB0AGgAZQAgAEQAaQBnAGkAQwBlAHIAdAAgAEMAUAAvAEMAUABTACAAYQBuAGQA
# IAB0AGgAZQAgAFIAZQBsAHkAaQBuAGcAIABQAGEAcgB0AHkAIABBAGcAcgBlAGUA
# bQBlAG4AdAAgAHcAaABpAGMAaAAgAGwAaQBtAGkAdAAgAGwAaQBhAGIAaQBsAGkA
# dAB5ACAAYQBuAGQAIABhAHIAZQAgAGkAbgBjAG8AcgBwAG8AcgBhAHQAZQBkACAA
# aABlAHIAZQBpAG4AIABiAHkAIAByAGUAZgBlAHIAZQBuAGMAZQAuMAsGCWCGSAGG
# /WwDFTAfBgNVHSMEGDAWgBT0tuEgHf4prtLkYaWyoiWyyBc1bjAdBgNVHQ4EFgQU
# VlMPwcYHp03X2G5XcoBQTOTsnsEwcQYDVR0fBGowaDAyoDCgLoYsaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC10cy5jcmwwMqAwoC6GLGh0dHA6
# Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMIGFBggrBgEF
# BQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBP
# BggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsFAAOC
# AQEALoOhRAVKBOO5MlL62YHwGrv4CY0juT3YkqHmRhxKL256PGNuNxejGr9YI7JD
# nJSDTjkJsCzox+HizO3LeWvO3iMBR+2VVIHggHsSsa8Chqk6c2r++J/BjdEhjOQp
# gsOKC2AAAp0fR8SftApoU39aEKb4Iub4U5IxX9iCgy1tE0Kug8EQTqQk9Eec3g8i
# cndcf0/pOZgrV5JE1+9uk9lDxwQzY1E3Vp5HBBHDo1hUIdjijlbXST9X/AqfI157
# 9JSN3Z0au996KqbSRaZVDI/2TIryls+JRtwxspGQo18zMGBV9fxrMKyh7eRHTjOe
# Z2ootU3C7VuXgvjLqQhsUwm09zCCBTEwggQZoAMCAQICEAqhJdbWMht+QeQF2jaX
# whUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGln
# aUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTE2MDEwNzEyMDAwMFoXDTMxMDEw
# NzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGlnaUNlcnQgU0hB
# MiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnFOVQoV7YjSsQOB0UzURB90Pl9TWh+
# 57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQAOPcuHjvuzKb2Mln+X2U/4Jvr40ZH
# BhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhisEeTwmQNtO4V8CdPuXciaC1TjqAlx
# a+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQjMF287DxgaqwvB8z98OpH2YhQXv1m
# blZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+fMRTWrdXyZMt7HgXQhBlyF/EXBu89
# zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW/5MCAwEAAaOCAc4wggHKMB0GA1Ud
# DgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAT
# BgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGG
# GGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2Nh
# Y2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDCB
# gQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBQBgNVHSAESTBHMDgG
# CmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggEBAHGVEulRh1Zp
# ze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafDDiBCLK938ysfDCFaKrcFNB1qrpn4
# J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6HHssIeLWWywUNUMEaLLbdQLgcseY
# 1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4H9YLFKWA1xJHcLN11ZOFk362kmf7
# U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHKeZR+WfyMD+NvtQEmtmyl7odRIeRY
# YJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIoxhhWz0E0tmZdtnR79VYzIi8iNrJL
# okqV2PWmjlIxggJNMIICSQIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQD
# EyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgVGltZXN0YW1waW5nIENBAhAEzT+F
# aK52xhuw/nFgzKdtMA0GCWCGSAFlAwQCAQUAoIGYMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjAxMjIyMTYyNDAyWjArBgsqhkiG
# 9w0BCRACDDEcMBowGDAWBBQDJb1QXtqWMC3CL0+gHkwovig0xTAvBgkqhkiG9w0B
# CQQxIgQgCKjsHCQ24cdy7+J4R9YAZ62nhgPuYzR5sAx8atvP5NgwDQYJKoZIhvcN
# AQEBBQAEggEAUeRbik2mZ/ezP1h8kDjJ6F34jwV2UNKiBhYMNLaqdZjG2scxtw3f
# L6WbAkV4LsgjHkEqBLTjxgKVIkxtCAg9Mun65DaBTXIbV7f+utuwzgv3dnK7kxUf
# 34PB8fHzxTWSyIpr4OLjyT7hTRWps+jKSpKt+UT+jvRXtSmtU2bOBzFUnDS+qWNs
# bZsANLOibooS7O25p0QOQteUUn0+wlvYEFMxDW25mTuJc2h+K5+pnEM1resQNM0d
# wTCUG6sUbjsKa4L1Ol3jO6/SpuxPIyfbdXoHbYakDJUMwRaSfVYFl9z+XRDIdcUy
# KQftAvR963h9ESGpfQQ+3zABK7jX6SQWcA==
# SIG # End signature block
