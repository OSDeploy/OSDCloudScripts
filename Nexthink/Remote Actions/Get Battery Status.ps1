<#
.SYNOPSIS
Obtains battery health status.

.DESCRIPTION
Returns the health status of the battery installed on the laptop, in terms of capacity that it can still hold. It also retrieves the currently active power plan. Useful for identifying the batteries to be replaced and optimize the power settings of the devices.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   BatteryHealth                   Ratio           Health ratio, expressed as a percentage
2   BatteryDesignedCapacity         Int             Initial capacity, in milliamp per hour (mAh)
3   BatteryFullChargeCapacity       Int             Current full charge capacity, in milliamp per hour (mAh)
4   BatteryCycleCount               Int             Number of charge cycles the battery has so far
5   EstimatedBatteryLife            Millisecond     Estimated battery life time with one full charge. It will be 0 on Windows 7 devices
6   PowerPlan                       String          The power plan which is currently active on the device. It will display "Custom" if the power plan is not any of the default ones (Balanced, High performance, Power saving) and it will display "Unknown" in the case the information could not be retrieved

.RESTRICTIONS
- In the case of the device has multiple batteries, the script only retrieves information about the main one.
- The "Estimated Battery Life" value can only be obtained for Windows 10 devices. On Windows 7 devices, this value will be 0.
- The battery cycle count may be 0 sometimes, even though the battery has been recharged several times already.

.NOTES
Context:            LocalSystem
Version:            4.2.0.0 - Fixed powercfg.exe execution in Windows 10 ARM devices
                    4.1.2.0 - Execution frequency and suggested scheduling updated on documentation
                    4.1.1.0 - Made Remote Action compatible with devices with more than one battery
                    4.1.0.0 - Made Remote Action compatible with Windows 7 again
                    4.0.0.0 - Added "PowerPlan" output field and updated OS compatibility (Windows 10 only)
                    3.0.0.0 - Added new output fields and restricted to one battery only
                    2.1.0.0 - Major refactoring and bugfixing
                    2.0.0.0 - Support for at most 2 batteries
                    1.0.0.0 - Initial release
Last Generated:     30 Mar 2022 - 12:42:32
Copyright (C) 2022 Nexthink SA, Switzerland
#>

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
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script

New-Variable -Name 'REPORT_FILE_PATH' `
    -Value (Join-Path -Path $env:TEMP -ChildPath 'battery-report.xml') `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'POWERCFG_EXE' `
    -Value "$env:SystemRoot\System32\powercfg.exe" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SYSNATIVE_POWERCFG_EXE' `
    -Value "$env:SystemRoot\Sysnative\powercfg.exe" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'POWERCFG_BATTERY_INFO_ARGUMENTS' `
    -Value "/BATTERYREPORT /OUTPUT `"$REPORT_FILE_PATH`" /XML" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'POWERCFG_POWER_PLAN_ARGUMENT' `
    -Value '/GETACTIVESCHEME' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'ROOT_WMI_NAMESPACE' `
    -Value 'root\WMI' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'RUNTIME_REGEX' `
    -Value 'PT((?<hours>\d{1,2})H)?((?<minutes>\d{1,2})M)?((?<seconds>\d{1,2})S)?' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'POWER_PLAN_GUID_REGEX' `
    -Value '[a-fA-F-0-9]{8}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{12}' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'DEFAULT_POWER_PLANS' `
    -Value @{'381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'
             '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'
             'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'REPORT_XML_SCHEMA' `
    -Value 'http://schemas.microsoft.com/battery/2012' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'MULTIPLE_BATTERIES_MESSAGE' `
    -Value 'More than one battery were detected in this device. This Remote Action is designed to be run in devices with only one battery. Only data for the battery which is found first will be shown. ' `
    -Option ReadOnly -Scope Script -Force

#
# Invoke main
#
function Invoke-Main {
    $exitCode = 0
    [hashtable]$batteryOutput = Initialize-BatteryOutput

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-SupportedOSVersion

        Test-BatteryWmi
        Update-BatteryOutput -Output $batteryOutput
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -Output $batteryOutput
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

function Remove-File ([string]$Path) {
    if ([string]::IsNullOrEmpty($Path) -or `
        (-not (Test-Path -Path $Path))) { return }

    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Test-WOW6432Process {

    return (Test-Path Env:\PROCESSOR_ARCHITEW6432)
}

function Invoke-Process ([string]$FilePath, [string]$Arguments) {
    $output = @{ExitCode = -1
                StdOut = $null
                StdErr = $null}
    $processInfo = New-object -TypeName diagnostics.processstartinfo
    $processInfo.CreateNoWindow = $true
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.FileName = $FilePath
    $processInfo.Arguments = $Arguments
    $processInfo.WorkingDirectory = Split-Path $FilePath -Parent
    $process = New-Object -TypeName diagnostics.process
    $process.StartInfo = $processInfo

    try {
        [void]$process.Start()
        $output.StdOut = $process.StandardOutput.ReadToEnd()
        $output.StdErr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) '$FilePath' execution failed. "
    } finally {
        $output.ExitCode = $process.ExitCode
        $process.Dispose()
    }

    return $output
}

#
# Battery management
#
function Initialize-BatteryOutput {
    return  @{BatteryHealth = [float]0
              BatteryDesignedCapacity = 0
              BatteryFullChargeCapacity = 0
              BatteryCycleCount = 0
              EstimatedBatteryLife = 0 -as [timespan]
              PowerPlan = '-'}
}

function Test-BatteryWmi {
    if ($null -eq (Get-WmiObject -Class 'Win32_Battery' `
                                 -ErrorAction SilentlyContinue)) {
        throw 'The battery on this device cannot be detected. '
    }
}

function Update-BatteryOutput ([hashtable]$Output) {
    $batteryData = Get-BatteryData

    $Output.BatteryDesignedCapacity = $batteryData.DesignCapacity -as [int]
    $Output.BatteryFullChargeCapacity = $batteryData.FullChargeCapacity -as [int]
    $Output.BatteryCycleCount = $batteryData.CycleCount -as [int]
    $Output.EstimatedBatteryLife = $batteryData.EstimatedBatteryLife

    $Output.BatteryHealth = Get-BatteryHealth -DesignedCapacity $Output.BatteryDesignedCapacity `
                                              -FullChargedCapacity $Output.BatteryFullChargeCapacity
    $Output.PowerPlan = Get-CurrentPowerPlan
}

function Get-BatteryData {
    $osVersion = (Get-OSVersion) -as [version]
    if ($osVersion.Major -eq 10) { return Get-BatteryDataFromPowerCfg }
    return Get-BatteryDataFromWmi
}

function Get-BatteryDataFromPowerCfg {
    $batteryData = @{}

    try {
        [xml]$batteryReportXml = Get-BatteryReportContent

        $batteryObject = Get-FirstBatteryNode -Report $batteryReportXml

        $batteryData.DesignCapacity = $batteryObject.DesignCapacity
        $batteryData.FullChargeCapacity = $batteryObject.FullChargeCapacity
        $batteryData.CycleCount = $batteryObject.CycleCount
        $batteryData.EstimatedBatteryLife = Get-EstimatedBatteryLife -ContentXml $batteryReportXml
    } finally {
        Remove-File -Path $REPORT_FILE_PATH
    }

    return $batteryData
}

function Get-FirstBatteryNode([xml]$Report) {
    [object[]]$batteryNodes = @()
    try {
        $namespace = New-Object xml.xmlnamespacemanager $Report.NameTable
        $namespace.AddNamespace("batteryReportNamespace", `
                                "$REPORT_XML_SCHEMA")

        [object[]]$batteryNodes = $Report.SelectNodes("//batteryReportNamespace:Battery", $namespace)
        if ($batteryNodes.Count -gt 1) { Write-StatusMessage $MULTIPLE_BATTERIES_MESSAGE }
    } catch {
        throw "Unable to get first battery from xml document. Error: $_ "
    }

    return $batteryNodes[0]
}

function Get-BatteryReportContent {
    $parameters = @{Arguments = $POWERCFG_BATTERY_INFO_ARGUMENTS}
    if (Test-WOW6432Process) {
        $parameters.FilePath = $SYSNATIVE_POWERCFG_EXE
    } else {
        $parameters.FilePath = $POWERCFG_EXE
    }
    $output = Invoke-Process @parameters

    if ($output.ExitCode -ne 0) {
        throw "There was an error executing '$POWERCFG_EXE' with arguments '$POWERCFG_BATTERY_INFO_ARGUMENTS'. "
    }

    return (Get-Content -Path $REPORT_FILE_PATH) -as [xml]
}

function Get-EstimatedBatteryLife ([xml]$ContentXml) {
    $activeRunTimeRetrieved = $ContentXml.BatteryReport.RuntimeEstimates.FullChargeCapacity.ActiveRuntime
    if ($activeRunTimeRetrieved -match $RUNTIME_REGEX) {
        $hour = $Matches.hours -as [int]
        $minutes = $Matches.minutes -as [int]
        $seconds = $Matches.seconds -as [int]
        return "$hour`:$minutes`:$seconds" -as [timespan]
    }

    Write-StatusMessage -Message "Active runtime may be unreliable. Retrieved value '$activeRunTimeRetrieved' does not have the expected format. "
    return 0 -as [timespan]
}

function Get-BatteryDataFromWmi {
    $batteryData = @{}

    [int[]]$designCapacities = @(Get-WmiClassProperty -Namespace $ROOT_WMI_NAMESPACE `
                                                      -Class 'BatteryStaticData' `
                                                      -Property 'DesignedCapacity')
    [int[]]$fullChargeCapacities = @(Get-WmiClassProperty -Namespace $ROOT_WMI_NAMESPACE `
                                                          -Class 'BatteryFullChargedCapacity' `
                                                          -Property 'FullChargedCapacity')
    [int[]]$cycleCounts = @(Get-WmiClassProperty -Namespace $ROOT_WMI_NAMESPACE `
                                                 -Class 'BatteryCycleCount' `
                                                 -Property 'CycleCount')

    $designCapacitiesCount = $designCapacities.Length
    $fullChargeCapacitiesCount = $fullChargeCapacities.Length
    $cycleCountsCount = $cycleCounts.Length

    if ($designCapacitiesCount -gt 1 -or $fullChargeCapacitiesCount -gt 1 -or $cycleCountsCount -gt 1) {
        Write-StatusMessage $MULTIPLE_BATTERIES_MESSAGE
        if ($designCapacitiesCount -ne $fullChargeCapacitiesCount -or $designCapacitiesCount -ne $cycleCountsCount) {
            Write-StatusMessage -Message 'Battery data may not be reliable due to lack of information from WMI. '
        }
    }

    $batteryData.DesignCapacity = $designCapacities[0] -as [int]
    $batteryData.FullChargeCapacity = $fullChargeCapacities[0] -as [int]
    $batteryData.CycleCount = $cycleCounts[0] -as [int]
    $batteryData.EstimatedBatteryLife = 0 -as [timespan]

    return $batteryData
}

function Get-WmiClassProperty ([string]$Namespace, [string]$Class, [string]$Property) {
    try {
        Get-WmiObject -Namespace $Namespace -Class $Class |
            Select-Object -ExpandProperty $Property -ErrorAction SilentlyContinue
    } catch {
        Write-StatusMessage -Message "Could not obtain $Property property from $Class class at $Namespace Namespace. "
    }
}

function Get-BatteryHealth ([int]$DesignedCapacity, [int]$FullChargedCapacity) {
    if ($DesignedCapacity -eq 0) {
        Write-StatusMessage -Message 'Battery health may be unreliable. Designed capacity data is missing. '
        return 0
    }

    if ($FullChargedCapacity -gt $DesignedCapacity) {
        Write-StatusMessage -Message 'Battery health may be unreliable. Retrieved capacity exceeds maximum capacity. '
        return 1.0
    }

    [float]$batteryHealth = $FullChargedCapacity / $DesignedCapacity
    if ($batteryHealth -lt 0) {
        Write-StatusMessage -Message 'Battery health may be unreliable. Some retrieved data is not correct. '
        return 0
    }

    return $batteryHealth
}

function Get-CurrentPowerPlan {
    [hashtable]$output = Invoke-Process -FilePath $POWERCFG_EXE `
                                        -Arguments $POWERCFG_POWER_PLAN_ARGUMENT
    if ($output.StdOut -match $POWER_PLAN_GUID_REGEX) {
        if ($DEFAULT_POWER_PLANS.ContainsKey($Matches[0])) { return $DEFAULT_POWER_PLANS.($Matches[0]) }
        return 'Custom'
    }
    return 'Unknown'
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$Output) {
    [nxt]::WriteOutputRatio('BatteryHealth', $Output.BatteryHealth)
    [nxt]::WriteOutputUInt32('BatteryDesignedCapacity', $Output.BatteryDesignedCapacity)
    [nxt]::WriteOutputUInt32('BatteryFullChargeCapacity', $Output.BatteryFullChargeCapacity)
    [nxt]::WriteOutputUInt32('BatteryCycleCount', $Output.BatteryCycleCount)
    [nxt]::WriteOutputDuration('EstimatedBatteryLife', $Output.EstimatedBatteryLife)
    [nxt]::WriteOutputString('PowerPlan', $Output.PowerPlan)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main))
# SIG # Begin signature block
# MIIimgYJKoZIhvcNAQcCoIIiizCCIocCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCKyOowfcEj3Inb
# +rjWp2JTefH4LTn9bWlxCcP7cdy3raCCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCByJRu/dnnr
# tJoiySX4g3QAhOeQ8cWMks9xQle9aTnO9zANBgkqhkiG9w0BAQEFAASCAgBtl71e
# XCOcw8Uf9Qf+/jhtUJinqXx5qdP8VWcOuwJP0wGD/WwSmxzPYYfhOASbU47o/XY9
# tZueXMT98eVPf8xwaZuuylOSRlatOtYM7i4artpvHED71N2q9DIHKOHHyQcliXJK
# MQiPpvtJHduRKf+Xsnh/eHjJSpG1gvwf76Mxjq3Vnr7TZIYFUafiYElbe2y9s2xI
# 3Cn1KaL8pj+1fKtVpvI6NME/VoLcG+GhYK0S4IBomQbHTzbeQdFeJn2aZc8Ibc3J
# TePojPOwnDRhfAH4xRFensjhZjmOm8rpRIrUi0b7MZmT1cg75wqUFudjoTWdHZvs
# PX2/b9u5P9ktDuGbbPWofxHrwolqlz0Lv/YB3GrSj8AQJG1w0UGdhIFig5S7iDln
# jlwfn0G0Zg9nnwpp6f/PEDZgi15AcSFWnKMVIDrhFCXStRU8zd5FdpTcpDxcsiBJ
# sxnzcuQO+aUp4J3XMEiK2gcf0qsbOSB92DGOjhfWaSGv4/ouOjEMmKk3NVC8wyab
# TS3/MPZ83HTnHQNbYQ6Qm1aMOTCzTN1Ft5i6ywlMIKnrpz4tGliQrYjLVU8muRRE
# e2ZpofCjLw5PBL3TCB1LhOC5KSn50D4sQGfxi6OWzYOjff+eX3T66DYUCc7R0Y8S
# NqDp+76kcBOnn6DHlM3zGQ9GPGoGvU++GUZNLaGCDX4wgg16BgorBgEEAYI3AwMB
# MYINajCCDWYGCSqGSIb3DQEHAqCCDVcwgg1TAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCB0qT4+TRhtFcufTlDkHR2cRcSge+HlO/aeqQMXAZIQvQIRAMtX2JPE62y0
# 1ApS+QkZZ6UYDzIwMjIwMzMwMTA0MjQwWqCCCjcwggT+MIID5qADAgECAhANQkrg
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
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMjAzMzAxMDQyNDBaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFOHXgqjhkb7va8oWkbWqtJSmJJvzMC8GCSqGSIb3DQEJBDEi
# BCC+PySfbf3LpRLerCf2jZU0zEZzq7eAvsJx949laAajEDA3BgsqhkiG9w0BCRAC
# LzEoMCYwJDAiBCCzEJAGvArZgweRVyngRANBXIPjKSthTyaWTI01cez1qTANBgkq
# hkiG9w0BAQEFAASCAQB5zaotmng5No1AxGAtImIAq7uyc1PvH+/NZz8yxLAcUwgt
# 6KZcshOD8+Qmi2BFvd8mrAqKrcfxP5osilU9+J3xK+Okaika8SV7bttVXAyitl6Z
# XZwlvlO+mdVxm+KNoc96LXvbMzdsDVc4jUb8mIsuuU825zrKc6C6oy7sedQkCSOM
# JCOHmTCbyRmlN0jU1BCpRJkNbqJz68PF5ava6KbQ94BvSzmpVee2oSNOZEUAuYyj
# K7EL13ZOinphLEd/PIWIKYbsPE3ewQ4hOf7aHK6RiX3lnr5DTf7dt6+rSEpy/HWc
# AWEavubECgE8ugpPVemVJflkKuqzT7zM47ucqpCh
# SIG # End signature block
