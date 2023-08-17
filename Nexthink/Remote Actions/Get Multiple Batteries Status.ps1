<#
.SYNOPSIS
Obtains battery health status for devices with 2 batteries.

.DESCRIPTION
Returns the health status of the batteries installed on the laptop, in terms of capacity that they can still hold. It also retrieves the currently active power plan. Useful for identifying the batteries to be replaced and optimize the power settings of the devices.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   Battery1Health                  Ratio           Health ratio for battery 1, expressed as a percentage
2   Battery1DesignedCapacity        Int             Initial capacity for battery 1, in milliamp hour (mAh)
3   Battery1FullChargeCapacity      Int             Current full charge capacity for battery 1, in milliamp hour (mAh)
4   Battery1CycleCount              Int             Number of charge cycles the battery 1 has so far
5   Battery2Health                  Ratio           Health ratio for battery 2, expressed as a percentage
6   Battery2DesignedCapacity        Int             Initial capacity for battery 2, in milliamp hour (mAh)
7   Battery2FullChargeCapacity      Int             Current full charge capacity for battery 2, in milliamp hour (mAh)
8   Battery2CycleCount              Int             Number of charge cycles the battery 2 has so far
9   EstimatedBatteryLife            Millisecond     Estimated life time with one full charge. It will be 0 on Windows 7 devices
10  PowerPlan                       String          The power plan which is currently active on the device. It will display "Custom" if the power plan is not any of the default ones (Balanced, High performance, Power saving) and it will display "Unknown" in the case the information could not be retrieved

.RESTRICTIONS
- In the case the device has only one battery, outputs for the second one will be the default values (empty or 0).
- Up to 2 batteries are supported for data retrieval.
- The "Estimated Battery Life" value can only be obtained for Windows 10 devices. On Windows 7 devices, this value will be 0.
- The battery cycle count may be 0 sometimes, even though the battery has been recharged several times already.

.NOTES
Context:            LocalSystem
Version:            1.0.0.0 - Initial release
Last Generated:     17 Apr 2020 - 10:00:45
Copyright (C) 2020 Nexthink SA, Switzerland
#>

# End of parameters definition

#
# Constants definition
#
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
    -Value 'PT(\d{1,2})H(\d{1,2})M(\d{1,2})S' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'POWER_PLAN_GUID_REGEX' `
    -Value '[a-fA-F-0-9]{8}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{12}' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'DEFAULT_POWER_PLANS' `
    -Value @{'381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'
             '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'
             'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'} `
    -Option ReadOnly -Scope Script -Force

#
# Invoke main
#
function Invoke-Main {
    $exitCode = 0
    [hashtable]$batteriesOutput = Initialize-BatteriesOutput

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-SupportedOSVersion

        Test-BatteryWmi
        Update-BatteriesOutput -Output $batteriesOutput
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -Output $batteriesOutput
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
    $currentIdentity = Get-CurrentIdentity
    if ($currentIdentity -ne $LOCAL_SYSTEM_IDENTITY) {
        throw 'This script must be run as LocalSystem. '
    }
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

function Remove-File ([string]$Path) {
    if ([string]::IsNullOrEmpty($Path) -or `
        (-not (Test-Path -Path $Path))) { return }

    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
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
        throw "'$FilePath' execution failed. "
    } finally {
        $output.ExitCode = $process.ExitCode
        $process.Dispose()
    }

    return $output
}

#
# Batteries management
#
function Initialize-BatteriesOutput {
    return  @{Battery1Health = [float]0
              Battery1DesignedCapacity = 0
              Battery1FullChargeCapacity = 0
              Battery1CycleCount = 0
              Battery2Health = [float]0
              Battery2DesignedCapacity = 0
              Battery2FullChargeCapacity = 0
              Battery2CycleCount = 0
              EstimatedBatteryLife = 0 -as [timespan]
              PowerPlan = '-'}
}

function Test-BatteryWmi {
    if ($null -eq (Get-WmiObject -Class 'Win32_Battery' `
                                 -ErrorAction SilentlyContinue)) {
        throw 'The battery on this device cannot be detected. '
    }
}

function Update-BatteriesOutput ([hashtable]$Output) {
    [hashtable[]]$batteriesData = @(Get-BatteriesData)

    Update-Battery -Output $Output -BatteriesData $batteriesData -BatteryNumber 1
    if ($batteriesData.Length -gt 1) {
        Update-Battery -Output $Output -BatteriesData $batteriesData -BatteryNumber 2
    }

    $Output.PowerPlan = Get-CurrentPowerPlan
    $Output.EstimatedBatteryLife = $batteriesData[0].EstimatedBatteryLife
}

function Get-BatteriesData {
    $osVersion = (Get-OSVersion) -as [version]
    if ($osVersion.Major -eq 10) { return Get-BatteriesDataFromPowerCfg }
    return Get-BatteriesDataFromWmi
}

function Get-BatteriesDataFromPowerCfg {
    [hashtable[]]$batteriesData = @()

    try {
        [xml]$batteryReportXml = Get-BatteryReportContent

        $estimatedLife = Get-EstimatedBatteryLife -ContentXml $batteryReportXml

        foreach ($batteryObject in $batteryReportXml.BatteryReport.Batteries.Battery) {
            $batteriesData += @{DesignCapacity = $batteryObject.DesignCapacity
                                FullChargeCapacity = $batteryObject.FullChargeCapacity
                                CycleCount = $batteryObject.CycleCount
                                EstimatedBatteryLife = $estimatedLife}
        }
    } finally {
        Remove-File -Path $REPORT_FILE_PATH
    }

    return $batteriesData
}

function Get-BatteryReportContent {
    [hashtable]$output = Invoke-Process -FilePath $POWERCFG_EXE `
                                        -Arguments $POWERCFG_BATTERY_INFO_ARGUMENTS
    if ($output.ExitCode -ne 0) {
        throw "There was an error executing '$POWERCFG_EXE' with arguments '$POWERCFG_BATTERY_INFO_ARGUMENTS'. "
    }

    return (Get-Content -Path $REPORT_FILE_PATH) -as [xml]
}

function Get-EstimatedBatteryLife ([xml]$ContentXml) {
    $batteryLife = $ContentXml.BatteryReport.RuntimeEstimates.FullChargeCapacity.ActiveRuntime
    if ($batteryLife -match $RUNTIME_REGEX) {
        $hour = $Matches[1]
        $minutes = $Matches[2]
        $seconds = $Matches[3]
        return "$hour`:$minutes`:$seconds" -as [timespan]
    }

    Write-StatusMessage -Message "Estimated battery life may be unreliable. Retrieved value '$batteryLife' does not have the expected format. "
    return 0 -as [timespan]
}

function Get-BatteriesDataFromWmi {
    [hashtable[]]$batteriesData = @()

    [int[]]$designCapacities = @(Get-WmiClassProperty -Namespace $ROOT_WMI_NAMESPACE `
                                                      -Class 'BatteryStaticData' `
                                                      -Property 'DesignedCapacity')
    [int[]]$fullChargeCapacities = @(Get-WmiClassProperty -Namespace $ROOT_WMI_NAMESPACE `
                                                          -Class 'BatteryFullChargedCapacity' `
                                                          -Property 'FullChargedCapacity')
    [int[]]$cycleCounts = @(Get-WmiClassProperty -Namespace $ROOT_WMI_NAMESPACE `
                                                 -Class 'BatteryCycleCount' `
                                                 -Property 'CycleCount')

    $count = $designCapacities.Length
    if ($count -ne $fullChargeCapacities.Length -or $count -ne $cycleCounts.Length) {
        Write-StatusMessage -Message 'Battery data may not be reliable due to lack of information from WMI. '
    }

    for ($i = 0; $i -lt $count; $i++) {
        $designCapacity = $(if ($i -lt $designCapacities.Length) { $designCapacities[$i] } else { 0 })
        $fullChargeCapacity = $(if ($i -lt $fullChargeCapacities.Length) { $fullChargeCapacities[$i] } else { 0 })
        $cycleCount = $(if ($i -lt $cycleCounts.Length) { $cycleCounts[$i] } else { 0 })

        $batteriesData += @{DesignCapacity = $designCapacity
                            FullChargeCapacity = $fullChargeCapacity
                            CycleCount = $cycleCount
                            EstimatedBatteryLife = 0 -as [timespan]}
    }

    return $batteriesData
}

function Get-WmiClassProperty ([string]$Namespace, [string]$Class, [string]$Property) {
    try {
        return Get-WmiObject -Namespace $Namespace -Class $Class |
                   Select-Object -ExpandProperty $Property -ErrorAction SilentlyContinue
    } catch {
        Write-StatusMessage -Message "Could not obtain $Property property from $Class class at $Namespace Namespace. "
    }
}

function Update-Battery ([hashtable]$Output, [hashtable[]]$BatteriesData, [int]$BatteryNumber) {
    $batteriesDataIndex = $BatteryNumber - 1

    if ($BatteryNumber -lt 1) {
        throw 'BatteryNumber cannot be 0 nor negative. '
    }

    if ($BatteryNumber -gt $BatteriesData.Length) {
        throw "Information about battery $BatteryNumber is not present. "
    }

    $Output["Battery$($BatteryNumber)DesignedCapacity"] = $BatteriesData[$batteriesDataIndex].DesignCapacity -as [int]
    $Output["Battery$($BatteryNumber)FullChargeCapacity"] = $BatteriesData[$batteriesDataIndex].FullChargeCapacity -as [int]
    $Output["Battery$($BatteryNumber)CycleCount"] = $BatteriesData[$batteriesDataIndex].CycleCount -as [int]

    [float]$health = Get-BatteryHealth -DesignedCapacity $Output["Battery$($BatteryNumber)DesignedCapacity"] `
                                       -FullChargedCapacity $Output["Battery$($BatteryNumber)FullChargeCapacity"]
    $Output["Battery$($BatteryNumber)Health"] = $health
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
    [nxt]::WriteOutputRatio('Battery1Health', $Output.Battery1Health)
    [nxt]::WriteOutputUInt32('Battery1DesignedCapacity', $Output.Battery1DesignedCapacity)
    [nxt]::WriteOutputUInt32('Battery1FullChargeCapacity', $Output.Battery1FullChargeCapacity)
    [nxt]::WriteOutputUInt32('Battery1CycleCount', $Output.Battery1CycleCount)

    [nxt]::WriteOutputRatio('Battery2Health', $Output.Battery2Health)
    [nxt]::WriteOutputUInt32('Battery2DesignedCapacity', $Output.Battery2DesignedCapacity)
    [nxt]::WriteOutputUInt32('Battery2FullChargeCapacity', $Output.Battery2FullChargeCapacity)
    [nxt]::WriteOutputUInt32('Battery2CycleCount', $Output.Battery2CycleCount)

    [nxt]::WriteOutputDuration('EstimatedBatteryLife', $Output.EstimatedBatteryLife)
    [nxt]::WriteOutputString('PowerPlan', $Output.PowerPlan)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main))
# SIG # Begin signature block
# MIIj5AYJKoZIhvcNAQcCoIIj1TCCI9ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBRK3xt/BvGmg9L
# F5JAa0DhUGn5ON9F5UJZw2yLGGiiRaCCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDsbC0Volh+
# 1e5qWc+CFblqQvmGXSeSftye0KwOVrnonTANBgkqhkiG9w0BAQEFAASCAgAvOefL
# rAPZ7pjHXd+rBYF9EcarlmPYNZG0WzUPesSMysIcSxbyUCHT2Ik86++92GOTXhy0
# ADKAEMkT2gfPr9IWdOe0jtBgLSqEYSptiLDON2nYEIeEi4rPewioSSiiYPiXOa4g
# 3bR2SBbaEdJdNvD7POh4s2Uj/s9eu8UBDk6s/wc1wQJjzhW4qofrZKutXGK2T5jD
# rSMR2NdjPNyGUgxBmzapd2gxST0QkDP6mhJKXw4xVK8gEhqVJEu6TSLgZY31nfKi
# QEyEuRSdeYHegPvfxLb259oOCyL2WhvpVsgOEMLs71f76qmxbOBQHgOvDsZi9x0E
# n2dB3B+ojMXpPkACAllS8H3ME0BqQ4WRpmcEdQ+CuVbJpP1uHlgISE6AG26cBdc/
# 2hKFUK2/TD7v4m0v9OeNrR2Ai7HOFgY9Acbk8NYmNG/+7hnx3Vz1xc1zIUVlYbZH
# Yrfq7ZVlEOCRqCioX9kE718NYazeEZxu9a7UT8kTrkZo1Gp2rN5PlKPP5igmRIzf
# uacKm8GN9vtQp6qmLAiGzTH+fbjUzDaGoVQv2I6XfmN4RLxNRbthyIy2czdmUjF9
# MYjCifWcmDpQMc+Ze5XwCH8gU0yBYmahpRcFhuPnKCDKFUzsrev6knckTWFq9lj0
# yO7KW5iAPOyynHMEDRXXGOReteyw0HVgZPwJQaGCDsgwgg7EBgorBgEEAYI3AwMB
# MYIOtDCCDrAGCSqGSIb3DQEHAqCCDqEwgg6dAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCCQjH1miq3jtpLDW0jPwNpQW3ZdwpaFU2eWOeCbXVbRHgIQdjBDinjXW4Lm
# p7LMh+xkURgPMjAyMDA4MTkxNjM3MjlaoIILuzCCBoIwggVqoAMCAQICEATNP4Vo
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
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMDA4MTkxNjM3MjlaMCsGCyqGSIb3
# DQEJEAIMMRwwGjAYMBYEFAMlvVBe2pYwLcIvT6AeTCi+KDTFMC8GCSqGSIb3DQEJ
# BDEiBCAy/wvtX5uSkOUwHGICSyaorRd76KLx5xK0U7F2+wIvjjANBgkqhkiG9w0B
# AQEFAASCAQB6MNviBtPmuWYmPb6dJQSSG/c9qYKBZsJ63pv/3+UFiqtGMQ9knlNN
# FjLXlKY7UF3RgT9ZJS8GC/vL+Oe4q6JWdwyRTA15dSeLwknUHF6W3PrhvXpwXOhk
# N9Ra5xb5xKwtX7wzbHKDq1632jsCeKu0twVaaCZn0Du4/Aztvx/GJsaCYcn5KTek
# KmScCbZDq3GYLpdxnUeK2rI9bbfBaQokrd+myp0w+cy2Ntz/jELy9lHParAIcxxi
# 22p8uqUrwNAD+TOZyJX/gSiyzYtHXSZVzgcYZ7W6sqvBO+6rCpMfWYVXUPjrlgE5
# EPfJhcTav7HY/h5R2q73C2IK83AFRPhT
# SIG # End signature block
