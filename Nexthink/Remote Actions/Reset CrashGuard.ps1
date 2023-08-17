<#
.SYNOPSIS
Resets CrashGuard counter and restarts the Collector.

.DESCRIPTION
ADVANCED SCRIPT
Resets the Collector CrashGuard count and restarts the Collector driver. The script is designed for Windows 10 and 7.

.FUNCTIONALITY
Remediation

.FURTHER INFORMATION
The status of the Collector is checked before resetting the CrashGuard.

.NOTES
Context:            LocalSystem
Version:            1.0.2.0 - Adapted the code to the new service name after 6.30.5
                    1.0.1.0 - Reformatting and message improvement
                    1.0.0.0 - Initial release
Last Generated:     12 May 2021 - 17:02:01
Copyright (C) 2021 Nexthink SA, Switzerland
#>

#
# Constants definition
#
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'COLLECTOR_PRIMARY_DRIVER' `
    -Value 'nxtrdrv' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_SECONDARY_DRIVER' `
    -Value 'nxtrdrv5' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_SECONDARY_DRIVER_6_30_1' `
    -Value 'nxtrdrvwfp' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_HELPER' `
    -Value 'Nexthink Service' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NXTRDRV_REG_PATH' `
    -Value 'HKLM:\SYSTEM\CurrentControlSet\services\nxtrdrv' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'CRASH_INFO' `
    -Value 'CrashInfo' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'CRASH_INFO_REG_TYPE' `
    -Value 'BINARY' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'LAST_UNLOAD_SUCCESS_POS' `
    -Value 0 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FAILURE_COUNT_POS' `
    -Value 1 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MAX_FAILURE_COUNT_POS' `
    -Value 5 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'REACTIVATION_START_POS' `
    -Value 13 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'REACTIVATION_END_POS' `
    -Value 20 `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'CLT_REG_KEY' `
    -Value 'HKLM:\SOFTWARE\Nexthink' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'CLT_REG_VERSION' `
    -Value 'ProductVersion' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NUM_RETRIES' `
    -Value 25 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'RETRY_WAIT_MS' `
    -Value 200 `
    -Option ReadOnly -Scope Script -Force

if (-not ('ServiceStatus' -as [type])) {
    Add-Type -TypeDefinition 'public enum ServiceStatus {Running, Stopped}'
}

#
# Environment checks
#
function Test-RunningAsLocalSystem {
    $currentIdentity = Get-CurrentIdentity
    if ($currentIdentity -ne $LOCAL_SYSTEM_IDENTITY) {
        throw 'This script must be run as LocalSystem. '
    }
}

function Get-CurrentIdentity {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.ToString()
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

function Test-CollectorVersion {
    if (-not (Test-RegistryKey -Key $CLT_REG_KEY -Property $CLT_REG_VERSION)) {
        throw 'Collector is not installed. '
    }

    $cltVersion = Get-RegistryKey -Key $CLT_REG_KEY -Property $CLT_REG_VERSION
    if (-not ($cltVersion -as [version])) {
        throw "Wrong value of Collector version, found $cltVersion. "
    }
}

#
# Registry management
#
function Test-RegistryKey ([string]$Key, [string]$Property) {
    return $null -ne (Get-ItemProperty -Path $Key `
                                       -Name $Property `
                                       -ErrorAction SilentlyContinue)
}

function Get-RegistryKey ([string]$Key, [string]$Property) {
    return (Get-ItemProperty -Path $Key `
                             -Name $Property `
                             -ErrorAction SilentlyContinue).$Property
}

function Set-RegistryKey ([string]$Key, [string]$Property, [string]$Type, [byte[]]$Value) {
    if (-not (Test-Path -Path $Key)) { [void](New-Item -Path $Key -Force) }
    [void](New-ItemProperty -Path $Key `
                            -Name $Property `
                            -PropertyType $Type `
                            -Value $Value -Force)
}

#
# Services management
#
function Stop-GivenService ([string]$ServiceName) {
    if (Test-ServiceExists -ServiceName $ServiceName) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Wait-GivenServiceProperty -ServiceName $ServiceName `
                                  -Property 'Status' `
                                  -DesiredPropertyValue ([servicestatus]::Stopped).ToString()
    }
}

function Wait-GivenServiceProperty ([string]$ServiceName,
                                    [string]$Property,
                                    [string]$DesiredPropertyValue) {
    $i = 0
    while ((Get-GivenServiceProperty -ServiceName $ServiceName `
                                     -Property $Property) -ne $DesiredPropertyValue) {
        if ($i -ge $NUM_RETRIES - 1) {
            throw "There was an error changing the '$ServiceName' service '$Property' to '$DesiredPropertyValue'. "
        }
        Start-Sleep -Milliseconds $RETRY_WAIT_MS
        $i++
    }
}

function Get-GivenServiceProperty ([string]$ServiceName, [string]$Property) {
    return [string](Get-GivenService -ServiceName $ServiceName).$Property
}

function Test-ServiceExists ([string]$ServiceName) {
    return $null -ne (Get-GivenService -ServiceName $ServiceName)
}

function Get-GivenService ([string]$ServiceName) {
    return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Start-GivenService ([string]$ServiceName) {
    if (Test-ServiceExists -ServiceName $ServiceName) {
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        Wait-GivenServiceProperty -ServiceName $ServiceName `
                                -Property 'Status' `
                                -DesiredPropertyValue ([servicestatus]::Running).ToString()
    }
}

#
# CrashGuard management
#
function Restart-CollectorIfNeeded {
    [byte[]]$crashInfoValue = Get-CrashInfo
    if (Test-CrashGuardActive -CrashInfo $crashInfoValue) {
        Restart-CollectorDriverResettingCrashGuard -CrashInfo $CrashInfoValue
        Write-StatusMessage -Message 'CrashGuard reset and Collector successfully restarted. '
    } else {
        Write-StatusMessage -Message 'Number of failures inferior to the maximum allowed. Not needed to restart Collector. '
    }
}

function Get-CrashInfo {
    if (-not (Test-RegistryKey -Key $NXTRDRV_REG_PATH -Property $CRASH_INFO)) {
        throw 'Registry key for CrashGuard not found. '
    }
    return Get-RegistryKey -Key $NXTRDRV_REG_PATH -Property $CRASH_INFO
}

function Test-CrashGuardActive ([byte[]]$CrashInfo) {
    return $CrashInfo[$FAILURE_COUNT_POS] -ge $CrashInfo[$MAX_FAILURE_COUNT_POS]
}

function Restart-CollectorDriverResettingCrashGuard ([byte[]]$CrashInfo) {
    Stop-GivenService -ServiceName $COLLECTOR_HELPER
    Stop-GivenService -ServiceName $COLLECTOR_SECONDARY_DRIVER
    Stop-GivenService -ServiceName $COLLECTOR_SECONDARY_DRIVER_6_30_1
    Stop-GivenService -ServiceName $COLLECTOR_PRIMARY_DRIVER

    Reset-CrashGuard -CrashInfo $CrashInfo

    Start-GivenService -ServiceName $COLLECTOR_PRIMARY_DRIVER
    Start-GivenService -ServiceName $COLLECTOR_SECONDARY_DRIVER
    Start-GivenService -ServiceName $COLLECTOR_SECONDARY_DRIVER_6_30_1
    Start-GivenService -ServiceName $COLLECTOR_HELPER
}

function Reset-CrashGuard ([byte[]]$CrashInfo) {
    $newCrashInfo = $CrashInfo

    $newCrashInfo[$LAST_UNLOAD_SUCCESS_POS] = 1
    $newCrashInfo[$FAILURE_COUNT_POS] = 0
    for ($i = $REACTIVATION_START_POS; $i -le $REACTIVATION_END_POS; $i++) { $newCrashInfo[$i] = 0 }
    Set-CrashGuard -NewCrashInfo $newCrashInfo
}

function Set-CrashGuard ([byte[]]$NewCrashInfo) {
    try { Set-RegistryKey -Key $NXTRDRV_REG_PATH `
                          -Property $CRASH_INFO `
                          -Type $CRASH_INFO_REG_TYPE `
                          -Value $NewCrashInfo }
    catch { throw 'Impossible to reset registry key for CrashGuard. ' }
}

function Write-StatusMessage ([psobject]$Message) {
    $exception = $Message.ToString()

    if ($Message.InvocationInfo.ScriptLineNumber) {
        $errorLineMessage = "Line '$($Message.InvocationInfo.ScriptLineNumber)'. "
    }

    $host.ui.WriteErrorLine($errorLineMessage + $exception)
}

#
# Invoke Main
#
function Invoke-Main {
    $exitCode = 0
    try {
        Test-RunningAsLocalSystem
        Test-SupportedOSVersion
        Test-CollectorVersion

        Restart-CollectorIfNeeded
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    }

    return $exitCode
}

#
# Main script flow
#
[Environment]::Exit((Invoke-Main))

# SIG # Begin signature block
# MIIiYQYJKoZIhvcNAQcCoIIiUjCCIk4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCcj+2fc4klPBaa
# 7rSi+2r1q5Yx/p9VD+VYuJLemNsFyKCCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIQfDCCEHgCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDmsgCCGMYh
# 9PIAS36gwvQ+WHxvDN4fd/SJyRVTtPmYbzANBgkqhkiG9w0BAQEFAASCAgBJCHnZ
# ZMvQhI2a9/QO9F6fl0VWNbYtSFHQR/zNTARIWJZreDbx7ilmJdp9AqPQ3NR9ByII
# UVluYv7gf6y9/vb9BJXzpYAM5evQdhB8TsNjXtlv1edVB+YOCFhljkoS7mfbSoT9
# uCZwP/yvxQOjZsG2rC5Adz3mRl5tREnCUhIpdi6f9+ffGD7SZ296puRurvclJx72
# gqrtRtFN+gL/lhsl/32ojIU0iuj9cOlX9j7ETYA4zlK1sgAbASiNZgE+CEVIhEnr
# zA5o2rNV+KtvJ95sMgzTlDwMV+QRxnt4WFweIG9GcLmkRPMRQssWt8DoS0x5fmTV
# E2PSlqMBZvy8Oxg2dQPpZg2dTxOTVly7wuu9Xso/6NZPM9n8PxPc2mT2Y+MkwAWb
# B9ZlMuRUSsskpNHZcem1+CyhzLlIXAN0t4w0dWeLDWwo6p+S+W6Jc6YPTQHTkuTU
# aJOwSEeSspIyLoVuKMnqJBhveATWc+SQ17mBfn5l3exu3xQLT+1ns/YbZP4XFMXo
# AHHFUwHJl0pZdWd38mfE4W0jQjl8YUDndR1bId1mTMG/6o1Sk1JposyX0DUjXyAR
# j0/rXuoyG+3ddv7wrrO2zhbt8c6JbDJebTktVjkOfdfvT6O8YqhlLmid3y0rmH7T
# G4bfezpdCGUV88oMx50qI8UOSApOVpmvAsbbeqGCDUUwgg1BBgorBgEEAYI3AwMB
# MYINMTCCDS0GCSqGSIb3DQEHAqCCDR4wgg0aAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCBbO04ERazoGz8hehxYpoUcAXarmMItcL8JQjyjENlYhgIRALYZwfEVBBqS
# /H7dXE6t4bsYDzIwMjEwNTEyMTUwMjA1WqCCCjcwggT+MIID5qADAgECAhANQkrg
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
# 9aaOUjGCAk0wggJJAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0ECEA1CSuC+Ooj/
# YEAhzhQA8N0wDQYJYIZIAWUDBAIBBQCggZgwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMTA1MTIxNTAyMDVaMCsGCyqGSIb3DQEJ
# EAIMMRwwGjAYMBYEFOHXgqjhkb7va8oWkbWqtJSmJJvzMC8GCSqGSIb3DQEJBDEi
# BCB2dS9Ifm/NlAMV6ftxDT8zZFOab1nxBiAv84mjatixVjANBgkqhkiG9w0BAQEF
# AASCAQBYtKT6LFd/ULzP5zgLPLD0De2WFKHxdRx+ZsquN6PYIFmeknv1X/gRzmOQ
# vohpJMy6cZwLnIcMcfvGLZB4oCMsdOCkJCZv7ZxpIEAPSXTuMNYXILPN+5Pi44t3
# 5DC9egUCzhdeU684KhVEpuDAggRyZy6rdMPqQq1DNx6fEHhosHeMaK3LldgqzTdJ
# kfMUYFCza6HAkLqs4UbYL7HZgBE54Gzt/GwmnJx2wXTRsVC863C2bu6d/iGAaN99
# bq0DZtsJF2Foyed8Ws4ojmwc8CjRE0NXM2WRSLCZrAKn+EB1pyiY3+za5g5g3Exc
# pOWT5cdb7vxVEjxuYlOU9A2SFeTR
# SIG # End signature block
