<#
.SYNOPSIS
Sets the device power plan.

.DESCRIPTION
Sets the device power plan (Balanced, High performance or Power saver) on Windows Configuration. By default the user will be asked before changing their current power plan.

.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   CampaignId                      GUID of the campaign that ask the user if they want to change their plan. Use an empty GUID (00000000-0000-0000-0000-000000000000) to avoid asking the user and force the change
2   PowerPlanToSet                  Power plan to set. Valid values are Balanced, High performance and Power saver

.RESTRICTIONS
- The plan to set has to be an standard Windows power plan. Custom plans are not allowed.

.NOTES
Context:            LocalSystem
Version:            1.0.1.0 - Execution frequency and suggested scheduling updated on documentation
                    1.0.0.0 - Initial release
Last Generated:     27 Oct 2021 - 15:26:12
Copyright (C) 2021 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$CampaignId,
    [Parameter(Mandatory = $true)][string]$PowerPlanToSet
)
# End of parameters definition

#
# Constants definition
#
New-Variable -Name 'CAMPAIGN_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'CAMPAIGN_TIMEOUT' `
    -Value 60 `
    -Option ReadOnly -Scope Script
New-Variable -Name 'ERROR_EXCEPTION_TYPE' `
    -Value @{Environment = '[Environment error]'
             Input = '[Input error]'
             Internal = '[Internal error]'} `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script

New-Variable -Name 'POWERCFG_EXE' `
    -Value "$env:SystemRoot\System32\powercfg.exe" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'POWER_PLAN_GUID_REGEX' `
    -Value '[a-fA-F-0-9]{8}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{4}-[a-fA-F-0-9]{12}' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'DEFAULT_POWER_PLANS' `
-Value @{'Balanced' = '381b4222-f694-41f0-9685-ff5bb260df2e'
         'High performance' = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
         'Power saver' = 'a1841308-3541-4fab-bc81-f71556f20b4a'} `
-Option ReadOnly -Scope Script -Force

New-Variable -Name 'DEFAULT_POWER_PLANS_ID' `
    -Value @{'381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'
             '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'
             'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'} `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0

    try {
        Add-NexthinkCampaignDLL
        Test-RunningAsLocalSystem
        Test-SupportedOSVersion
        Test-InputParameters -InputParameters $InputParameters

        Invoke-PowerPlanEnforcement -InputParameters $InputParameters
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    }

    return $exitCode
}

#
# Template functions
#
function Add-NexthinkCampaignDLL {

    if (-not (Test-Path -Path $CAMPAIGN_DLL_PATH)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink Campaign DLL not found. "
    }
    Add-Type -Path $CAMPAIGN_DLL_PATH
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

function Test-GUIDParameter ([string]$ParamName, [string]$ParamValue) {
    if (-not ($ParamValue -as [guid])) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. Only UID values are accepted. "
    }
}

function Test-StringSet ([string]$ParamName, $ParamValue, [string[]]$ValidValues) {
    if ([string]::IsNullOrEmpty($ParamValue) -or -not ($ParamValue -is [string])) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It is not a string. "
    }

    foreach ($value in $ValidValues) {
        if ($ParamValue -eq $value) { return }
    }

    $expectedValues = $ValidValues -join ', '
    throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. Accepted values are $expectedValues. "
}

function Test-EmptyGUID ([string]$Guid) {
    return $Guid -eq [guid]::Empty.Guid
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

function Get-CampaignResponse ([string]$CampaignId) {
    return [nxt.campaignaction]::RunCampaign($CampaignId, $CAMPAIGN_TIMEOUT)
}

function Get-CampaignResponseStatus ($Response) {
    return [nxt.campaignaction]::GetResponseStatus($Response)
}

function Get-CampaignResponseAnswer ($Response, [string]$QuestionName) {
    return [nxt.campaignaction]::GetResponseAnswer($Response, $QuestionName)[0]
}

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-GUIDParameter `
        -ParamName 'CampaignId' `
        -ParamValue $InputParameters.CampaignId
    Test-StringSet `
        -ParamName 'PowerPlanToSet' `
        -ParamValue $InputParameters.PowerPlanToSet `
        -ValidValues $DEFAULT_POWER_PLANS.Keys
}

#
# Set power plan
#
function Invoke-PowerPlanEnforcement ([hashtable]$InputParameters) {
    $currentTestPlan = Get-CurrentPowerPlan

    if ($currentTestPlan -eq $InputParameters.PowerPlanToSet) {
        Write-StatusMessage -Message 'The user already has the recommended power plan. '
        return
    }

    if ((Test-EmptyGUID -Guid $InputParameters.CampaignId) -or `
        (Invoke-Campaign -CampaignId $InputParameters.CampaignId)) {
        Set-PowerPlan -Name $InputParameters.PowerPlanToSet
    } else { Write-StatusMessage -Message 'The user declined to change their current power plan. ' }
}

function Get-CurrentPowerPlan {
    [hashtable]$output = Invoke-Process -FilePath $POWERCFG_EXE `
                                        -Arguments '/GETACTIVESCHEME'
    if ($output.StdOut -match $POWER_PLAN_GUID_REGEX) {
        if ($DEFAULT_POWER_PLANS_ID.ContainsKey($Matches[0])) { return $DEFAULT_POWER_PLANS_ID.($Matches[0]) }
    }
    return 'Other'
}

function Set-PowerPlan ([string]$Name) {
    $output = Invoke-Process -FilePath $POWERCFG_EXE `
                             -Arguments "/SETACTIVE $($DEFAULT_POWER_PLANS.$Name)"
    if ($output.ExitCode -ne 0) { throw 'The power plan could not be set on the device. ' }
    Write-StatusMessage -Message 'The power plan was set correctly. '
}

#
# Campaign management
#
function Invoke-Campaign ([string]$CampaignId) {
    $response = Get-CampaignResponse -CampaignId $CampaignId
    $status = Get-CampaignResponseStatus -Response $response

    switch ($status) {
        'fully' {
            return (Get-CampaignResponseAnswer -Response $response -QuestionName 'PowerPlan') -eq 'Yes'
        }
        'timeout' { throw 'Timeout on getting an answer from the user. ' }
        'postponed' { throw 'The user postponed the campaign. ' }
        'declined' { throw 'The user declined the campaign. ' }
        'connectionfailed' { throw 'Unable to connect to the Collector component that controls campaign notifications. ' }
        'notificationfailed' { throw 'Unable to notify the Collector component that controls campaign notifications. ' }
        default { throw "Failed to handle campaign response: $response. " }
    }
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))
# SIG # Begin signature block
# MIIimQYJKoZIhvcNAQcCoIIiijCCIoYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDoWdcVRV6Wb+lS
# tGcuRlizuxgj19b8YRepbKgyyfmALaCCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIQtDCCELACAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCxdf4BqI4O
# ocrqvINtx0S+byJf6DqvgZfAYCpLyAJ68TANBgkqhkiG9w0BAQEFAASCAgB/avTr
# 66EVOofHzPaB+ZjvwfAB3QBfTf0BtOxK45GYYs96wpl3i06+ebz2pYP+g4nWN8UB
# 5Sdhe1GczQdFVWXQ4jjkHEYB/0jCakXs5QP/A2jCtoIZeq3PTyrl5XxMU7r+ho4I
# CRxF+jQFlK4719BXLJ5G0c2Uq3MXrfZGzmu5saUJSVAyuqeLgeVR5tHD9sgzb1ZF
# BD8l/pl9Td8WJToMX12YVP31EqOi6HgByW9rij2sHLaqHiZR9OPREWT8HtRrpT8f
# WElHmaj5MrrkjbJ2lxxQuTgp8LEEhL9WJqoSeFQX5d0lIA/JkSPdkx4IRpfgW0e2
# Xmk7/aqfdkytEwyqmOfd8X32hYfTPElGVvn4A7WtsgHbafzsYhJD1vw0s6KtWlsK
# 9oeckqm5KaujgDjWP+Wkh5yGinFdHzkjRW4P5C9a3tKCF6XMDHhT9RiKr4juZ49d
# 8DEKfuvFKVLNw8ICk2FnQ6+qDnDfDdHDJqsZhmFhCHI6tNpM5jqgm3kMDSk0vnK2
# ls89E4vATC5NhsGOogsOTxwdyIn7jgzuyQIC8uc/QlvRPFlnsD+U4P3odOfbHc8C
# ZnNqs4Qa40GFrjj38zOX93zDQZCgcXwz5XTgJD6YYbMCutsNw7G2HvPXJG1B+5MH
# BvZkERm2SFK367tw7K58UmXulOf2m3BNHXVNx6GCDX0wgg15BgorBgEEAYI3AwMB
# MYINaTCCDWUGCSqGSIb3DQEHAqCCDVYwgg1SAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCA8r05JLKp3xLlst+Su5rHZAhy5SMYoswnn2kOneCLLzgIQOe3qM/6XyfHr
# sCMsuRs5UhgPMjAyMTEwMjcxMzI2MjRaoIIKNzCCBP4wggPmoAMCAQICEA1CSuC+
# Ooj/YEAhzhQA8N0wDQYJKoZIhvcNAQELBQAwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQTAe
# Fw0yMTAxMDEwMDAwMDBaFw0zMTAxMDYwMDAwMDBaMEgxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjEgMB4GA1UEAxMXRGlnaUNlcnQgVGltZXN0
# YW1wIDIwMjEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDC5mGEZ8WK
# 9Q0IpEXKY2tR1zoRQr0KdXVNlLQMULUmEP4dyG+RawyW5xpcSO9E5b+bYc0VkWJa
# uP9nC5xj/TZqgfop+N0rcIXeAhjzeG28ffnHbQk9vmp2h+mKvfiEXR52yeTGdnY6
# U9HR01o2j8aj4S8bOrdh1nPsTm0zinxdRS1LsVDmQTo3VobckyON91Al6GTm3dOP
# L1e1hyDrDo4s1SPa9E14RuMDgzEpSlwMMYpKjIjF9zBa+RSvFV9sQ0kJ/SYjU/aN
# Y+gaq1uxHTDCm2mCtNv8VlS8H6GHq756WwogL0sJyZWnjbL61mOLTqVyHO6fegFz
# +BnW/g1JhL0BAgMBAAGjggG4MIIBtDAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/
# BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDBBBgNVHSAEOjA4MDYGCWCGSAGG
# /WwHATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMw
# HwYDVR0jBBgwFoAU9LbhIB3+Ka7S5GGlsqIlssgXNW4wHQYDVR0OBBYEFDZEho6k
# urBmvrwoLR1ENt3janq8MHEGA1UdHwRqMGgwMqAwoC6GLGh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9zaGEyLWFzc3VyZWQtdHMuY3JsMDKgMKAuhixodHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLXRzLmNybDCBhQYIKwYBBQUHAQEE
# eTB3MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTwYIKwYB
# BQUHMAKGQ2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJB
# c3N1cmVkSURUaW1lc3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQELBQADggEBAEgc
# 3LXpmiO85xrnIA6OZ0b9QnJRdAojR6OrktIlxHBZvhSg5SeBpU0UFRkHefDRBMOG
# 2Tu9/kQCZk3taaQP9rhwz2Lo9VFKeHk2eie38+dSn5On7UOee+e03UEiifuHokYD
# Tvz0/rdkd2NfI1Jpg4L6GlPtkMyNoRdzDfTzZTlwS/Oc1np72gy8PTLQG8v1Yfx1
# CAB2vIEO+MDhXM/EEXLnG2RJ2CKadRVC9S0yOIHa9GCiurRS+1zgYSQlT7LfySmo
# c0NR2r1j1h9bm/cuG08THfdKDXF+l7f0P4TrweOjSaH6zqe/Vs+6WXZhiV9+p7SO
# Z3j5NpjhyyjaW4emii8wggUxMIIEGaADAgECAhAKoSXW1jIbfkHkBdo2l8IVMA0G
# CSqGSIb3DQEBCwUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0
# IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0xNjAxMDcxMjAwMDBaFw0zMTAxMDcxMjAw
# MDBaMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNz
# dXJlZCBJRCBUaW1lc3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC90DLuS82Pf92puoKZxTlUKFe2I0rEDgdFM1EQfdD5fU1ofue2oPSN
# s4jkl79jIZCYvxO8V9PD4X4I1moUADj3Lh477sym9jJZ/l9lP+Cb6+NGRwYaVX4L
# J37AovWg4N4iPw7/fpX786O6Ij4YrBHk8JkDbTuFfAnT7l3ImgtU46gJcWvgzyIQ
# D3XPcXJOCq3fQDpct1HhoXkUxk0kIzBdvOw8YGqsLwfM/fDqR9mIUF79Zm5WYScp
# iYRR5oLnRlD9lCosp+R1PrqYD4R/nzEU1q3V8mTLex4F0IQZchfxFwbvPc3WTe8G
# Qv2iUypPhR3EHTyvz9qsEPXdrKzpVv+TAgMBAAGjggHOMIIByjAdBgNVHQ4EFgQU
# 9LbhIB3+Ka7S5GGlsqIlssgXNW4wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6ch
# nfNtyA8wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwgweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwgYEGA1Ud
# HwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwUAYDVR0gBEkwRzA4BgpghkgB
# hv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9D
# UFMwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IBAQBxlRLpUYdWac3v3dp8
# qmN6s3jPBjdAhO9LhL/KzwMC/cWnww4gQiyvd/MrHwwhWiq3BTQdaq6Z+CeiZr8J
# qmDfdqQ6kw/4stHYfBli6F6CJR7Euhx7LCHi1lssFDVDBGiy23UC4HLHmNY8ZOUf
# SBAYX4k4YU1iRiSHY4yRUiyvKYnleB/WCxSlgNcSR3CzddWThZN+tpJn+1Nhiaj1
# a5bA9FhpDXzIAbG5KHW3mWOFIoxhynmUfln8jA/jb7UBJrZspe6HUSHkWGCbugwt
# K22ixH67xCUrRwIIfEmuE7bhfEJCKMYYVs9BNLZmXbZ0e/VWMyIvIjayS6JKldj1
# po5SMYIChjCCAoICAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UEAxMoRGln
# aUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQDUJK4L46iP9g
# QCHOFADw3TANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIxMTAyNzEzMjYyNFowKwYLKoZIhvcNAQkQ
# AgwxHDAaMBgwFgQU4deCqOGRvu9ryhaRtaq0lKYkm/MwLwYJKoZIhvcNAQkEMSIE
# IGBSjlFJaRgOY2a5TehvTXxcIUr2TlglxM4DathyPXgqMDcGCyqGSIb3DQEJEAIv
# MSgwJjAkMCIEILMQkAa8CtmDB5FXKeBEA0Fcg+MpK2FPJpZMjTVx7PWpMA0GCSqG
# SIb3DQEBAQUABIIBABELjfGsahal+v/35nRdt8FB7frSsfPUKur/IiPvJJcoxDXL
# PTDRagHgnvhj4kvYC+s+3OhxXnFohBIEz6uEE+nsMDGIp3yRzxZ9aTwJcSces9TX
# U9m2qgAempqYfqSr0Yd5q+ZG+Qir7+42uIYspjuSW+2k9cFR8fPEmK6M+txfMTzn
# UAF130gBXvgn/mlXOG6VcuYjrreLvbem0A2qXCXIFQtYqyAUQZtnF27MYcWqjI1c
# JkiFeqgNS9xL2z+iPzh3ffmq5bqsa149tZpdtHbEQZSfRZZsAtjdNljAdx+T4GFN
# 8MEDKtK0i2uBaj1/qBBKuyWHtBf3kgM70cy9oOQ=
# SIG # End signature block
