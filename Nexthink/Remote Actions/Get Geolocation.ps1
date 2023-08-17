<#
.SYNOPSIS
Displays device location.

.DESCRIPTION
Retrieves the device geolocation (city, region, country) by public IP and the Internet Service Provider (ISP).

.FUNCTIONALITY
On-demand

.INPUTS
ID  Label                           Description
1   APIKey                          API key to be used for the external geolocation service
2   EnableHTTPS                     HTTPS enabled. Valid values are true/false
3   MaximumDelayInSeconds           Maximum random delay set to avoid external API overload. Provide number of seconds lower than 600

.OUTPUTS
ID  Label                           Type            Description
1   City                            String          City where the device is located
2   Region                          String          Region where the device is located
3   Country                         String          Country where the device is located
4   ISP                             String          Name of the Internet Service Provider (ISP) the device is connected to

.FURTHER INFORMATION
The script is designed to use IPAPI geolocation API [https://ipapi.com/ link]. This is a third-party API, hence its availability does not depend on Nexthink.

.RESTRICTIONS
- Service restrictions may apply depending on the user API account type (free, business, etc.). For further information please visit this [https://ipapi.com/product article]
- HTTPS may not be available for all the user plans (e.g. free plan)
- ISP information can only be retrieved with a paid plan. If a free APIKey is provided the ISP field will be set to '-'

.NOTES
Context:            InteractiveUser
Version:            4.0.0.0 - Added ISP information
                    3.0.0.0 - Location was split in different outputs. Related Scores, Metrics and Investigations need to be updated
                    2.0.0.0 - API change. Added API key and HTTPS enabling input parameters
                    1.0.0.0 - Initial release
Last Generated:     07 Aug 2020 - 13:10:23
Copyright (C) 2020 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$APIKey,
    [Parameter(Mandatory = $true)][string]$EnableHTTPS,
    [Parameter(Mandatory = $true)][string]$MaximumDelayInSeconds
)
# End of parameters definition

#
# Constants definition
#
New-Variable -Name 'DEFAULT_USER_AGENT' `
    -Value 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36 Edg/84.0.522.40' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'MAX_SCRIPT_DELAY_SEC' `
    -Value 600 -Option ReadOnly -Scope Script
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'TLS_12' `
    -Value 3072 `
    -Option ReadOnly -Scope Script

New-Variable -Name 'GEOLOCATION_API_BASE_URL' `
    -Value 'api.ipapi.com' -Option Constant -Scope Script
New-Variable -Name 'GEOLOCATION_API_SUFFIX' `
    -Value 'check' -Option Constant -Scope Script
New-Variable -Name 'GEOLOCATION_API_KEY_PARAM' `
    -Value 'access_key' -Option Constant -Scope Script

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    [hashtable]$locationInfo = Initialize-LocationInfo

    try {
        Add-WebExtensions
        Add-NexthinkRemoteActionDLL
        Test-RunningAsInteractiveUser
        Test-SupportedOSVersion

        Test-InputParameters -InputParameters $InputParameters

        Wait-RandomTime -MaximumDelayInSeconds $InputParameters.MaximumDelayInSeconds

        Update-LocationFromIP -InputParameters $InputParameters `
                              -LocationInfo $locationInfo
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -LocationInfo $locationInfo
    }

    return $exitCode
}

#
# Template functions
#
function Add-WebExtensions {
    try { Add-Type -AssemblyName system.web.extensions }
    catch { throw 'Web extensions not found. ' }
}

function Add-NexthinkRemoteActionDLL {
    if (-not (Test-Path -Path $REMOTE_ACTION_DLL_PATH)) {
        throw 'Nexthink Remote Action DLL not found. '
    }
    Add-Type -Path $REMOTE_ACTION_DLL_PATH
}

function Test-RunningAsInteractiveUser {
    if (Confirm-CurrentUserIsLocalSystem) {
        throw 'This script must be run as InteractiveUser. '
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

function Wait-RandomTime ([int]$MaximumDelayInSeconds) {
    if ($MaximumDelayInSeconds -gt 0) {
        $seconds = Get-Random -Minimum 0 -Maximum $MaximumDelayInSeconds
        Start-Sleep -Seconds $seconds
    }
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

function Test-HexadecimalParameter ([string]$ParamName, [string]$ParamValue) {
    if ($ParamValue -notmatch "^[0-9a-f]+$") {
        throw "Error on parameter '$ParamName'. It is not a valid hexadecimal. "
    }
}

function Test-BooleanParameter ([string]$ParamName, [string]$ParamValue) {
    $value = $ParamValue.ToLower()
    if ($value -ne 'true' -and $value -ne 'false') {
        throw "Error on parameter '$ParamName'. It must be 'true' or 'false'. "
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

function Get-WebContent ([string]$URL, [string]$ContentType) {
    $response, $responseStream, $streamReader = $null, $null, $null

    try {
        Set-SecurityProtocol

        $webRequest = New-WebRequest -URL $URL -ContentType $ContentType
        $response = Get-WebResponse -Request $webRequest
        $responseStream = $response.GetResponseStream()
        $streamReader = New-Object -TypeName 'io.streamreader' -ArgumentList $responseStream

        return $streamReader.ReadToEnd()
    } finally {
        if ($null -ne $streamReader) {
            $streamReader.Close()
            $streamReader.Dispose()
        }
        if ($null -ne $responseStream) {
            $responseStream.Close()
            $responseStream.Dispose()
        }
        if ($null -ne $response) { $response.Close() }
    }
}

function Set-SecurityProtocol {
    [net.servicepointmanager]::SecurityProtocol = [enum]::ToObject([net.securityprotocoltype], $TLS_12)
}

function New-WebRequest ([string]$URL, [string]$ContentType) {
    try {
        $webRequest = [net.webrequest]::Create($URL)
        $webRequest.Timeout = 20000
        $webRequest.Method = 'GET'
        $webRequest.ContentType = $ContentType
        $webRequest.Proxy.Credentials = [net.credentialcache]::DefaultNetworkCredentials
        $webRequest.UserAgent = $DEFAULT_USER_AGENT
    } catch {
        throw "Unable to create a new web request for '$URL'. "
    }

    return $webRequest
}

function Get-WebResponse ([psobject]$Request) {
    return $Request.GetResponse()
}

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-HexadecimalParameter `
        -ParamName 'APIKey' -ParamValue $InputParameters.APIKey
    Test-BooleanParameter `
        -ParamName 'EnableHTTPS' -ParamValue $InputParameters.EnableHTTPS
    Test-ParamInAllowedRange `
        -ParamName 'MaximumDelayInSeconds' `
        -ParamValue $InputParameters.MaximumDelayInSeconds `
        -LowerLimit 0 -UpperLimit $MAX_SCRIPT_DELAY_SEC
}

#
# Geolocation
#
function Initialize-LocationInfo {
    return @{City = '-'
             Region = '-'
             Country = '-'
             ISP = '-'}
}

function Update-LocationFromIP ([hashtable]$InputParameters, [hashtable]$LocationInfo) {
    $url = Get-APIRequestURL -InputParameters $InputParameters
    $response = Get-WebContent -URL $url -ContentType 'application/json'
    $jsonResponse = Convert-ResponseToJSON -Response $response
    Update-LocationInfo -JSONResponse $jsonResponse -LocationInfo $LocationInfo
}

function Get-APIRequestURL ([hashtable]$InputParameters) {
    $enableHTTPS = [bool]::Parse($InputParameters.EnableHTTPS)
    $url = 'http'
    if ($enableHTTPS) { $url += 's' }
    $url += "://$GEOLOCATION_API_BASE_URL/"
    $url += "$GEOLOCATION_API_SUFFIX"
    $url += "?$GEOLOCATION_API_KEY_PARAM=$($InputParameters.APIKey)"
    return $url
}

function Convert-ResponseToJSON ([string]$Response) {
    try {
        $serializer = New-Object web.script.serialization.javascriptserializer
        return $serializer.DeserializeObject($Response)
    } catch {
        throw "Impossible to load JSON content '$Response'. "
    }
}

function Update-LocationInfo ([psobject]$JSONResponse, [hashtable]$LocationInfo) {
    $LocationInfo.City = Format-OutputString -Output $JSONResponse.city
    $LocationInfo.Region = Format-OutputString -Output $JSONResponse.region_name
    $LocationInfo.Country = Format-OutputString -Output $JSONResponse.country_name
    $LocationInfo.ISP = Format-OutputString -Output $JSONResponse.connection.isp

    $emptyValues = $LocationInfo.Values | Where-Object { $_ -eq '-' }
    if ($emptyValues.Count -ge 3) {
        $errorMsg = 'Impossible to display location information. '
        $errorType = $JSONResponse.error.type
        if ($null -ne $errorType) { throw $errorMsg += "Error: $errorType. " }
        throw $errorMsg
    }
}

function Format-OutputString ([string]$Output) {
    if ([string]::IsNullOrEmpty($Output)) { return '-' }
    else { return $Output }
}

#
# Nexthink Engine update
#
function Update-EngineOutputVariables ([hashtable]$LocationInfo) {
    [nxt]::WriteOutputString('City', $LocationInfo.City)
    [nxt]::WriteOutputString('Region', $LocationInfo.Region)
    [nxt]::WriteOutputString('Country', $LocationInfo.Country)
    [nxt]::WriteOutputString('ISP', $LocationInfo.ISP)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

# SIG # Begin signature block
# MIIj5AYJKoZIhvcNAQcCoIIj1TCCI9ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBKyK1kAYlitjSU
# z0EW20SRtbqNaycdl6xqTP6Vd41f8KCCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBSVjsAc/Rv
# WiflfRRerExBqbYEbdGLqJsOV9n136GDozANBgkqhkiG9w0BAQEFAASCAgAwbaWq
# SC3xf5f9eh3gcZ2+93s8JCE06br5jY7R3MIkSI4BlOzQrb/CRaFqgdMFmIT08xuv
# Ll8xDAP9GBL3hkDboXMN5aXrw8YPmzzS62i18419rDQWR52RYwS0IBwYkEnrqp4p
# uyEwE4weiMX8Iquzhi5qtBIeCKzy6PKCA+HXNnfD/lAXamHSSF6wnGSY2UqXW2XJ
# CniWBl3t5IimNk5dRTAxFIyfN6nYc7VX0dMbdcl9eYN3NgvdL2muuevUA6VMuZAq
# PMFyttjyMqOqDXevgPoWVdU2HsyAtMgvICfB/ro43GI4H+1R6dGvV6GWGY9VRNuR
# q4f8aSNDKzJVyuIxDq7Z0h90BvDhVmoFlX9XHZuIW9S1yNucq1nE3q94ptAPk0V3
# YnVQlosoMgmaHH/V4qXUfvNQfDwd0bmlKu+Uzbhcme2TsJzYgwEumspue5HW8hVi
# zAe8ndh9LPwepCsGcPeaAYMw5pyP4lg0b8kSRQDdN5RcReAARDOqobpZ560IqorS
# RGdlwYpSpQb10sIPJFze2Xby1k19kITUTPsEyy0oWwxIGEpqwJi8GiDePjYg/79Y
# 3xipGzHJqg2D1IaVoR1RDR3z5fZPpE6F01O5VLqz96iZAtpAWqWpDPy+lIONkTwv
# 9j9IZcFqW6QRiIp4jQmU5UZnpE+mv21yuSqs1qGCDsgwgg7EBgorBgEEAYI3AwMB
# MYIOtDCCDrAGCSqGSIb3DQEHAqCCDqEwgg6dAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCDCsnUtn1ZbXsB4poJ7erf2jctgQ8ykybRls2d5NKH86wIQTfRx7Vy8c4+r
# 6UYlmtLbMRgPMjAyMDA4MTkxNjM3MzBaoIILuzCCBoIwggVqoAMCAQICEATNP4Vo
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
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMDA4MTkxNjM3MzBaMCsGCyqGSIb3
# DQEJEAIMMRwwGjAYMBYEFAMlvVBe2pYwLcIvT6AeTCi+KDTFMC8GCSqGSIb3DQEJ
# BDEiBCBm+U5BVLWsy4cJDMjkti1fciR9VU60Vu5weZvjIFuMqzANBgkqhkiG9w0B
# AQEFAASCAQCuF45tBJbez1Hv3gW1fZqjyrolJZ753hpFr7uhbrLMEff+5EjlWi8p
# EBbGPiu5T5FKO3u03/eNv1T+uHJuAnBFToMnYaZoE54y+yyRJN+xEDqAHchn9zz+
# VwdI9vObHFM6j/c67rT+pu+YrnYsE+fbH/QdcVt6DuS/TbtHTMFx11NWGWyAEbOO
# hYG5ly2YsJo7ZY/n4gyoA6DwneSazXIvLbql51ex54NZ4O/yMbqBuqAC7jZrqQxN
# APSkFaIxvVV8XgbV1SzRC775DTJowFu1JC0dUcWPAKLmUE6VA2c0I5prOpbEUagh
# u1goob1kSoKI8kuvwJGVwwJF5RKhcixe
# SIG # End signature block
