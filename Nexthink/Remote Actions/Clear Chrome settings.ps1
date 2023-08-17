<#
.SYNOPSIS
Clears Chrome settings.

.DESCRIPTION
Clears Chrome files according to the specified parameters. Useful for troubleshooting several browsing-related issues. The script is developed for Windows 10 and 7 and Chrome 65 onwards.

.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   ClearChromeSettingsCampaignId   UID of the campaign to notify the user that Chrome must be closed
2   BrowsingHistory                 List of visited websites. Set it to "true" for deletion, "false" otherwise
3   Cache                           Cached images and sites. Set it to "true" for deletion, "false" otherwise
4   Cookies                         Cookies saved on the device by websites. Set it to "true" for deletion, "false" otherwise

.OUTPUTS
ID  Label                           Type            Description
1   CleanedSettings                 StringList      List of cleaned settings

.FURTHER INFORMATION
Bookmarks and passwords are not included in the available settings, as they are synchronized when logged-in in Chrome.

.NOTES
Context:            InteractiveUser
Version:            1.1.0.0 - Chrome is restarted after clearing settings. Some minor improvements
                    1.0.0.0 - Initial release
Last Generated:     14 Jan 2019 - 18:50:32
Copyright (C) 2019 Nexthink SA, Switzerland
#>

param(
    [Parameter(Mandatory = $true)][string]$ClearChromeSettingsCampaignId,
    [Parameter(Mandatory = $true)][string]$BrowsingHistory,
    [Parameter(Mandatory = $true)][string]$Cache,
    [Parameter(Mandatory = $true)][string]$Cookies
)
# End of parameters definition

New-Variable -Name 'HKLM_CHROME_REG_PATH' -Value 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -Option Constant -Scope Script
New-Variable -Name 'CHROME_DIR_PATH' -Value "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" -Option Constant -Scope Script
New-Variable -Name 'CHROME_PROCESS_NAME' -Value 'Chrome' -Scope script -Option Constant
New-Variable -Name 'FIRST_CHROME_VERSION_SUPPORTED' -Value 65 -Scope script -Option Constant

function Test-RunningAsInteractiveUser {
    $currentIdentity = Get-CurrentIdentity
    if ($currentIdentity -eq 'S-1-5-18') { throw 'This script must be run as InteractiveUser. ' }
}

function Get-CurrentIdentity {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.ToString()
}

function Add-NexthinkDLLs {
    $remoteActionPath = "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"
    $campaignPath = "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll"
    if (-not (Test-Path -Path $remoteActionPath)) { throw 'Nexthink DLL nxtremoteactions.dll not found. ' }
    if (-not (Test-Path -Path $campaignPath)) { throw 'Nexthink DLL nxtcampaignaction.dll not found. ' }

    Add-Type -Path $remoteActionPath
    Add-Type -Path $campaignPath
}

function Test-SupportedOSVersion {
    $OSVersion = (Get-OSVersion) -as [version]
    if (-not ($OSVersion)) { throw 'This script could not return OS version. ' }
    if (($OSVersion.Major -ne 10) -and ($OSVersion.Major -ne 6 -or $OSVersion.Minor -ne 1)) {
        throw 'This script is compatible with Windows 10 and Windows 7 only. '
    }
}

function Get-OSVersion {
    return Get-WmiObject -Class Win32_OperatingSystem -Filter 'ProductType = 1' -ErrorAction SilentlyContinue `
        | Select-Object -ExpandProperty Version -ErrorAction SilentlyContinue
}

function Test-Chrome {
    Test-SupportedChromeVersion
    Test-ChromeFolder
}

function Test-SupportedChromeVersion {
    $chromeDefaultRegKey = '(Default)'
    $hklmChromeRegPath = 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe'

    if (-not (Test-RegistryKey -Path $hklmChromeRegPath -Key $chromeDefaultRegKey)) {
        throw "Registry key for $CHROME_PROCESS_NAME executable not found"
    }

    $chromeVersion = $(Get-Item -Path $(Get-RegistryKey -Path $hklmChromeRegPath -Key $chromeDefaultRegKey) -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
    if (-not $chromeVersion) {
        throw "$CHROME_PROCESS_NAME version not found"
    }

    if ([int]($chromeVersion.Split('.')[0]) -lt $FIRST_CHROME_VERSION_SUPPORTED) {
        throw "This script is compatible with $CHROME_PROCESS_NAME $FIRST_CHROME_VERSION_SUPPORTED onwards only"
    }
}

function Test-ChromeFolder {
    if (-not (Test-Path -Path $CHROME_DIR_PATH)) {
        throw "$CHROME_PROCESS_NAME folder not found"
    }
}

function Test-RegistryKey ([string]$Path, [string]$Key) {
    return $null -ne (Get-ItemProperty -Path $Path -Name $Key -ErrorAction SilentlyContinue)
}

function Get-RegistryKey ([string]$Path, [string]$Key) {
    return (Get-ItemProperty -Path $Path -Name $Key).$Key
}

function Test-InputParameters ([hashtable]$Parameters) {
    Test-CampaignParameter
    Test-SettingsParameters -SettingsParameters $Parameters
}

function Test-CampaignParameter {
    if (-not ($ClearChromeSettingsCampaignId -as [guid])) { throw "Error on parameter 'ClearChromeSettingsCampaignId'. Only UID values are accepted. " }
}

function Test-SettingsParameters ([hashtable]$SettingsParameters) {
    $validValues = @('true', 'false')
    foreach ($param in $SettingsParameters.keys) {
        if ($validValues -NotContains $SettingsParameters[$param].ToLower()) {
            throw "Error on input parameter '$param'. Accepted values are `"true`" or `"false`""
        }
    }
}

function Get-CampaignResponse {
    return [Nxt.CampaignAction]::RunCampaign($ClearChromeSettingsCampaignId)
}

function Get-CampaignResponseStatus($Response) {
    return [Nxt.CampaignAction]::GetResponseStatus($Response)
}

function Get-CampaignResponseAnswer($Response) {
    return [Nxt.CampaignAction]::GetResponseAnswer($Response, 'CloseChrome')[0]
}

function Invoke-CampaignToCloseChrome {
    $response = Get-CampaignResponse
    $status = Get-CampaignResponseStatus -Response $response

    switch ($status) {
        'fully' {
            if ($(Get-CampaignResponseAnswer -Response $response) -eq 'CloseNow') {
                if (Stop-GivenProcess -ProcessName $CHROME_PROCESS_NAME) {
                    return
                }
                throw "$CHROME_PROCESS_NAME was not closed correctly and it could not be cleared"
            }
            throw "The user declined to close $CHROME_PROCESS_NAME and it could not be cleared"
        }
        'timeout' { throw "Timeout on getting an answer from the user. $CHROME_PROCESS_NAME could not be cleared" }
        'postponed' { throw "The user postponed the campaign. $CHROME_PROCESS_NAME could not be cleared" }
        'declined' { throw "The user declined the campaign. $CHROME_PROCESS_NAME could not be cleared" }
        default { throw "Failed to handle campaign response: $response" }
    }
}

function Stop-GivenProcess ([string]$ProcessName) {
    Stop-Process -Name $ProcessName -ErrorAction SilentlyContinue

    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Milliseconds 200
        if (-not $(Test-GivenProcess -ProcessName $ProcessName)) { return $true }
    }

    return $false
}

function Test-GivenProcess ([string]$ProcessName) {
    return $null -ne (Get-GivenProcess -ProcessName $ProcessName)
}

function Get-GivenProcess ([string]$ProcessName) {
    return (Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
}

function Start-GivenProcess([string]$ProcessName) {
    Start-Process $ProcessName
}

function Set-SettingsForDeletion ([hashtable]$Parameters) {
    [String[]]$message = @()
    $settings = @()

    $trueParams = @($Parameters.GetEnumerator() | Where-Object {$_.value.ToLower() -eq 'true'} | Select-Object -ExpandProperty Key | Sort-Object)
    switch ($trueParams) {
        BrowsingHistory { $settings += @('History', 'History-journal'); $message += 'Browsing History cleaned' }
        Cache { $settings += @('Cache', 'Media Cache'); $message += 'Cache cleaned' }
        Cookies { $settings += @('Cookies', 'Cookies-journal'); $message += 'Cookies cleaned' }
    }

    if (-not $message) {
        $message += 'No settings selected for cleaning'
    }
    return @{settings = $settings; message = $message}
}

function Clear-Settings ([string[]]$Settings) {
    foreach ($setting in $Settings) {
        Get-ChildItem $CHROME_DIR_PATH -ErrorAction SilentlyContinue `
            | Where-Object { $_ -like $setting } `
            | ForEach-Object { Remove-Item "$CHROME_DIR_PATH\$_" -Recurse -Confirm:$false -ErrorAction SilentlyContinue }
    }
}

# Main script flow
$ExitCode = 0
[String[]]$CleanedSettings = @()
[bool]$ChromeWasOpenedBeforeExecution = $false
try {
    Add-NexthinkDLLs
    Test-RunningAsInteractiveUser
    Test-SupportedOSVersion
    Test-Chrome

    $ParametersList = $MyInvocation.BoundParameters
    $ParametersList.Remove('ClearChromeSettingsCampaignId') | Out-Null
    Test-InputParameters -Parameters $ParametersList

    if (Test-GivenProcess -ProcessName $CHROME_PROCESS_NAME) {
        $ChromeWasOpenedBeforeExecution = $true
        Invoke-CampaignToCloseChrome
    }

    $settingsForDeletion = Set-SettingsForDeletion -Parameters $ParametersList
    Clear-Settings -Settings $settingsForDeletion.settings
    $CleanedSettings = $settingsForDeletion.message

    if ($ChromeWasOpenedBeforeExecution) {
        Start-GivenProcess -ProcessName $CHROME_PROCESS_NAME
    }
} catch {
    $host.ui.WriteErrorLine($_.ToString())
    $ExitCode = 1
} finally {
    [Nxt]::WriteOutputStringList('CleanedSettings', $CleanedSettings)
    [Environment]::Exit($ExitCode)
}

# SIG # Begin signature block
# MIIj5AYJKoZIhvcNAQcCoIIj1TCCI9ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCpwfWtCpwK732y
# m8YrEdIukiutmA4n2cr+AIjN3X8ySqCCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAKdoN+wO2Y
# TBeVhUiS0LGeKhyQKa3AI2OFx6xYg41qezANBgkqhkiG9w0BAQEFAASCAgAyNAAt
# s5LaMZfgk9sP3Ae8EDOk/jiBYvlYlijM8YIOMkBQQozdoEuJmn4IPoKAuVTU5xOZ
# RnQzBz1bNV+2GJHn7zAIgWIs4Ee/Pps40c9DSq+s/zq3DCE9sTgk7SDDpDBZIHqE
# QfTU/GtEB8jCf6jojy9rnkbfcobb8eLMi+K83CUHKaJOcbfBWqR8aeVDawIAlQCK
# c8ygkbfd9/cEOXyVU3sYq7l7HpHrxXOovHUmVcAOvZqxxDfMX9xBEm8hSpox8sXh
# sFUvDFH770fXlllLCUDCg9R7k9M/P44TfhM2B3pk3BOiXn2HYCQ2WDaL6il1H+xO
# xSXsgsVJi9iWWDfyUCKf5FEclbzQEU/Su3G8TT/JXR+0FjW/vuxqgVkNc6TVnss7
# pg0PQUJLlG8JXUkI7YxEZ9xwZr3IDPhFEYwp2ni1GgV0i9uJFtevtowB1NY8qjJB
# W9tMgRRlHw5Usw3Yqj/EbDRM3xTled3tZQyPfBWKeNkauqCg028F5ePNWMY2xfF6
# MqHwfpvRsBn1dMWzeSZmKMCVLlpZSaOKSBLbG5SwTkN/hJw++evoh44KbZdejyw3
# aa3dP61DZJ7IhXwkaKgksHMeY27PapgUzEFuHiR/2ceypI+TUCJwd3CVPgAmHLDg
# u6qbFw2diiBSE6F+/XMy58DG/xVERFS0NizoNaGCDsgwgg7EBgorBgEEAYI3AwMB
# MYIOtDCCDrAGCSqGSIb3DQEHAqCCDqEwgg6dAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCAdme+aJ3nzq7tULi0Uh6xLywxCFeiTHEkOtadbJBUgDAIQfx9dB6TgePnK
# SEhR0ajKFRgPMjAyMDA4MTkxNjM3MjdaoIILuzCCBoIwggVqoAMCAQICEATNP4Vo
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
# SIb3DQEJEAEEMBwGCSqGSIb3DQEJBTEPFw0yMDA4MTkxNjM3MjdaMCsGCyqGSIb3
# DQEJEAIMMRwwGjAYMBYEFAMlvVBe2pYwLcIvT6AeTCi+KDTFMC8GCSqGSIb3DQEJ
# BDEiBCAvciCo8IDU149Deylpr1Qp3ZloWQwmK9ngAZbA6WnDIzANBgkqhkiG9w0B
# AQEFAASCAQCh4OI77/jr6X/xUNsR0Uv5RapfmWl5RLVzoqXk279QHY11jnB61b+U
# Z4PPsRNZB8IGW+FAFLk0j4aeGpVrec4s/8EtsqF0p+gdJRyiTaBTtYMVCmv5scFw
# AB4pHlvYaHelFH5E1N2TQP9Iq6xfbNN32X4d2O8twXevgpzzbrkkskJa3lbXdh6R
# 5Hb0z0fa0mk4tz53npDGHhE2Kncg1OIT3OCssAkJv96K6PpMK0u7CNqI2J+nFbcX
# 3Qo6YklsnpZCpRXvfhov/UATtqm6AF5bdb/R4TOi+G8vE2VpraVIPp4g387S5I1h
# fn1vZMKVEd+k8CQrcsBPjPKRTrwn+G3z
# SIG # End signature block
