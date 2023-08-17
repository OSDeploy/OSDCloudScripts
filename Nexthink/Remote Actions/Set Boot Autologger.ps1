<#
.SYNOPSIS
Enables or disables an Autologger configuration.

.DESCRIPTION
Enables or disables an Autologger configuration on both Windows 10 and Windows 7. In addition to this, an ETW Trace Session will be enabled on Windows 10 along with the Autologger configuration.

.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   Status                          The action which the Remote Action will perform. The accepted values are 'enable' and 'disable'
2   CampaignId                      The id of the Campaign which will be executed as the final step. Use an empty GUID (00000000-0000-0000-0000-000000000000) or empty value "" to avoid the Campaign

.FURTHER INFORMATION
It is necessary to restart the device after executing this Remote Action so that the Autologger can log boot details. In Windows 7, only after a reboot will the Autologger .etl file be removed.

.NOTES
Context:            LocalSystem
Version:            1.0.0.0 - Initial release
Last Generated:     16 Jun 2020 - 14:39:33
Copyright (C) 2020 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
   [Parameter(Mandatory=$true)][string]$Status,
   [Parameter(Mandatory=$true)][string]$CampaignId
)

# End of parameters definition

#
# Constants definition
#
New-Variable -Name 'CAMPAIGN_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script

New-Variable -Name 'INPUT_VALID_VALUES' `
    -Value ([string[]]@('enable', 'disable')) `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_BOOT_AUTOLOGGER_NAME' `
    -Value 'Nexthink-Boot-Autologger' `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_BOOT_AUTOLOGGER_GUID' `
    -Value ([guid]::NewGuid().ToString('B')) `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_ETW_SESSION_NAME' `
    -Value 'Nexthink-Etw-Session' `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_LOGGER_SESSIONS_PATH' `
    -Value "$env:SystemDrive\ProgramData\Nexthink\BootDetails\" `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_AUTOLOGGER_FILENAME' `
    -Value 'nxtdiag.etl' `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_ETW_SESSION_FILENAME' `
    -Value 'nxtdiagBR.etl' `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH' `
    -Value "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$NEXTHINK_BOOT_AUTOLOGGER_NAME" `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'MAXIMUM_LOG_FILE_SIZE' `
    -Value 256 `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'MAXIMUM_LOG_BUFFER_SIZE' `
    -Value 256 `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'FLUSH_TIMER_VALUE' `
    -Value 1 `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'LOG_FILE_MODE_WIN10' `
    -Value 0x08000002 `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'CLOCKTYPE_WIN10' `
    -Value 'Performance' `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'LOG_FILE_MODE_WIN7' `
    -Value 0x00000002 `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'CLOCKTYPE_WIN7' `
    -Value 1 `
    -Option ReadOnly -Force -Scope Script

#
# Global variables definition
#
New-Variable -Name 'NEXTHINK_BOOT_AUTOLOGGER_CREATED' -Value $false -Scope Script -Option AllScope
New-Variable -Name 'NEXTHINK_ETW_SESSION_CREATED' -Value $false -Scope Script -Option AllScope

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    $enable = $false
    $isWin10 = $false
    [hashtable[]]$autologgerProperties = Initialize-AutologgerProperties
    [hashtable[]]$providersInfo = Initialize-ProvidersInfo

    try {
        Add-NexthinkCampaignDLL

        Test-RunningAsLocalSystem
        Test-SupportedOSVersion

        Test-InputParameters -InputParameters $InputParameters

        $enable = Test-MustEnable -Status $InputParameters.Status
        $isWin10 = Test-IsWindows10

        Update-BootAutoLogger -AutologgerProperties $autologgerProperties `
                              -ProvidersInfo $providersInfo `
                              -Enable $enable -IsWin10 $isWin10 `
                              -CampaignId $InputParameters.CampaignId

    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1

        if ($enable) {
            try {
                Invoke-Cleanup -IsWin10 $isWin10
            } catch {
                Write-StatusMessage -Message "There was a problem while cleaning up Boot Autologger entities and files due to a previous error. `
Please make sure the .etl files and Autologger entities are removed from your system. Error: $_. "
            }
        }
    }

    return $exitCode
}

#
# Template functions
#
function Add-NexthinkCampaignDLL {
    if (-not (Test-Path -Path $CAMPAIGN_DLL_PATH)) {
        throw 'Nexthink Campaign DLL not found. '
    }
    Add-Type -Path $CAMPAIGN_DLL_PATH
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

function Test-StringSet ([string]$ParamName, $ParamValue, [string[]]$ValidValues) {
    if ([string]::IsNullOrEmpty($ParamValue) -or -not ($ParamValue -is [string])) {
        throw "Error on parameter '$ParamName'. It is not a string. "
    }

    foreach ($value in $ValidValues) {
        if ($ParamValue -eq $value) { return }
    }

    $expectedValues = $ValidValues -join ', '
    throw "Error on parameter '$ParamName'. Accepted values are $expectedValues. "
}

function Test-EmptyOrGUIDParameter ([string]$ParamName, [string]$ParamValue) {
    if (-not [string]::IsNullOrEmpty((Format-StringValue -Value $ParamValue)) -and `
        -not ($ParamValue -as [guid])) {
        throw "Error on parameter '$ParamName'. Only UID values are accepted. "
    }
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Initialize-Folder ([string]$Path) {
    try {
        if (-not (Test-Path -Path $Path)) {
            [void](New-Item -Path $Path -ItemType 'Directory' -Force -ErrorAction Stop)
        }
    } catch {
        throw "Error creating folder at $Path. "
    }
}

function Test-TriggerCampaign ([string]$Guid) {
    return -not [string]::IsNullOrEmpty((Format-StringValue -Value $Guid)) -and `
           -not (Test-EmptyGUID -Guid $Guid)
}

function Test-EmptyGUID ([string]$Guid) {
    return $Guid -eq [guid]::Empty.Guid
}

function Invoke-OperationCompletedCampaign ([string]$CampaignId) {
    [nxt.campaignaction]::RunStandAloneCampaign($CampaignId)
}

function Remove-File ([string]$Path) {
    if ([string]::IsNullOrEmpty($Path) -or `
        (-not (Test-Path -Path $Path))) { return }

    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Get-RegistryKeyProperty ([string]$Key, [string]$Property) {
    if ([string]::IsNullOrEmpty($Key)) { return }
    return (Get-ItemProperty -Path $Key `
                             -Name $Property `
                             -ErrorAction SilentlyContinue) |
                Select-Object -ExpandProperty $Property
}

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-StringSet `
        -ParamName 'Status' `
        -ParamValue $InputParameters.Status `
        -ValidValues $INPUT_VALID_VALUES
    Test-EmptyOrGUIDParameter `
        -ParamName 'CampaignId' `
        -ParamValue $InputParameters.CampaignId
}

#
# Boot Auto Logger management
#
function Initialize-AutologgerProperties {
    return @(@{Name = 'FileName'
               Value = "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_AUTOLOGGER_FILENAME"
               RegType = 'STRING'},
             @{Name = 'ClockType'
               Value = $CLOCKTYPE_WIN7
               RegType = 'DWORD'},
             @{Name = 'LogFileMode'
               Value = $LOG_FILE_MODE_WIN7
               RegType = 'DWORD'},
             @{Name = 'MaxFileSize'
               Value = $MAXIMUM_LOG_FILE_SIZE
               RegType = 'DWORD'},
             @{Name = 'FlushTimer'
               Value = $FLUSH_TIMER_VALUE
               RegType = 'DWORD'},
             @{Name = 'BufferSize'
               Value = $MAXIMUM_LOG_BUFFER_SIZE
               RegType = 'DWORD'},
             @{Name = 'GUID'
               Value = $NEXTHINK_BOOT_AUTOLOGGER_GUID
               RegType = 'STRING'},
             @{Name = 'Start'
               Value = 1
               RegType = 'DWORD'})
}

function Initialize-ProvidersInfo {
    $level = [byte]0xff
    $property = [uint32]0x140
    $regProperty = [int32]0x140

    return @(@{Name = 'Microsoft Windows Kernel Boot'
               Guid = '{15ca44ff-4d7a-4baa-bba5-0998955e531e}'
               Level = $level
               Keyword = [uint64]::Parse("0C000000000000000", 'AllowHexSpecifier')
               RegKeyword = [int64]::Parse("0C000000000000000", 'AllowHexSpecifier')
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Kernel PnP'
               Guid = '{9c205a39-1250-487d-abd7-e831c6290539}'
               Level = $level
               Keyword = [uint64]::Parse("02000000000000020", 'AllowHexSpecifier')
               RegKeyword = [int64]::Parse("02000000000000020", 'AllowHexSpecifier')
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Boot UX'
               Guid = '{67D781BD-CBD2-4BD2-AD1F-6152FB891246}'
               Level = $level
               Keyword = [uint64]0x0000000000000004
               RegKeyword = [int64]0x0000000000000004
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Kernel Power'
               Guid = '{331C3B3A-2005-44C2-AC5E-77220C37D6B4}'
               Level = $level
               Keyword = [uint64]0x0000000000000800
               RegKeyword = [int64]0x0000000000000800
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Kernel Process'
               Guid = '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}'
               Level = $level
               Keyword = [uint64]0x10
               RegKeyword = [int64]0x10
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Winlogon Process'
               Guid = '{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}'
               Level = $level
               Keyword = [uint64]0x0000200000030000
               RegKeyword = [int64]0x0000200000030000
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Shell Core'
               Guid = '{30336ed4-e327-447c-9de0-51b652c86108}'
               Level = $level
               Keyword = [uint64]::Parse("00000000004000000", 'AllowHexSpecifier')
               RegKeyword = [int64]::Parse("00000000004000000", 'AllowHexSpecifier')
               Property = $property
               RegProperty = $regProperty},
             @{Name = 'Microsoft Windows Diagnostics PerfTrack'
               Guid = '{030f2f57-abd0-4427-bcf1-3a3587d7dc7d}'
               Level = $level
               Keyword = [uint64]::Parse("08001000000000000", 'AllowHexSpecifier')
               RegKeyword = [int64]::Parse("08001000000000000", 'AllowHexSpecifier')
               Property = $property
               RegProperty = $regProperty}
    )
}

function Test-MustEnable ([string]$Status) {
    return ($Status -eq 'enable')
}

function Test-IsWindows10 {
    $OSVersion = (Get-OSVersion) -as [version]
    return ($OSVersion.Major -eq 10)
}

function Update-BootAutoLogger ([hashtable[]]$AutologgerProperties, [hashtable[]]$ProvidersInfo, [bool]$Enable, [bool]$IsWin10, [string]$CampaignId) {
    Initialize-Folder -Path $NEXTHINK_LOGGER_SESSIONS_PATH
    if ($IsWin10) {
        Update-BootAutoLoggerWin10 -ProvidersInfo $ProvidersInfo -Enable $Enable
    } else {
        Update-BootAutoLoggerWin7 -AutologgerProperties $AutologgerProperties -ProvidersInfo $ProvidersInfo -Enable $Enable
    }

    if (Test-TriggerCampaign -Guid $CampaignId) {
        Invoke-OperationCompletedCampaign -CampaignId $CampaignId
    }
}

function Update-BootAutoLoggerWin10 ([hashtable[]]$ProvidersInfo, [bool]$Enable) {
    if ($Enable) {
        Enable-SessionsWin10
        Set-SessionProvidersWin10 -ProvidersInfo $ProvidersInfo
        Write-StatusMessage "The autologger $NEXTHINK_BOOT_AUTOLOGGER_NAME has been enabled. "
    } else {
        Disable-SessionsWin10
        Write-StatusMessage "The autologger $NEXTHINK_BOOT_AUTOLOGGER_NAME has been disabled. "
    }
}

function Enable-SessionsWin10 {
    New-BootAutologgerWin10
    $NEXTHINK_BOOT_AUTOLOGGER_CREATED = $true

    New-EtwSessionWin10
    $NEXTHINK_ETW_SESSION_CREATED = $true
}

function New-BootAutologgerWin10 {
    try {
        [void](New-AutologgerConfig -Name $NEXTHINK_BOOT_AUTOLOGGER_NAME -LocalFilePath "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_AUTOLOGGER_FILENAME" `
                                    -ClockType $CLOCKTYPE_WIN10 -LogFileMode $LOG_FILE_MODE_WIN10 -MaximumFileSize $MAXIMUM_LOG_FILE_SIZE -FlushTimer $FLUSH_TIMER_VALUE `
                                    -BufferSize $MAXIMUM_LOG_BUFFER_SIZE -Guid $NEXTHINK_BOOT_AUTOLOGGER_GUID -Start Enabled -ErrorAction Stop)
    } catch {
        throw "Unable to create the autologger $NEXTHINK_BOOT_AUTOLOGGER_NAME. Error: $_. "
    }
}

function New-EtwSessionWin10 {
    try {
        [void](Start-EtwTraceSession -Name $NEXTHINK_ETW_SESSION_NAME -LocalFilePath "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_ETW_SESSION_FILENAME" `
                                     -ClockType $CLOCKTYPE_WIN10 -LogFileMode $LOG_FILE_MODE_WIN10 -MaximumFileSize $MAXIMUM_LOG_FILE_SIZE `
                                     -FlushTimer $FLUSH_TIMER_VALUE -BufferSize $MAXIMUM_LOG_BUFFER_SIZE -ErrorAction Stop)
    } catch {
        throw "Unable to create the etw session $NEXTHINK_ETW_SESSION_NAME. Error: $_. "
    }
}

function Set-SessionProvidersWin10 ([hashtable[]]$ProvidersInfo) {
    foreach ($provider in $ProvidersInfo) {
        $name = $provider.Name
        $guid = $provider.Guid
        $level = $provider.Level
        $keyword = $provider.Keyword
        $property = $provider.Property
        $errorAction = 'Stop'

        $autologgerArguments = @{AutologgerName = $NEXTHINK_BOOT_AUTOLOGGER_NAME
                                 Guid = $guid
                                 Level = $level
                                 MatchAnyKeyword = $keyword
                                 Property = $property
                                 ErrorAction = $errorAction}
        $autologgerErrorMessage = "Unable to add $name as a provider to $NEXTHINK_BOOT_AUTOLOGGER_NAME"
        Add-Providers -Arguments $autologgerArguments -Message $autologgerErrorMessage

        $etwSessionArguments = @{SessionName = $NEXTHINK_ETW_SESSION_NAME
                                 Guid = $guid
                                 Level = $level
                                 MatchAnyKeyword = $keyword
                                 Property = $property
                                 ErrorAction = $errorAction}
        $etwSessionErrorMessage = "Unable to add $name as a provider to $NEXTHINK_ETW_SESSION_NAME"
        Add-Providers -Arguments $etwSessionArguments -Message $etwSessionErrorMessage
    }
}

function Add-Providers ([hashtable]$Arguments, [string]$Message) {
    try {
        [void](Add-EtwTraceProvider @Arguments)
    } catch {
        throw "$Message. Error: $_. "
    }
}

function Disable-SessionsWin10 {
    Disable-BootAutologgerWin10
    Remove-File -Path "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_ETW_SESSION_FILENAME"
}

function Disable-BootAutologgerWin10 {
    try {
        [void](Remove-AutologgerConfig -Name $NEXTHINK_BOOT_AUTOLOGGER_NAME -ErrorAction Stop)
    } catch {
        throw "Unable to remove the autologger $NEXTHINK_BOOT_AUTOLOGGER_NAME. Error: $_. "
    }

    Remove-File -Path "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_AUTOLOGGER_FILENAME"
}

function Disable-EtwSessionWin10 {
    try {
        [void](Remove-EtwTraceSession -Name $NEXTHINK_ETW_SESSION_NAME -ErrorAction Stop)
    } catch {
        throw "Unable to disable session $NEXTHINK_ETW_SESSION_NAME. Error: $_. "
    }

    Remove-File -Path "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_ETW_SESSION_FILENAME"
}

function Update-BootAutoLoggerWin7 ([hashtable[]]$AutologgerProperties, [hashtable[]]$ProvidersInfo, [bool]$Enable) {
    if ($Enable) {
        Enable-SessionWin7 -AutologgerProperties $AutologgerProperties
        Set-SessionProvidersWin7 -ProvidersInfo $ProvidersInfo
        Write-StatusMessage "The autologger $NEXTHINK_BOOT_AUTOLOGGER_NAME has been enabled. "
    } else {
        Disable-SessionWin7
        Write-StatusMessage "The autologger $NEXTHINK_BOOT_AUTOLOGGER_NAME has been disabled. "
    }
}

function Enable-SessionWin7 ([hashtable[]]$AutologgerProperties) {
    Add-AutologgerRegistryKey
    $NEXTHINK_BOOT_AUTOLOGGER_CREATED = $true

    Add-AutologgerProperties -Properties $AutologgerProperties
}

function Add-AutologgerRegistryKey {
    try {
        if ( -not (Test-Path -Path $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH)) {
            [void](New-Item -Path $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH -Force -ErrorAction Stop)
        } else {
            $startProperty = Get-RegistryKeyProperty -Key $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH -Property 'Start'
            if ($startProperty.Start -eq 1) {
                throw "There is already an active $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH in this device"
            }
        }
    } catch {
        throw "Unable to add $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH to registry. Error: $_. "
    }
}

function Add-AutologgerProperties ([hashtable[]]$Properties) {
    foreach ($property in $Properties) {
        try {
            [void](New-ItemProperty -Path $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH -Name $property.Name -PropertyType $property.RegType -Value $property.Value -Force -ErrorAction Stop)
        } catch {
            throw "Unable to add the property $($property.Name) with value $($property.Value) to $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH. Error: $_. "
        }
    }
}

function Set-SessionProvidersWin7 ([hashtable[]]$ProvidersInfo) {
    foreach ($provider in $ProvidersInfo) {
        $providerPath = "$NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH\$($provider.Guid)"
        try {
            [void](New-Item -Path $providerPath -Force -ErrorAction Stop)
        } catch {
            throw "Unable to create the new registry item $providerPath for provider $($provider.Name). Error: $_. "
        }

        try {

            [void](New-ItemProperty -Path $providerPath -Name 'Enabled' -PropertyType DWORD -Value 1 `
                                    -Force -ErrorAction Stop)
            [void](New-ItemProperty -Path $providerPath -Name 'EnableLevel' -PropertyType DWORD -Value $provider.Level `
                                    -Force -ErrorAction Stop)
            [void](New-ItemProperty -Path $providerPath -Name 'MatchAnyKeyword' -PropertyType QWORD -Value $provider.RegKeyword `
                                    -Force -ErrorAction Stop)
            [void](New-ItemProperty -Path $providerPath -Name 'EnableProperty' -PropertyType DWORD -Value $provider.RegProperty `
                                    -Force -ErrorAction Stop)
        } catch {
            throw "Unable to add $($provider.Name) as a provider to $NEXTHINK_BOOT_AUTOLOGGER_NAME. Error: $_. "
        }
    }
}

function Disable-SessionWin7 {
    try {
        if (Test-Path -Path $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH) {
            [void](Remove-Item -Path $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH -Recurse -ErrorAction Stop)
        } else {
            throw "The registry path $NEXTHINK_BOOT_AUTOLOGGER_REGISTRY_PATH does not exist"
        }
    } catch {
        throw "Unable to disable $NEXTHINK_BOOT_AUTOLOGGER_NAME. Error: $_. "
    }

    Remove-File -Path "$NEXTHINK_LOGGER_SESSIONS_PATH$NEXTHINK_AUTOLOGGER_FILENAME"
}

function Invoke-Cleanup ([bool]$IsWin10) {
    if ($IsWin10) {
        if ($NEXTHINK_BOOT_AUTOLOGGER_CREATED) {
            Disable-BootAutologgerWin10
        }
        if ($NEXTHINK_ETW_SESSION_CREATED) {
            Disable-EtwSessionWin10
        }
    } else {
        if ($NEXTHINK_BOOT_AUTOLOGGER_CREATED) {
            Disable-SessionWin7
        }
    }
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))
# SIG # Begin signature block
# MIIj5QYJKoZIhvcNAQcCoIIj1jCCI9ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDeR4cmpkDSbLd3
# rOIZWcfxp7hneZiOlaOqecemUTx306CCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDqxR52RS0i
# 9YR7vLRWXlfMrfBSCdKvwTsbQ/gi0DZ98zANBgkqhkiG9w0BAQEFAASCAgBLLcnE
# datLLP6PaOa5rk0/JCto2hepQVCaEECL+1QxFDxPZWh9UFUOSQEQDikF0PSv9tsD
# Ul1Q/7Gs7kjBZHuKOOO2kgIl9YQqoNJ5Yq6alQqZQ70+puONQj4MLiKx0S3AXj6N
# eqIKcJhbo7rIDyjGKE+cARYM2Lm9RQFXRcxOlNc1ASu5AWDpcCmAMSgnV/kOlvey
# yCRa81lgE8LIVE9oxNJWpywiCIfLWQPYgQwwidNwOdlmgJSj+oIE/KGTEZAomarV
# GGcwLmO1XJKlWzMkxS8cYBnsCqSsIACiG5bxnNo/gGiCk2F5C1RcwoUn5vd8Iwsi
# EAGm9ELJLI7ZynK6xrl45fsiMC62z96LyrZW/H8kbPmsXPT3iV7QBc8knpBhvLiV
# ymLU00RI2aUPCqeFVq96yq5InzO2T+XzaYoUexoMeitA9mFAqbddaaC1Sl336Q0d
# bTeMdOL+vUR3KjPSgq0+FfR3MmQtK1D5+q5dRNtBlacjHVyPW/m6qkfIo8zBBzDf
# tM1l0fTXlXPXo1u1Evf2mMa3YYS8HqMZRf1UVtWtWUerguLS8rLcgU2qRepid00+
# yispmGDOHUjj1OPLsthGrZCA80sx/ScyjBOtHgJAIdmF+cHE2hPKIW6YN9RStbqn
# 2vKVFPRc1oZrM+H8A7B0FdpEMJgsTLzHN76CVqGCDskwgg7FBgorBgEEAYI3AwMB
# MYIOtTCCDrEGCSqGSIb3DQEHAqCCDqIwgg6eAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCC32S36VI0Lqptq6O+sshMFkPDCLULHDlrCzVDk7JV+TQIRALjYKn2+BvED
# A5skgUr/yL4YDzIwMjAwODE5MTYzNzI3WqCCC7swggaCMIIFaqADAgECAhAEzT+F
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
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjAwODE5MTYzNzI3WjArBgsqhkiG
# 9w0BCRACDDEcMBowGDAWBBQDJb1QXtqWMC3CL0+gHkwovig0xTAvBgkqhkiG9w0B
# CQQxIgQgvYRvBwePuAxYInKxWO8QtcbpGb+sf7HE7kHhjNDQYIUwDQYJKoZIhvcN
# AQEBBQAEggEAmQfcfG5KSXsRuZgEjYh1OGhUSiKZnh4wAiYoBF/CWsX2GiPP5iRD
# NnfyApSEo+Z7e6JMPHLJFIH9INOWeIjjkabU4XzXolVjX4LHDlX5XRYRZBoquOeA
# 7m9zxGLWbaNdb84J5WBR9P8O1RsMsN7iqsLIYriCuCx16WRncWfab/osqFbEmXIZ
# uS30OZS4yuqPp+N+kA56f7oKNK+5e2PgLzN0jDyuZBWMvzeva4gOdzKiD89ecHkp
# fv4/RcMujOsNJar6iCrixGjyaeihhk9949AV9plIENFs7Pa30TMXQbWc39RwBtoS
# TEv/eg88udp25YbZvc09qq7x5QJd7NI5lw==
# SIG # End signature block
