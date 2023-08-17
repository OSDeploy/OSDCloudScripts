<#
.SYNOPSIS
Provides information about the boot information.

.DESCRIPTION
Provides detailed and granular information about the Boot time of a Windows 10 device.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID  Label                           Type            Description
1   TracingEnabled                  String          Indicates if the tracing has been enabled. The possibles values are (Tracing not enabled, Tracing is missing a provider, Tracing is enabled and data available, Tracing is enabled waiting for restart)
2   BootType                        String          The type of the boot of the device. Values can be 'normal boot' or 'fast boot'
3   LastBootTime                    DateTime        Indicates the time when the last boot started
4   OSBootDuration                  Millisecond     Indicates the time from the moment the kernel is loaded until logonui.exe is started
5   BootDuration                    Millisecond     Indicates the time from the moment that the user presses the power button until the user credentials are entered
6   MainPathBootDuration            Millisecond     Indicates the time from the moment that the OS starts to load until the desktop is displayed
7   LogonDuration                   Millisecond     Indicates the time from the moment the user has entered the credentials until the Desktop screen is displayed

.FURTHER INFORMATION
Only compatible with Windows 10.

.NOTES
Context:            LocalSystem
Version:            1.0.4.0 - Updated "LogonDuration" output description
                    1.0.3.0 - Fixed date for different timezones
                    1.0.2.0 - Fixed default date
                    1.0.1.0 - Updated documentation
                    1.0.0.0 - Initial release
Last Generated:     01 Sep 2021 - 15:44:07
Copyright (C) 2021 Nexthink SA, Switzerland
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

New-Variable -Name 'EVENT_TRACING_LOG_NORMAL_BOOT_FILENAME' `
    -Value 'nxtdiag.etl' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH' `
    -Value "$env:ProgramData\Nexthink\BootDetails\$EVENT_TRACING_LOG_NORMAL_BOOT_FILENAME" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'EVENT_TRACING_LOG_FAST_BOOT_FILENAME' `
    -Value 'nxtdiagBR.etl' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'EVENT_TRACING_LOG_FAST_BOOT_FILEPATH' `
    -Value "$env:ProgramData\Nexthink\BootDetails\$EVENT_TRACING_LOG_FAST_BOOT_FILENAME" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'EVENT_NAMESPACE' `
    -Value @{e = 'http://schemas.microsoft.com/win/2004/08/events/event'} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'XPATH_TEMPLATE' `
    -Value "//e:Data[@Name='{0}']/text()" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NEXTHINK_BOOT_AUTOLOGGER_NAME' `
    -Value 'Nexthink-Boot-Autologger' `
    -Option ReadOnly -Force -Scope Script
New-Variable -Name 'NEXTHINK_ETW_SESSION_NAME' `
    -Value 'Nexthink-Etw-Session' `
    -Option ReadOnly -Force -Scope Script

New-Variable -Name 'BOOT_TYPE' `
    -Value @{EventID = 27
             Fields = @('BootType')
             Process = $null} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'BOOT_TYPE_DICTIONARY' `
    -Value  @{'0' = 'normal boot'
              '1' = 'fast boot'} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'BOOT_START' `
    -Value @{EventID = 1
             Fields = @('ImageName')
             Process = 'smss.exe'} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'BOOT_STOP' `
    -Value @{EventID = 2
             Fields = @('ImageName')
             Process = 'logonui.exe'} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'FAST_BOOT_DURATION' `
    -Value @{EventID = 117
             Fields = @('POSTTime', 'ResumeBootMgrTime', 'ResumeAppTime', 'KernelResumeHiberFileTime', 'DeviceResumeTime')
             Process = $null} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_FAST_BOOT_DURATION' `
    -Value  @{Path=$EVENT_TRACING_LOG_FAST_BOOT_FILEPATH
              ProviderName='Microsoft-Windows-Kernel-Power'
              Keywords=0x0000000000000800
              ID=@($FAST_BOOT_DURATION.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'MAIN_PATH_BOOT_DURATION' `
    -Value @{EventID = 1500
             Fields = @('MainPathHybridbootTimeMs')
             Process = $null} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_FAST_MAIN_PATH_BOOT_DURATION' `
    -Value  @{Path=$EVENT_TRACING_LOG_FAST_BOOT_FILEPATH
              Keywords=0x8001000000000000
              ID=@($MAIN_PATH_BOOT_DURATION.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'TIME_FROM_CREDENTIALS' `
    -Value @{EventID = 202
             Fields = $null
             Process = $null} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_FAST_BOOT_TIME_FROM_CREDENTIALS' `
    -Value  @{Path=$EVENT_TRACING_LOG_FAST_BOOT_FILEPATH
              ProviderName='Microsoft-Windows-Winlogon'
              Keywords=0x0000200000030000
              ID=@($TIME_FROM_CREDENTIALS.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'POST_HYBRID_BOOT_START' `
    -Value @{EventID = 1111
             Fields = $null
             Process = $null} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_FAST_BOOT_POST_HYBRID_BOOT_START' `
    -Value  @{Path=$EVENT_TRACING_LOG_FAST_BOOT_FILEPATH
              Keywords=0x8001000000000000
              ID=@($POST_HYBRID_BOOT_START.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NORMAL_BOOT_DURATION' `
    -Value @{EventID = 11
             Fields = @('PreBootMgrTime')
             Process = $null } `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_NORMAL_BOOT_BOOT_DURATION' `
    -Value  @{Path=$EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
              ProviderName='Microsoft-Windows-Kernel-Boot'
              Keywords=0xC000000000000000
              ID=@($NORMAL_BOOT_DURATION.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'OS_LOADER' `
    -Value @{EventID = 204
             Fields = @('OSLoaderStart', 'OSLoaderEnd')
             Process = $null } `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_NORMAL_BOOT_OS_LOADER' `
    -Value  @{Path=$EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
              ProviderName='Microsoft-Windows-Kernel-PnP'
              Keywords=0x2000000000000020
              ID=@($OS_LOADER.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'FILTERHASH_NORMAL_BOOT_START_OS_BOOT' `
    -Value  @{Path=$EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
              ID=@($BOOT_START.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'WELCOME_SCREEN_START' `
    -Value @{EventID = 201
             Fields = $null
             Process = $null } `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_NORMAL_BOOT_TIME_TO_CREDENTIALS' `
    -Value  @{Path=$EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
              ProviderName='Microsoft-Windows-Kernel-PnP'
              Keywords=0x2000000000000020
              ID=@($WELCOME_SCREEN_START.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'POST_BOOT_START' `
    -Value @{EventID = 1100
             Fields = $null
             Process = $null } `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FILTERHASH_NORMAL_BOOT_POST_BOOT_START' `
    -Value  @{Path=$EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
              Keywords=0x8001000000000000
              ID=@($POST_BOOT_START.EventID)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'FILTERHASH_NORMAL_BOOT_TIME_FROM_CREDENTIALS' `
    -Value  @{Path=$EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
              Keywords=0x0000200000030000
              ProviderName='Microsoft-Windows-Winlogon'
              ID=@($TIME_FROM_CREDENTIALS.EventID)} `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main {
    $exitCode = 0
    [hashtable]$output = Initialize-Output
    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsLocalSystem
        Test-RunningOnWindows10
        Test-ETLFilePresent

        Update-TracingInfo -Output $Output
        Update-BootTimeDetails -Output $output
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Remove-File -Path $EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH
        Remove-File -Path $EVENT_TRACING_LOG_FAST_BOOT_FILEPATH
        Update-EngineOutputVariables -Output $output
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

function Test-RunningOnWindows10 {

    $OSVersion = (Get-OSVersion) -as [version]
    if (-not ($OSVersion)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script could not return OS version. "
    }
    if ($OSVersion.Major -ne 10) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script is compatible with Windows 10 only. "
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

function Test-CollectionNullOrEmpty ([psobject[]]$Collection) {
    return $null -eq $Collection -or ($Collection | Measure-Object).Count -eq 0
}

#
# Boot information
#
function Initialize-Output {
    return @{TracingEnabled = '-'
             BootType = '-'
             LastBootTime = $DEFAULT_DATE
             OSBootDuration = [timespan]0
             BootDuration = [timespan]0
             MainPathBootDuration = [timespan]0
             LogonDuration = [timespan]0}
}

function Test-ETLFilePresent {
   if ((-not (Test-Path -Path $EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH)) -and (-not (Test-Path -Path $EVENT_TRACING_LOG_FAST_BOOT_FILEPATH))) {
       throw "The files $EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH and $EVENT_TRACING_LOG_FAST_BOOT_FILEPATH are not present. " +
             'Be sure to have executed the Set Boot Details Remote Action and rebooted the device. '
   }
}

function Update-TracingInfo ([hashtable]$Output) {
    $autologgerSession = Get-AutologgerConfig -Name $NEXTHINK_BOOT_AUTOLOGGER_NAME -ErrorAction SilentlyContinue

    if (Test-CollectionNullOrEmpty -Collection $autologgerSession){
        $Output.TracingEnabled = 'Tracing not enabled'
    } else {
        if ((Test-ETLFileValidity -FilePath $EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH) -or (Test-ETLFileValidity -FilePath $EVENT_TRACING_LOG_FAST_BOOT_FILEPATH)) {
            $Output.TracingEnabled = 'Tracing is enabled and data available'
        } else { $Output.TracingEnabled = 'Tracing is enabled waiting for restart' }
    }
}

function Test-ETLFileValidity ([string]$FilePath) {
    return ((Test-Path -Path $FilePath) -and ((Get-Item -Path $FilePath).Length -gt 0))
}

function Update-BootTimeDetails ([hashtable]$Output) {
    $filepath = Get-ETLFilePath
    Update-BootTypeInformation -Output $Output -FilePath $filepath

    $filterhashKernel = @{Path = $filepath; ID = @($BOOT_START.EventID, $BOOT_STOP.EventID)}
    $infoStart = Get-FieldInfo -FilterTable $filterhashKernel -EventInfo $BOOT_START
    $infoStop = Get-FieldInfo -FilterTable $filterhashKernel -EventInfo $BOOT_STOP
    $Output.LastBootTime = $infoStart.($BOOT_START.Process).TimeCreated
    $Output.OSBootDuration = $infoStop.($BOOT_STOP.Process).TimeCreated - $infoStart.($BOOT_START.Process).TimeCreated

    if ($Output.BootType -eq $BOOT_TYPE_DICTIONARY.'0') {
        Update-NormalBootInformation -Output $Output
    } else {
        Update-FastBootInformation -Output $Output
    }
}

function Get-ETLFilePath {
    if (Test-ETLFileValidity -FilePath $EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH) { return $EVENT_TRACING_LOG_NORMAL_BOOT_FILEPATH }
    else { return $EVENT_TRACING_LOG_FAST_BOOT_FILEPATH }
}

function Update-BootTypeInformation ([hashtable]$Output, [string]$Filepath) {
    $FILTERHASH_BOOT = @{Path = $Filepath
                         ProviderName = 'Microsoft-Windows-Kernel-Boot'
                         Keywords = 0xC000000000000000
                         ID = @($BOOT_TYPE.EventID)}
    $info = Get-FieldInfo -FilterTable $FILTERHASH_BOOT -EventInfo $BOOT_TYPE
    if (($BOOT_TYPE_DICTIONARY.keys) -notcontains $($info.($BOOT_TYPE.Fields[0]))) {
        throw "The boot code $($info.($BOOT_TYPE.Fields[0])) is not valid, please reboot or turn off & on the device. "
    }
    $Output.BootType = $BOOT_TYPE_DICTIONARY.($info.($BOOT_TYPE.Fields[0]))
}

function Get-FieldInfo ([hashtable]$FilterTable, [hashtable]$EventInfo) {
    $filteredEvents = @(Get-WinEvent -FilterHashtable $FilterTable -Oldest -ErrorAction SilentlyContinue)
    if (Test-CollectionNullOrEmpty($filteredEvents)) { throw "There are no events matching the specified criteria. " }
    return Get-InfoFromWinEvent -Events $filteredEvents -EventInfo $EventInfo
}

function Get-InfoFromWinEvent ([array]$Events, [hashtable]$EventInfo) {
    $output = @{}
    foreach($winEvent in $Events) {
        if ($EventInfo.EventID -notcontains $($winEvent.id)) { continue }
        Update-WinEventOutput -EventInfo $EventInfo -WinEvent $winEvent -Output $output
   }
   return $output
}

function Update-WinEventOutput ([hashtable]$EventInfo, [psobject]$WinEvent, [hashtable]$Output) {
    if ($null -eq $EventInfo.Fields) {
        $output.TimeCreated = $winEvent.TimeCreated
        return
    }

    foreach ($field in $EventInfo.Fields) {
        $fieldInfo = Get-XmlFieldInfo -WinEvent $winEvent -Field $field
        if ($null -ne $EventInfo.Process) {
            Update-ProcessTimeCreated -Process $EventInfo.Process `
                                      -Output $output `
                                      -FieldInfo $fieldInfo `
                                      -WinEvent $winEvent
        } else {
            $output.$field = $fieldInfo
        }
    }
}

function Get-XmlFieldInfo ([psobject]$WinEvent, [string]$Field) {
    $xml = [xml]$winEvent.ToXml()
    return Select-Xml -Xml $xml -Namespace $EVENT_NAMESPACE -XPath ($XPATH_TEMPLATE -f $Field) |
               Select-Object -ExpandProperty Node | Select-Object -ExpandProperty Value
}

function Update-ProcessTimeCreated ([string]$Process, [hashtable]$Output, [psobject]$FieldInfo, [psobject]$WinEvent) {
    if ($FieldInfo -match $Process -and (($null -eq $Output.$Process) -or ($Output.$Process.ProcessId -gt $WinEvent.ProcessId))) {
        $Output.$Process = @{TimeCreated = $WinEvent.TimeCreated
                             ProcessId = $WinEvent.ProcessId}
    }
}

function Update-NormalBootInformation ([hashtable]$Output) {
    $infoStart = Get-FieldInfo -FilterTable $FILTERHASH_NORMAL_BOOT_START_OS_BOOT -EventInfo $BOOT_START
    $infoBootStart = Get-FieldInfo -FilterTable $FILTERHASH_NORMAL_BOOT_POST_BOOT_START -EventInfo $POST_BOOT_START
    $infoCredentials = Get-FieldInfo -FilterTable $FILTERHASH_NORMAL_BOOT_TIME_FROM_CREDENTIALS -EventInfo $TIME_FROM_CREDENTIALS

    $Output.BootDuration = Get-BootDuration -InfoStart $infoStart
    $Output.MainPathBootDuration = $infoBootStart.TimeCreated - ($infoStart.($BOOT_START.Process).TimeCreated)
    $Output.LogonDuration = $infoBootStart.TimeCreated - $infoCredentials.TimeCreated
}

function Get-BootDuration ([hashtable]$InfoStart) {
    $info = Get-FieldInfo -FilterTable $FILTERHASH_NORMAL_BOOT_BOOT_DURATION -EventInfo $NORMAL_BOOT_DURATION
    $infoCredentials = Get-FieldInfo -FilterTable $FILTERHASH_NORMAL_BOOT_TIME_TO_CREDENTIALS -EventInfo $WELCOME_SCREEN_START
    $info = Get-FieldInfo -FilterTable $FILTERHASH_NORMAL_BOOT_OS_LOADER -EventInfo $OS_LOADER

    $biosBootDuration = [timespan]::FromMilliseconds($info.($NORMAL_BOOT_DURATION.Fields[0]))
    $clockSpeed = (Get-WmiObject -Class Win32_Processor | Select-Object -First 1).MaxClockSpeed
    $OSLoaderDuration = [timespan]::FromMilliseconds(($info.($OS_LOADER.Fields[1]) - $info.($OS_LOADER.Fields[0])) / ($clockSpeed * 1000))

    return ($infoCredentials.TimeCreated - ($infoStart.($BOOT_START.Process).TimeCreated)) + $OSLoaderDuration + $biosBootDuration
}

function Update-FastBootInformation ([hashtable]$Output) {
    $infoDuration = Get-FieldInfo -FilterTable $FILTERHASH_FAST_BOOT_DURATION -EventInfo $FAST_BOOT_DURATION
    $info = Get-FieldInfo -FilterTable $FILTERHASH_FAST_MAIN_PATH_BOOT_DURATION -EventInfo $MAIN_PATH_BOOT_DURATION
    $infoStart = Get-FieldInfo -FilterTable $FILTERHASH_FAST_BOOT_TIME_FROM_CREDENTIALS -EventInfo $TIME_FROM_CREDENTIALS
    $infoStop = Get-FieldInfo -FilterTable $FILTERHASH_FAST_BOOT_POST_HYBRID_BOOT_START -EventInfo $POST_HYBRID_BOOT_START

    $sum = 0
    foreach ($value in $infoDuration.values) { $sum += $value }
    $Output.BootDuration = [timespan]::FromMilliseconds($sum)
    $Output.MainPathBootDuration = [timespan]::FromMilliseconds($info.($MAIN_PATH_BOOT_DURATION.Fields[0]))
    $Output.LogonDuration = $infoStop.TimeCreated - $infoStart.TimeCreated
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$Output) {
    [nxt]::WriteOutputString('BootType', $Output.BootType)
    [nxt]::WriteOutputString('TracingEnabled', $Output.TracingEnabled)
    [nxt]::WriteOutputDateTime('LastBootTime', $Output.LastBootTime)
    [nxt]::WriteOutputDuration('OSBootDuration', $Output.OSBootDuration)
    [nxt]::WriteOutputDuration('LogonDuration', $Output.LogonDuration)
    [nxt]::WriteOutputDuration('BootDuration', $Output.BootDuration)
    [nxt]::WriteOutputDuration('MainPathBootDuration', $Output.MainPathBootDuration)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main))

# SIG # Begin signature block
# MIIimQYJKoZIhvcNAQcCoIIiijCCIoYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBSbMk8cjXC4kPr
# /6bKFkSSbNLyLe1LNI0RvhbZAigRdKCCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCArY8KntIUx
# 6FN50Q0mbqlIWv6LDMnA+No+kbqbPX4VBTANBgkqhkiG9w0BAQEFAASCAgBFTNqt
# DY3fkj4UrHaMVjAVTFwAdCxqDlopLNM7vo37n2Ms7mfa6FbacssD5DVV0aWdY+qK
# c1tIOH81y9Xgj8V5X0h7WqYgbw7UPRR6Rb0hfhWdE/R6Gs5wvxMkuEcgJWCycHIk
# feplKtHtCE7trEwcOZx1RT+rGNg26s0XkYCF6VavuRo6s5HxkK762fFDy/g0TVI2
# b0VaiVqTfsqzok8k7BDYdh574Udp9UHgBm8OwMcqyH1zmGB4oDcvtM3rpFcPIc8D
# dy3sxk6JdsoS1CrMyCu4/LFNxnoiX3rmH+KtIJJGvpiFRl53TWhTynFvnI42xMAH
# DoF+pa8r9weaAHZaAA/nEkGt3YFK9S+v3qoeU+ZITK5Zn39b8iqJXU/ivKH3UsDH
# YxRjSeUHx+NEIFswkYX2dC0vOptEfBJMcIsZY8gSOemW/Hxzcpvfu8AvnsN/PmGe
# gLYtQk6tK/NjaXOnY4oF3bpc3E6VLbFQZh6vs25wMhlw4QHcSrM4UGavcnRNicku
# 3i2UkBJSGbFJFxUb8pEwwWDRH8Lr8uCffCIOWXDnFsXEr7b/bRekz8HjViTXKpb7
# xGfdTf2kGmDSa+qUltI+V2lrxU7tBfqNQVxSzChmf/JPeKGi9JIzg6lLp+mjNoFV
# kx3aLY1sM8dxqPSdIXefp5Fl0mK0wlfvzSdefKGCDX0wgg15BgorBgEEAYI3AwMB
# MYINaTCCDWUGCSqGSIb3DQEHAqCCDVYwgg1SAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCCpXQPbNbdbpl9M7oZKTflGOInbQvzxmjCwfbAmrFszlgIQHJACr1XtNRDo
# 7ZJ69kTQKhgPMjAyMTA5MDExMzQ0MTRaoIIKNzCCBP4wggPmoAMCAQICEA1CSuC+
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
# AQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIxMDkwMTEzNDQxNFowKwYLKoZIhvcNAQkQ
# AgwxHDAaMBgwFgQU4deCqOGRvu9ryhaRtaq0lKYkm/MwLwYJKoZIhvcNAQkEMSIE
# IM1zhD5/xDVOAj6xiMKOr7bfCm9i3nqrnXYAgY8LN7msMDcGCyqGSIb3DQEJEAIv
# MSgwJjAkMCIEILMQkAa8CtmDB5FXKeBEA0Fcg+MpK2FPJpZMjTVx7PWpMA0GCSqG
# SIb3DQEBAQUABIIBAHSn8fHjLLyHFjQuMfIq6G6HWs61fXYaWHk+k+rmeWHv27Tl
# 3ACo3divkjptwM+TfX48GzCvW3SWtDqOo7fPDJ3TvxzsP5aylVWpyjBv2Yql80fw
# e/2W8bUjY+e4TK6knibK0Jj3xsplcWc+GXu4NWakncQMlbq/YdKFl4dWCAKe8UbS
# 14NansxuLe/U5nWLrp2j+vJ5jbrD1qVLFxZjx2vhG705nRZ+idFC9rhQJ6McbMa+
# /LZ64SMiWONmBg1pY1kmZSkWwlqFQIW+5PVvhgyxk7Q8XxsMEUI4LgiLjyISC1f7
# ceDDheByZ1ebzqWqDc9IDZl+mIDnITIhSUV3sWk=
# SIG # End signature block
