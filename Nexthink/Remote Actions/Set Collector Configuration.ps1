<#
.SYNOPSIS
Sets Collector configuration parameters and restarts Collector services afterwards, whenever applicable.

.DESCRIPTION
ADVANCED SCRIPT - This Remote action should be used by a certified Nexthink expert.
Collector configuration is changed using Nxtcfg tool, except for 'AppStartTime'.
'AppStartTime' configuration parameter change involves Registry Key changes and additional verifications done by the Remote Action.

.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   Tag                             Optional number to identify the installation (0-2147483647)
2   LogMode                         Logging mode (0 - Silent, 1 - Verbose, 2 - Debug). It might impact performance. Use only for debugging
3   WMDomains                       List of domains for which to report the URL of web requests (comma-separated)
4   IOPS                            Enables (1) or disables (0) IOPS monitoring functionality
5   PKGInterval                     Period, in hours, in which the Collector checks for new installed packages and updates. Integer in range (0-24) (0-Never)
6   Printing                        Enables ('enable') or disables ('disable') print monitoring
7   AppStartTime                    Enables (0) or disables (1) App Start Time feature. If enabled, a list of executables must be provided as AppStartTimeWhitelist input parameter
8   AppStartTimeWhitelist           Comma-separated list of executables that should be monitored by Collector. Example":" 'my-executable.exe, exec*.exe, prefix*name*suffix'. Use "*" if you want to monitor all the executables
9   WindowFocusTimeMonitoring       Enables (1) or disables (0) the Windows Focus Time Monitoring
10  UserInteractionTimeMonitoring   Enables (0) or disables (1) the User Interaction Time Monitoring
11  AnonymizeUserName               Enables (1) or disables (0) the Anonymize User Name
12  AnonymizeWifiNetwork            Enables (1) or disables (0) the Anonymize Wifi Networks

.OUTPUTS
ID  Label                           Type            Description
1   CollectorParametersSet          StringList      List of Collector parameter=value set

.FURTHER INFORMATION
Please use '""' (two double-quotes) as input parameter in Finder to prevent any of the configuration values from being changed.
Notice that if the 'EnableStringTag' input parameter is enabled, the StringTag functionality will set the same value in all selected Collectors.

.NOTES
Context:            LocalSystem
Version:            8.3.0.1 - Fixed typo in Test-MinimumWindowsVersion
                    8.3.0.0 - Improved Scheduled Tasks management
                    8.2.0.0 - Added compatibility for Windows Servers
                    8.1.2.0 - Fixed bug on Scheduled Tasks management
                    8.1.1.0 - Fixed bug on Scheduled Tasks management
                    8.1.0.0 - Added support for changing 64 bits Windows Registry from 32 bits processes
                    8.0.0.0 - Added 'AnonymizeWifiNetwork' input parameter for Collector to anonymize wireless network information
                    7.0.0.0 - Removed String Tag due to the possible impact on not prepared environments
                    6.0.0.0 - Added new capabilities to configure 'User Interaction Time Monitoring' and 'Anonymize User Name' Collector parameters
                    5.1.0.0 - Added new capability through new input parameters 'StringTag', as an optional label to identify the installation, and 'EnableStringTag' to enable it
                    5.0.0.0 - Added 'WindowFocusTimeMonitoring' input parameter to monitor the Windows Focus Time
                    4.0.1.0 - Fixed bug to prevent updating AppStartTime settings when no 'AppStartTime' input parameters are passed
                    4.0.0.0 - Added 'AppStartTimeWhitelist' input parameter to set the executables to monitor with App start Time feature
                    3.0.3.0 - Updated description of "IOPS" input parameter
                    3.0.2.0 - Fixed documentation
                    3.0.1.0 - Fixed bug with processing AppStartTime as only input
                    3.0.0.1 - Script security revision
                    3.0.0.0 - Added 'AppStartTime' parameter to enable or disable App Start Time feature
                    2.0.0.0 - Added 'pkg_interval' and 'printing' parameters, and removed 'custom_shells'. Added version compatibility check for parameters
                    1.0.1.0 - Driver restarting process update
                    1.0.0.0 - Initial release
Last Generated:     26 Apr 2022 - 18:51:24
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][string]$LogMode,
    [Parameter(Mandatory = $true)][string]$WMDomains,
    [Parameter(Mandatory = $true)][string]$IOPS,
    [Parameter(Mandatory = $true)][string]$PKGInterval,
    [Parameter(Mandatory = $true)][string]$Printing,
    [Parameter(Mandatory = $true)][string]$AppStartTime,
    [Parameter(Mandatory = $true)][string]$AppStartTimeWhitelist,
    [Parameter(Mandatory = $true)][string]$WindowFocusTimeMonitoring,
    [Parameter(Mandatory = $true)][string]$UserInteractionTimeMonitoring,
    [Parameter(Mandatory = $true)][string]$AnonymizeUserName,
    [Parameter(Mandatory = $true)][string]$AnonymizeWifiNetwork
)
# End of parameters definition

$env:Path = 'C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\'

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
New-Variable -Name 'RESTART_COLLECTOR_ARGUMENT' `
    -Value '/restart' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'RESTART_COLLECTOR_EXECUTABLE' `
    -Value 'C:\Windows\System32\nxtcfg.exe' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'RESTART_COLLECTOR_TASK_NAME' `
    -Value 'Nexthink Coordinator service restart' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'RESTART_COLLECTOR_TIME_DELAY' `
    -Value 75 `
    -Option ReadOnly -Scope Script
New-Variable -Name 'TASK_SCHEDULER_EXE' `
    -Value "$env:SystemRoot\system32\schtasks.exe" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'WINDOWS_VERSIONS' `
    -Value @{Windows7 = '6.1'
             Windows8 = '6.2'
             Windows81 = '6.3'
             Windows10 = '10.0'
             Windows11 = '10.0'} `
    -Option ReadOnly -Scope Script

New-Variable -Name 'COLLECTOR_REG_KEY' `
    -Value 'HKLM:\SOFTWARE\Nexthink' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_REG_VERSION' `
    -Value 'ProductVersion' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_APP_START_TIME_REGKEY' `
    -Value "$COLLECTOR_REG_KEY\Collector\AppStartTime" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'APP_START_TIME_DISABLED_REGKEY_PROP' `
    -Value 'Disabled' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'APP_START_TIME_WHITELIST_REGKEY_PROP' `
    -Value 'Whitelist' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'APP_START_TIME_ENABLED_VALUE' `
    -Value 0 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'APP_WHITELIST_FORBIDDEN_CHARACTERS' `
    -Value '[\\\/;:\?"<>\|]' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'COLLECTOR_WINDOWS_FOCUS_REGKEY' `
    -Value "$COLLECTOR_REG_KEY\Collector\WindowFocusTimeMonitoring" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_WINDOWS_FOCUS_REGKEY_PROP' `
    -Value 'Enabled' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_WINDOWS_FOCUS_ENABLED_VALUE' `
    -Value 1 `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY' `
    -Value "$COLLECTOR_REG_KEY\Collector\UserInteractionTimeMonitoring" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY_PROP' `
    -Value 'Disabled' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_USER_INTERACTION_TIME_MONITORING_DISABLED_VALUE' `
    -Value 1 `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'COLLECTOR_ANONYMIZE_DATA_REGKEY' `
    -Value "$COLLECTOR_REG_KEY\Collector\AnonymizedData" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_ANONYMIZE_USERNAME_REGKEY_PROP' `
    -Value 'UserName' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_ANONYMIZE_WIFI_REGKEY_PROP' `
    -Value 'WifiNetwork' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_ANONYMIZE_DATA_ENABLED_VALUE' `
    -Value 1 `
    -Option ReadOnly -Scope Script -Force

if (-not ('RestartRequired' -as [type])) {
    Add-Type -TypeDefinition 'public enum RestartRequired {No, Driver}'
}

New-Variable -Name 'COLLECTOR_SET_PARAMETER' `
    -Value '/s' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_TOOL_SUCCESS_MESSAGE' `
    -Value 'nxtcfg.exe completed successfully.' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_PARAMETERS_NAME' `
    -Value @{Tag = 'Tag'
             LogMode = 'LogMode'
             IOPS = 'IOPS'
             PKGInterval = 'PKGInterval'
             AppStartTime = 'AppStartTime'
             AppStartTimeWhitelist = 'AppStartTimeWhitelist'
             Whitelist = 'Whitelist'
             Printing = 'Printing'
             WindowFocusTimeMonitoring = 'WindowFocusTimeMonitoring'
             UserInteractionTimeMonitoring = 'UserInteractionTimeMonitoring'
             AnonymizeUserName = 'AnonymizeUserName'
             AnonymizeWifiNetwork = 'AnonymizeWifiNetwork'} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COLLECTOR_PARAMETERS_NON_REGKEY_KEYS' `
    -Value @{Tag = 'tag'
             LogMode = 'logmode'
             WMDomains = 'wm_domains'
             IOPS = 'iops'
             PKGInterval = 'pkg_interval'
             Printing = 'printing'} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'VALID_STRING_0_OR_1_VALUES' `
    -Value (@('0', '1') -as [string[]]) `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'VALID_STRING_ENABLE_OR_DISABLE_VALUES' `
    -Value (@('enable', 'disable') -as [string[]]) `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    try {
        Set-ToolsPath
        Add-NexthinkRemoteActionDLL
        Add-ServiceStatusType

        Test-InputParameters -InputParameters $InputParameters
        Test-RunningAsLocalSystem
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows7' -SupportedWindowsServer

        $collectorVersion = Test-CollectorVersion
        $parameters = Initialize-CollectorParameters -ScriptParams $InputParameters `
                                                     -CollectorVersion $collectorVersion

        Update-CollectorParameters -Parameters $parameters.ParametersToUpdate

        if ($parameters.ParametersToIgnore.Count -gt 0) {
            $message = Show-ParametersNotAvailable -ParametersNotAvailable $parameters.ParametersToIgnore `
                                                   -CollectorVersion $collectorVersion
            Write-StatusMessage -Message $message
        }
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        $outputStringList = Edit-CollectorToolParameters -Parameters $parameters.ParametersToUpdate
        Update-EngineOutputVariables -OutputStringList $outputStringList
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

function Add-ServiceStatusType {

    if (-not ('ServiceStatus' -as [type])) {
        Add-Type -TypeDefinition 'public enum ServiceStatus {Running, Stopped}'
    }
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

function Confirm-StringIsNotEmpty ([string]$Value) {
    return -not [string]::IsNullOrEmpty((Format-StringValue -Value $Value))
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Test-ParamInAllowedRange ([string]$ParamName, [string]$ParamValue, [int]$LowerLimit, [int]$UpperLimit) {
    Test-ParamIsInteger -ParamName $ParamName -ParamValue $ParamValue
    $intValue = $ParamValue -as [int]
    if ($intValue -lt $LowerLimit -or $intValue -gt $UpperLimit) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It must be between [$LowerLimit, $UpperLimit]. "
    }
}

function Test-ParamIsInteger ([string]$ParamName, [string]$ParamValue) {
    $intValue = $ParamValue -as [int]
    if ([string]::IsNullOrEmpty($ParamValue) -or $null -eq $intValue) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. '$ParamValue' is not an integer. "
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

function Test-StringNullOrEmpty ([string]$ParamName, [string]$ParamValue) {
    if ([string]::IsNullOrEmpty((Format-StringValue -Value $ParamValue))) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) '$ParamName' cannot be empty nor null. "
    }
}

function Test-WOW6432Process {

    return (Test-Path Env:\PROCESSOR_ARCHITEW6432)
}

function Test-RegistryKeyProperty ([string]$Key, [string]$Property) {
    if ([string]::IsNullOrEmpty($Key)) { return $false }
    if (Test-WOW6432Process) {
        $regSubkey = Get-WOW64RegistrySubKey -Key $Key -Property $Property -ReadOnly
        return $null -ne $regSubkey.GetValue($Property)
    } else {
        return $null -ne (Get-ItemProperty -Path $Key `
                                           -Name $Property `
                                           -ErrorAction SilentlyContinue)
    }
}

function Get-WOW64RegistrySubKey ([string]$Key, [switch]$ReadOnly) {
    switch -Regex ($Key) {
        '^HKLM:\\(.*)' { $hive = "LocalMachine" }
        '^HKCU:\\(.*)' { $hive = "CurrentUser" }
    }

    try {
        $regKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive,[Microsoft.Win32.RegistryView]::Registry64)

        switch ($ReadOnly) {
            $true { return $regKey.OpenSubKey($Matches[1]) }
            $false { return $regKey.OpenSubKey($Matches[1],$true) }
        }
    }
    catch {
         throw 'Error opening registry hive. '
    }
}

function Get-RegistryKeyProperty ([string]$Key, [string]$Property) {
    if ([string]::IsNullOrEmpty($Key)) { return }
    if (Test-WOW6432Process) {
        $regSubkey = Get-WOW64RegistrySubKey -Key $Key -Property $Property -ReadOnly
        return $regSubkey.GetValue($Property)
    } else {
        return (Get-ItemProperty -Path $Key `
                                 -Name $Property `
                                 -ErrorAction SilentlyContinue) |
                    Select-Object -ExpandProperty $Property
    }
}

function Test-CollectionNullOrEmpty ([psobject[]]$Collection) {
    return $null -eq $Collection -or ($Collection | Measure-Object).Count -eq 0
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

function Set-RegistryKey ([string]$Key, [string]$Property, [string]$Type, [object]$Value) {
    if (Test-WOW6432Process) {
        $regSubkey = Get-WOW64RegistrySubKey -Key $Key
        Set-Win32RegistryKeyValue -SubKey $regSubkey -Property $Property -Type $Type -Value $Value
    } else {
        if (-not (Test-Path -Path $Key)) { [void](New-Item -Path $Key -Force -ErrorAction Stop) }
        [void](New-ItemProperty -Path $Key `
                                -Name $Property `
                                -PropertyType $Type `
                                -Value $Value -ErrorAction Stop -Force)
    }
}

function Set-Win32RegistryKeyValue ([Microsoft.Win32.RegistryKey]$SubKey, [string]$Property, [string]$Type, [object]$Value) {
    try {
        $Subkey.SetValue($Property,$Value,$Type)
    }
    catch {
        throw "Error setting $($Subkey.Name)\$Property to $Value as $Type from 64 bits registry. "
    }
}

function Invoke-CollectorRestart {

    if (Test-PowerShellVersion -MinimumVersion 5) {
        $scheduledTaskArguments = @{
            TaskName = $RESTART_COLLECTOR_TASK_NAME
            ProgramOrScript = $RESTART_COLLECTOR_EXECUTABLE
            Arguments = $RESTART_COLLECTOR_ARGUMENT
            Delay = $RESTART_COLLECTOR_TIME_DELAY
            User = 'NT AUTHORITY\SYSTEM'
        }

        Set-NexthinkScheduledTask @scheduledTaskArguments
    } else {
        Set-CollectorRestartTaskWindows7
    }
}

function Test-PowerShellVersion ([int]$MinimumVersion) {
    if ((Get-Host).Version.Major -ge $MinimumVersion) {
        return $true
    }
}

function Set-NexthinkScheduledTask ([string]$TaskName, [string]$ProgramOrScript, [string]$Arguments, [int]$DelayInSeconds, [string]$User) {
    $scheduledTaskAction = New-ScheduledTaskAction -Execute $ProgramOrScript -Argument $Arguments
    $scheduledTaskTrigger = Set-TriggerForScheduledTask -Delay $DelayInSeconds
    $scheduledTaskSettings = New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter '00:00:00' -AllowStartIfOnBatteries:$true -DontStopIfGoingOnBatteries:$true
    $scheduledTaskPrincipal = New-ScheduledTaskPrincipal -UserID $User
    $scheduledTaskArguments = @{
        TaskName = $TaskName
        Action = $scheduledTaskAction
        Trigger = $scheduledTaskTrigger
        Settings = $scheduledTaskSettings
        Principal = $scheduledTaskPrincipal
        Force = $true
    }

    Register-ScheduledTask @scheduledTaskArguments | Out-Null
}

function Set-TriggerForScheduledTask ([int]$Delay) {
    $currentDate = (Get-Date).AddSeconds($Delay)
    $expirationTime = $currentDate.AddMinutes(1).ToString('s')
    $scheduledTaskTrigger = New-ScheduledTaskTrigger -Once -At $currentDate
    $scheduledTaskTrigger.EndBoundary = $expirationTime

    return $scheduledTaskTrigger
}

function Set-CollectorRestartTaskWindows7 {

    $arguments = Get-ScheduledTaskArguments -Name $RESTART_COLLECTOR_TASK_NAME `
                                            -Delay $RESTART_COLLECTOR_TIME_DELAY `
                                            -Action 'C:\Windows\System32\nxtcfg.exe /restart'
    $executionOutput = Invoke-Process -FilePath $TASK_SCHEDULER_EXE -Arguments $arguments

    if (-not [string]::IsNullOrEmpty($executionOutput.StdErr)) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Scheduled task creation was unsuccessful with exit code $($executionOutput.ExitCode) and message $($executionOutput.StdErr)"
    }
}

function Get-ScheduledTaskArguments ([string]$Name, [int]$Delay, [string]$Action) {
    $startTime = "{0:HH:mm:ss}" -f (Get-Date).AddSeconds($Delay)
    return @('/Create'
             '/SC Once'
             '/RU "SYSTEM"'
             "/TN `"$($Name)`""
             '/Z'
             '/V1'
             "/TR `"$($Action)`""
             "/ST `"$($startTime)`""
             '/F'
            ) -join ' '
}

function Edit-StringListResult ([string[]]$StringList) {
    return $(if ($StringList.Count -gt 0) { $StringList } else { '-' })
}

#
# Input parameter validation
#

function Test-InputParameters ([hashtable]$InputParameters) {
    Test-AnyParamProvided -Params $InputParameters

    if (Confirm-StringIsNotEmpty -Value $InputParameters.Tag) {
        Test-ParamInAllowedRange -ParamName $COLLECTOR_PARAMETERS_NAME.Tag `
                                 -ParamValue $InputParameters.Tag `
                                 -LowerLimit 0 `
                                 -UpperLimit ([int]::MaxValue)
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.LogMode) {
        Test-ParamInAllowedRange -ParamName $COLLECTOR_PARAMETERS_NAME.LogMode `
                                 -ParamValue $InputParameters.LogMode `
                                 -LowerLimit 0 `
                                 -UpperLimit 2
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.IOPS) {
        Test-ParamInAllowedRange -ParamName $COLLECTOR_PARAMETERS_NAME.IOPS `
                                 -ParamValue $InputParameters.IOPS `
                                 -LowerLimit 0 `
                                 -UpperLimit 1
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.PKGInterval) {
        Test-ParamInAllowedRange -ParamName $COLLECTOR_PARAMETERS_NAME.PKGInterval `
                                 -ParamValue $InputParameters.PKGInterval `
                                 -LowerLimit 0 `
                                 -UpperLimit 24
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.AppStartTime) {
        Test-StringSet -ParamName $COLLECTOR_PARAMETERS_NAME.AppStartTime `
                       -ParamValue $InputParameters.AppStartTime `
                       -ValidValues $VALID_STRING_0_OR_1_VALUES
        if ($InputParameters.AppStartTime -eq $APP_START_TIME_ENABLED_VALUE) {
            Test-AppStartTimeWhiteListParam -ParamName $COLLECTOR_PARAMETERS_NAME.AppStartTimeWhitelist `
                                            -ParamValue $InputParameters.AppStartTimeWhitelist
        }
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.Printing) {
        Test-StringSet -ParamName $COLLECTOR_PARAMETERS_NAME.Printing `
                       -ParamValue $InputParameters.Printing `
                       -ValidValues $VALID_STRING_ENABLE_OR_DISABLE_VALUES
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.WMDomains) {
        Test-WMDomains -WMDomains $InputParameters.WMDomains
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.WindowFocusTimeMonitoring) {
        Test-StringSet -ParamName $COLLECTOR_PARAMETERS_NAME.WindowFocusTimeMonitoring `
                       -ParamValue $InputParameters.WindowFocusTimeMonitoring `
                       -ValidValues $VALID_STRING_0_OR_1_VALUES
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.UserInteractionTimeMonitoring) {
        Test-StringSet -ParamName $COLLECTOR_PARAMETERS_NAME.UserInteractionTimeMonitoring `
                       -ParamValue $InputParameters.UserInteractionTimeMonitoring `
                       -ValidValues $VALID_STRING_0_OR_1_VALUES
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.AnonymizeUserName) {
        Test-StringSet -ParamName $COLLECTOR_PARAMETERS_NAME.AnonymizeUserName `
                       -ParamValue $InputParameters.AnonymizeUserName `
                       -ValidValues $VALID_STRING_0_OR_1_VALUES
    }

    if (Confirm-StringIsNotEmpty -Value $InputParameters.AnonymizeWifiNetwork) {
        Test-StringSet -ParamName $COLLECTOR_PARAMETERS_NAME.AnonymizeWifiNetwork `
                       -ParamValue $InputParameters.AnonymizeWifiNetwork `
                       -ValidValues $VALID_STRING_0_OR_1_VALUES
    }
}

function Test-AnyParamProvided ([hashtable]$Params) {
    $emptyCount = 0
    foreach ($key in $Params.Keys) {
        $emptyCount += [int](-not (Confirm-StringIsNotEmpty -Value $Params.$key))
    }

    if ($emptyCount -eq $Params.Count) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) At least one input parameter must be provided. "
    }
}

function Test-AppStartTimeWhiteListParam ([string]$ParamName, [string]$ParamValue) {
    Test-StringNullOrEmpty -ParamName $ParamName -ParamValue $ParamValue

    if ($ParamValue -match $APP_WHITELIST_FORBIDDEN_CHARACTERS) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Invalid value in '$ParamName' input parameter: It contains forbidden character(s). Please check this Remote Action's documentation for more details. "
    }
}

function Test-WMDomains ([string]$WMDomains) {
    if ($WMDomains -NotMatch '^[,a-zA-Z0-9\.\-\:/\*]*$') {
        throw "$($ERROR_EXCEPTION_TYPE.Input) WMDomains must be a comma-separated list of strings. "
    }
}

#
# Collector management
#
function Set-ToolsPath {
    if (Test-WOW6432Process) {
        $systemPath = "Sysnative"
    } else {
        $systemPath = "System32"
    }

    New-Variable -Name 'COLLECTOR_CONFIG_TOOL_EXE' `
        -Value "$env:SYSTEMROOT\$systemPath\nxtcfg.exe" `
        -Option ReadOnly -Scope Script -Force
    New-Variable -Name 'TASK_SCHEDULER_EXE' `
        -Value "$env:SystemRoot\$systemPath\schtasks.exe" `
        -Option ReadOnly -Scope Script -Force
}

function Test-CollectorVersion {
    if (-not (Test-RegistryKeyProperty -Key $COLLECTOR_REG_KEY `
                                       -Property $COLLECTOR_REG_VERSION)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Collector not installed. "
    }

    $collectorVersion = (Get-RegistryKeyProperty -Key $COLLECTOR_REG_KEY `
                                                 -Property $COLLECTOR_REG_VERSION) -as [version]
    if (-not ($collectorVersion)) { throw "$($ERROR_EXCEPTION_TYPE.Environment) Wrong value for Collector version. " }

    return $collectorVersion
}

function Initialize-CollectorParameters ([hashtable]$ScriptParams, [version]$CollectorVersion) {
    $parameters = @{}
    $parametersNotAvailable = @()

    Initialize-CollectorParameter -Name $COLLECTOR_PARAMETERS_NAME.Tag -Key $COLLECTOR_PARAMETERS_NON_REGKEY_KEYS.Tag `
                                  -Value $ScriptParams.Tag `
                                  -RestartRequired ([restartrequired]::No.value__) `
                                  -Parameters $parameters

    Initialize-CollectorParameter -Name $COLLECTOR_PARAMETERS_NAME.LogMode -Key $COLLECTOR_PARAMETERS_NON_REGKEY_KEYS.LogMode `
                                  -Value $ScriptParams.LogMode `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters

    Initialize-CollectorParameter -Name $COLLECTOR_PARAMETERS_NAME.WMDomains -Key $COLLECTOR_PARAMETERS_NON_REGKEY_KEYS.WMDomains `
                                  -Value $ScriptParams.WMDomains `
                                  -RestartRequired ([restartrequired]::No.value__) `
                                  -Parameters $parameters

    Initialize-CollectorParameter -Name $COLLECTOR_PARAMETERS_NAME.IOPS -Key $COLLECTOR_PARAMETERS_NON_REGKEY_KEYS.IOPS `
                                  -Value $ScriptParams.IOPS `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters

    Initialize-CollectorParameter -Name $COLLECTOR_PARAMETERS_NAME.PKGInterval -Key $COLLECTOR_PARAMETERS_NON_REGKEY_KEYS.PKGInterval `
                                  -Value $ScriptParams.PKGInterval `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.17' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $COLLECTOR_PARAMETERS_NAME.Printing -Key $COLLECTOR_PARAMETERS_NON_REGKEY_KEYS.Printing `
                                  -Value $ScriptParams.Printing `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.18' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $APP_START_TIME_DISABLED_REGKEY_PROP `
                                  -Key $COLLECTOR_APP_START_TIME_REGKEY `
                                  -Value $ScriptParams.AppStartTime `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.27' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $APP_START_TIME_WHITELIST_REGKEY_PROP `
                                  -Key $COLLECTOR_APP_START_TIME_REGKEY `
                                  -Value $ScriptParams.AppStartTimeWhitelist `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.27' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $COLLECTOR_WINDOWS_FOCUS_REGKEY_PROP `
                                  -Key $COLLECTOR_WINDOWS_FOCUS_REGKEY `
                                  -Value $ScriptParams.WindowFocusTimeMonitoring `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.29' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY_PROP `
                                  -Key $COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY `
                                  -Value $ScriptParams.UserInteractionTimeMonitoring `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.30' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $COLLECTOR_ANONYMIZE_USERNAME_REGKEY_PROP `
                                  -Key $COLLECTOR_ANONYMIZE_DATA_REGKEY `
                                  -Value $ScriptParams.AnonymizeUserName `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '6.30' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    Initialize-CollectorParameter -Name $COLLECTOR_ANONYMIZE_WIFI_REGKEY_PROP `
                                  -Key $COLLECTOR_ANONYMIZE_DATA_REGKEY `
                                  -Value $ScriptParams.AnonymizeWifiNetwork `
                                  -RestartRequired ([restartrequired]::Driver.value__) `
                                  -Parameters $parameters `
                                  -MinimumCollectorVersion '21.7' `
                                  -CollectorVersion $CollectorVersion `
                                  -ParametersNotAvailable ([ref]$parametersNotAvailable)

    return @{ParametersToUpdate = $parameters
             ParametersToIgnore = @($parametersNotAvailable)}
}

function Initialize-CollectorParameter ([string]$Name,
                                        [string]$Key,
                                        [string]$Value,
                                        [int]$RestartRequired,
                                        [hashtable]$Parameters,
                                        [version]$MinimumCollectorVersion,
                                        [version]$CollectorVersion,
                                        [ref]$ParametersNotAvailable) {

    if ([string]::IsNullOrEmpty((Format-StringValue -Value $Value))) { return }

    $paramUniqueId = Get-ParamUniqueId -ParamKey $Key -ParamName $Name

    if ($null -ne $MinimumCollectorVersion) {
        if ($CollectorVersion -lt $MinimumCollectorVersion) {
            $ParametersNotAvailable.Value += $paramUniqueId
            return
        }
    }

    $Parameters.$paramUniqueId = @{Name = $Name
                                   Key = $Key
                                   Value = $Value
                                   Restart = $RestartRequired}
}

function Get-ParamUniqueId ([string]$ParamKey, [string]$ParamName) {
    switch ($ParamKey) {
        $COLLECTOR_APP_START_TIME_REGKEY {
            if ($APP_START_TIME_DISABLED_REGKEY_PROP -eq $ParamName) {
                return $COLLECTOR_PARAMETERS_NAME.AppStartTime
            }
            return $COLLECTOR_PARAMETERS_NAME.Whitelist
        }
        $COLLECTOR_WINDOWS_FOCUS_REGKEY { return $COLLECTOR_PARAMETERS_NAME.WindowFocusTimeMonitoring }
        $COLLECTOR_ANONYMIZE_DATA_REGKEY {
            if ($ParamName -eq $COLLECTOR_ANONYMIZE_USERNAME_REGKEY_PROP) {
                return $COLLECTOR_PARAMETERS_NAME.AnonymizeUserName
            }
            return $COLLECTOR_PARAMETERS_NAME.AnonymizeWifiNetwork
        }
        $COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY { return $COLLECTOR_PARAMETERS_NAME.UserInteractionTimeMonitoring }
        default { return $ParamName }
    }
}

function Update-CollectorParameters ([hashtable]$Parameters) {
    if ($null -eq $Parameters -or $Parameters.Count -eq 0) { return }
    [string[]]$argumentList = New-CollectorToolParameters -Parameters $Parameters

    Invoke-CollectorTool -ArgumentList $argumentList

    if (($null -ne $Parameters.AppStartTime) -and ($null -ne $Parameters.Whitelist)) {
        Update-CollectorAppStartTimeSettings -AppStartTime $Parameters.AppStartTime `
                                             -Whitelist $Parameters.Whitelist
    }

    if ($null -ne $Parameters.WindowFocusTimeMonitoring) {
        Update-CollectorConfigurationParameter -Information $Parameters.WindowFocusTimeMonitoring `
                                               -Value $COLLECTOR_WINDOWS_FOCUS_ENABLED_VALUE
    }

    if ($null -ne $Parameters.UserInteractionTimeMonitoring) {
        Update-CollectorConfigurationParameter -Information $Parameters.UserInteractionTimeMonitoring `
                                               -Value $COLLECTOR_USER_INTERACTION_TIME_MONITORING_DISABLED_VALUE
    }

    if ($null -ne $Parameters.AnonymizeUserName) {
        Update-CollectorConfigurationParameter -Information $Parameters.AnonymizeUserName `
                                               -Value $COLLECTOR_ANONYMIZE_DATA_ENABLED_VALUE
    }

    if ($null -ne $Parameters.AnonymizeWifiNetwork) {
        Update-CollectorConfigurationParameter -Information $Parameters.AnonymizeWifiNetwork `
                                               -Value $COLLECTOR_ANONYMIZE_DATA_ENABLED_VALUE
    }

    Restart-NecessaryCollectorServices -Parameters $Parameters
}

function New-CollectorToolParameters ([hashtable]$Parameters) {
    $argumentList = @()
    foreach ($item in $Parameters.Values) {
        if (Test-CollectorConfigItemIsRegistryType -ConfigItemName $item.Name) { continue }

        $argumentList += "{0}={1}" -f $item.Key, $item.Value
    }
    return $argumentList
}

function Test-CollectorConfigItemIsRegistryType ([string]$ConfigItemName) {
    return ($ConfigItemName -eq $APP_START_TIME_DISABLED_REGKEY_PROP -or `
            $ConfigItemName -eq $APP_START_TIME_WHITELIST_REGKEY_PROP -or `
            $ConfigItemName -eq $COLLECTOR_WINDOWS_FOCUS_REGKEY_PROP -or `
            $ConfigItemName -eq $COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY_PROP -or `
            $ConfigItemName -eq $COLLECTOR_ANONYMIZE_USERNAME_REGKEY_PROP -or `
            $ConfigItemName -eq $COLLECTOR_ANONYMIZE_WIFI_REGKEY_PROP)
}

function Invoke-CollectorTool ([string[]]$ArgumentList) {
    if (Test-CollectionNullOrEmpty -Collection $ArgumentList) { return }

    $arguments = "$COLLECTOR_SET_PARAMETER " + ($ArgumentList -join ' ')
    $output = Invoke-Process -FilePath $COLLECTOR_CONFIG_TOOL_EXE -Arguments $arguments

    if ($output.StdOut -notmatch $COLLECTOR_TOOL_SUCCESS_MESSAGE) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Collector tool execution failed. "
    }
}

function Update-CollectorAppStartTimeSettings ([hashtable]$AppStartTime, [hashtable]$Whitelist) {
    Set-RegistryKey -Key $AppStartTime.Key `
                    -Property $AppStartTime.Name `
                    -Type 'DWORD' `
                    -Value $AppStartTime.Value
    if ($AppStartTime.Value -eq $APP_START_TIME_ENABLED_VALUE) {
        Set-RegistryKey -Key $Whitelist.Key `
                        -Property $Whitelist.Name `
                        -Type 'String' `
                        -Value $Whitelist.Value
    }
}

function Update-CollectorConfigurationParameter ([hashtable]$Information, [string]$Value) {
    Remove-RegistryKey -Key $Information.Key
    if ($Information.Value -eq $Value) {
        Set-RegistryKey -Key $Information.Key `
                        -Property $Information.Name `
                        -Type 'DWORD' `
                        -Value $Information.Value
    }
}

function Remove-RegistryKey ([string]$Key) {
    if (Test-Path -Path $Key) {
        Remove-Item -Path $Key -ErrorAction SilentlyContinue
    }
}

function Restart-NecessaryCollectorServices ([hashtable]$Parameters) {
    $restart = Get-ServicesToRestart -Parameters $Parameters

    if ($restart['driver']) { Invoke-CollectorRestart }
}

function Get-ServicesToRestart ([hashtable]$Parameters) {
    $restart = @{'driver' = $false}

    foreach ($name in $Parameters.Keys) {
        $restartValue = $Parameters[$name]['restart']

        if ($restartValue -eq [restartrequired]::Driver.value__) { $restart['driver'] = $true }
    }

    return $restart
}

#
# Print parameters not available
#
function Show-ParametersNotAvailable ([string[]]$ParametersNotAvailable, [version]$CollectorVersion) {
    $output = "Parameter(s) $($ParametersNotAvailable -join ', ')"
    return "$output not available for this Collector version ($CollectorVersion). "
}

function Edit-CollectorToolParameters ([hashtable]$Parameters) {
    [string[]]$outputStringList = @()

    foreach ($item in $Parameters.Values) {
        if (Test-CollectorConfigItemIsRegistryType -ConfigItemName $item.Name) { continue }

        $name = $item.Key
        $outputStringList += "{0}={1}" -f $name, $item.Value
    }

    if (Confirm-StringIsNotEmpty -Value $Parameters.AppStartTime.Value) {
        $name = "AppStartTime ($APP_START_TIME_DISABLED_REGKEY_PROP)"
        $outputStringList += "{0}={1}" -f $name, $Parameters.AppStartTime.Value

        if ($Parameters.AppStartTime.Value -eq $APP_START_TIME_ENABLED_VALUE) {
            $name = "AppStartTime ($APP_START_TIME_WHITELIST_REGKEY_PROP)"
            $outputStringList += "{0}={1}" -f $name, $Parameters.Whitelist.Value
        }
    }

    if (Confirm-StringIsNotEmpty -Value $Parameters.UserInteractionTimeMonitoring.Value) {
        $name = "UserInteractionTimeMonitoring ($COLLECTOR_USER_INTERACTION_TIME_MONITORING_REGKEY_PROP)"
        $outputStringList += "{0}={1}" -f $name, $Parameters.UserInteractionTimeMonitoring.Value
    }

    if (Confirm-StringIsNotEmpty -Value $Parameters.WindowFocusTimeMonitoring.Value) {
        $name = "WindowFocusTimeMonitoring ($COLLECTOR_WINDOWS_FOCUS_REGKEY_PROP)"
        $outputStringList += "{0}={1}" -f $name, $Parameters.WindowFocusTimeMonitoring.Value
    }

    if (Confirm-StringIsNotEmpty -Value $Parameters.AnonymizeUserName.Value) {
        $name = "AnonymizeUserName ($COLLECTOR_ANONYMIZE_USERNAME_REGKEY_PROP)"
        $outputStringList += "{0}={1}" -f $name, $Parameters.AnonymizeUserName.Value
    }

    if (Confirm-StringIsNotEmpty -Value $Parameters.AnonymizeWifiNetwork.Value) {
        $name = "AnonymizeWifiNetwork ($COLLECTOR_ANONYMIZE_WIFI_REGKEY_PROP)"
        $outputStringList += "{0}={1}" -f $name, $Parameters.AnonymizeWifiNetwork.Value
    }

    return $outputStringList
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([string[]]$OutputStringList) {
    [string[]]$output = Edit-StringListResult -StringList $OutputStringList
    [nxt]::WriteOutputStringList('CollectorParametersSet', $output)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

# SIG # Begin signature block
# MIImzwYJKoZIhvcNAQcCoIImwDCCJrwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCN0byI5bmIWyIF
# vutSUrfNL+u7ddwMeiP/Wf9PIZdsg6CCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIU6jCCFOYCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD4/dpJzeQY
# XXQMf02mY97MRZV5GM+lqOkaJufdv19YGjANBgkqhkiG9w0BAQEFAASCAgBjBCj5
# 91KrqsGE3iuuKlyXiA1GIAv34+QVVrM0iwwAiNE8oe4kXaLLaVoiax3NFwFHjTd6
# CcDq8KCbudjWW5SvX3j8kCz3uPnFd1wXJWBCGKPhe9IcelXVu7aoLtHfZ722b4k7
# DbQg9SBO5XSBacpoH1OsbZuAl8ZEGCoHOFA1JiD8MDAkqcoBmJfu2ZGbdae5+k9+
# u2L11ikelOsbYNBGf3FrDDQf5Nj+ek5QKqUPL5FUyR134o1MxTWEzPQ896wLINKL
# GpDMhWurxpB60sobZ4/ntJIOiwAUO2LJzDzHtDpxiDX3ziBmUN8taMwdaHnl1Szy
# uZQkWuewMEWVSx0cFCLvHKVWg1lSGbc/XlN2W1wwk74RbELMayguXU42NOe5/7jD
# EyI2RTGOO21J+e+q64p7DQgqFR947MXMFeKQuhWR8JYeAQgEY6zwPF5S9KBToA2p
# lmCfFGs8N+LaH0D43eo99t66xEUJXAzEEh3aacwrnACQgJiWT9V9d1CQlxlYQ6Bf
# dwK7irtwXKz4P+Uz0CJT3oqaTva/AfVE8QHI+XqpfJx3rSL+dSvCZs4jNHcmQCNa
# gv1/mD4WISzDwGFbqHytCgTJ2W6Pzf8yUMpRQZL0WEQAyxifAKx1aGsCqXkNQxp5
# HP8mKbB9BLvhdymN0j0U+9XttNXixBO60adflaGCEbMwghGvBgorBgEEAYI3AwMB
# MYIRnzCCEZsGCSqGSIb3DQEHAqCCEYwwghGIAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCCyRrzV8NZ+QbHUmlA0BxXJD77+fYZTSVnKVsX9YZyrGAIRAIlJJvYR++/U
# j7tiFk+GZq4YDzIwMjIwNDI2MTY1MTI2WqCCDXwwggbGMIIErqADAgECAhAKekqI
# nsmZQpAGYzhNhpedMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBH
# NCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwMzI5MDAwMDAw
# WhcNMzMwMzE0MjM1OTU5WjBMMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALkqliOmXLxf1knwFYIY9DPu
# zFxs4+AlLtIx5DxArvurxON4XX5cNur1JY1Do4HrOGP5PIhp3jzSMFENMQe6Rm7p
# o0tI6IlBfw2y1vmE8Zg+C78KhBJxbKFiJgHTzsNs/aw7ftwqHKm9MMYW2Nq867Lx
# g9GfzQnFuUFqRUIjQVr4YNNlLD5+Xr2Wp/D8sfT0KM9CeR87x5MHaGjlRDRSXw9Q
# 3tRZLER0wDJHGVvimC6P0Mo//8ZnzzyTlU6E6XYYmJkRFMUrDKAz200kheiClOEv
# A+5/hQLJhuHVGBS3BEXz4Di9or16cZjsFef9LuzSmwCKrB2NO4Bo/tBZmCbO4O2u
# fyguwp7gC0vICNEyu4P6IzzZ/9KMu/dDI9/nw1oFYn5wLOUrsj1j6siugSBrQ4nI
# fl+wGt0ZvZ90QQqvuY4J03ShL7BUdsGQT5TshmH/2xEvkgMwzjC3iw9dRLNDHSNQ
# zZHXL537/M2xwafEDsTvQD4ZOgLUMalpoEn5deGb6GjkagyP6+SxIXuGZ1h+fx/o
# K+QUshbWgaHK2jCQa+5vdcCwNiayCDv/vb5/bBMY38ZtpHlJrYt/YYcFaPfUcONC
# leieu5tLsuK2QT3nr6caKMmtYbCgQRgZTu1Hm2GV7T4LYVrqPnqYklHNP8lE54CL
# KUJy93my3YTqJ+7+fXprAgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFI1kt4kh/lZYRIRhp+pvHDaP3a8NMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAA0tI3Sm0fX46kuZPwHk9gzkrxad2bOMl4IpnENvAS2rOLVwEb+EGYs/
# XeWGT76TOt4qOVo5TtiEWaW8G5iq6Gzv0UhpGThbz4k5HXBw2U7fIyJs1d/2Wcuh
# wupMdsqh3KErlribVakaa33R9QIJT4LWpXOIxJiA3+5JlbezzMWn7g7h7x44ip/v
# EckxSli23zh8y/pc9+RTv24KfH7X3pjVKWWJD6KcwGX0ASJlx+pedKZbNZJQfPQX
# podkTz5GiRZjIGvL8nvQNeNKcEiptucdYL0EIhUlcAZyqUQ7aUcR0+7px6A+TxC5
# MDbk86ppCaiLfmSiZZQR+24y8fW7OK3NwJMR1TJ4Sks3KkzzXNy2hcC7cDBVeNaY
# /lRtf3GpSBp43UZ3Lht6wDOK+EoojBKoc88t+dMj8p4Z4A2UKKDr2xpRoJWCjihr
# pM6ddt6pc6pIallDrl/q+A8GQp3fBmiW/iqgdFtjZt5rLLh4qk1wbfAs8QcVfjW0
# 5rUMopml1xVrNQ6F1uAszOAMJLh8UgsemXzvyMjFjFhpr6s94c/MfRWuFL+Kcd/K
# l7HYR+ocheBFThIcFClYzG/Tf8u+wQ5KbyCcrtlzMlkI5y2SoRoR/jKYpl0rl+CL
# 05zMbbUNrkdjOEcXW28T2moQbh9Jt0RbtAgKh1pZBHYRoad3AhMcMIIGrjCCBJag
# AwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjIw
# MzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0ZWQgRzQg
# UlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPRnkyibaCw
# zIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1DtITaEfFz
# sbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8GZY2UKdPZ
# 7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQLIWhuNyG7
# QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1WE15/teP
# c5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7dW4nJZCY
# OjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAoq3NDzt9K
# oRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9/g64ZCr6
# dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45wPmyMKVM
# 1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj4KbhPvbC
# dLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM0jO0zbEC
# AwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLoW2W1N
# hS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9P
# MA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcB
# AQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggr
# BgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAI
# BgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9WY7Ak7Zv
# mKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHPHQfpPmDI
# 2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6VaT9Hd/ty
# dBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAKfO+ovHVP
# ulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr9p6xeZmB
# o1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5d2aR8XKc
# 6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA0LcTJM3c
# HXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjpnOHdI/0d
# KNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/mADfIBZP
# J/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX2bwE+oLe
# Mt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVUKx+A+sDy
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DGCA3YwggNyAgEBMHcwYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQCnpK
# iJ7JmUKQBmM4TYaXnTANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIyMDQyNjE2NTEyNlowKwYLKoZI
# hvcNAQkQAgwxHDAaMBgwFgQUhQjzhlFcs9MHfba0t8B/G0peQd4wLwYJKoZIhvcN
# AQkEMSIEIM89K61ZntNS8f8mO788Xk50UIfynrJj87zYIErWQt3jMDcGCyqGSIb3
# DQEJEAIvMSgwJjAkMCIEIJ2mkBXDScbBiXhFujWCrXDIj6QpO9tqvpwr0lOSeeY7
# MA0GCSqGSIb3DQEBAQUABIICAC2rFF0eT5oa/PbEXf+mJYQ4yC/p+GA6Sc6uWyTy
# gRJferXz0jJrh/A6s0JF7tmBUdm12SvzdlcAWzBFPQZrS6Y0UZcKrQ/5w2O0HlBw
# eA+FA4uf5JoQkgOPQwanRb+9X3cGLwUVQieGK9kvClCD2bO2DLCw3mxVDteeGIvt
# gdUhCcg/uyS2YxXRi6mDxznq5vNSXlQrEn6hVm1mmzj233SFnQtQDOAF0RS/NMkQ
# mojECu8FsrcF/z0P1Cl936MjilAgi16zz37TnkM+HF4U1m2jwdXagCg5iRPfkgZP
# HyfocayCxtbVDeJtCQ2aKi7ScEMrivWwol8i6JO80x5fzf/M+8Z01EzVMWwxAvgp
# hFhZSy+AfPtSHNvCEcpPd2FWMAItcMbIFRvNpsJuwRjQ7mkF9Dw2so7as/JscLTp
# ma7vzqTsy6F6RdTJmaYXyrGetSXdEo30yr/7dfteRHQ/4Lz5q9giePJUySshUXMV
# egd8lOrmf4Kwdaep06eMud6pwfheqlVATh/FSUpwO3ADc2Y2JJE90OcRj/Heq/NO
# ZX8Q7uqP6YULHgBR+Bm77zu4cJXiUsqf9EeejiXTE4dpR33dvxxRJuxd71NqhsRz
# 6cgtSXUNB0ONJTUmVO4SdkwnJltEq2+gIS5yak4QNVoEgN+aergyffQZSzCOlfsP
# 6LDQ
# SIG # End signature block
