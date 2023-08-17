<#
.SYNOPSIS
Verifies if device requires restart and triggers campaign to allow user control over the process.

.DESCRIPTION
Retrieves information if restart is necessary due to too long device uptime or pending reboot, and based on provided input configures restart of target device. Campaign is displayed to enable user immediate restart, or postpone till next script execution. After restart, previously opened user's applications are restored.

'''''Warning:''' The 'Device Restart' Remote Action restarts devices based on the provided input parameters. Avoid choosing parameters that cause users to be regularly prompted, or forced, to restart their device.''

.FUNCTIONALITY
Remediation

.INPUTS
ID  Label                           Description
1   NumberOfDaysSinceLastReboot     Number of days considered as maximum allowed without device restart. Accepted values are (0-60)
2   TestPendingRestart              Test if a reboot is needed. Accepted values are (True/False)
3   ShowCampaign                    Determines under what circumstances the campaign should be shown. Accepted values are (Always/DuringGracePeriod/OnlyFirstExecution/Never)
4   CampaignId                      Id of a campaign to be presented to user before triggering restart
5   PostponeGracePeriodInDays       Number of days provided for user to postpone campaign, verified with hourly precision. Once due date is passed, restart will be scheduled. Accepted values are (1-30)
6   RestartDelayInSeconds           Number of seconds provided as delay before restart is executed. Accepted values are (45-86400)

.FURTHER INFORMATION
For a deeper understanding of the usage of this Remote Action, read the official Nexthink Documentation [https://doc.nexthink.com/Documentation/Nexthink/latest/LibraryPacksConfiguration/RestartDevice here].


'''ShowCampaign''' input parameter behaviour:

- ''Always'' - The campaign is always shown to the user, and the user can decide if he wants to restart the device (Yes, restart) or if he wants to postpone the campaign (Postpone).

- ''Never'' - The campaign is never shown to the user. The device is restarted using the "RestartDelayInSeconds" input parameter. For e.g., if "RestartDelayInSeconds" is set to 300, once the RA is triggered on the device, the device is will restart after 300 seconds.

- ''OnlyFirstExecution'' - The campaign is shown only one time to the user, and the user can decide if he wants to restart the device (Yes, restart), or if he wants to postpone the campaign (Postpone). If the user decides to postpone the campaign, and the RA gets triggered another time on the device, this latter will be restarted using the "RestartDelayInSeconds" input parameter.

- ''DuringGracePeriod'' - If we use this parameter, the RA is going to take into account the ''PostponeGracePeriodInDays''. It means that if we use 7 days as ''PostponeGracePeriodInDays'', the campaign is shown during 7 days to the user. If the user restarts the device in the meantime, the counter is reset and the campaign is not shown anymore. But if the user does not restart the device during the 7 days of grace period, the device will be restarted on the 8th day using the ''RestartDelayInSeconds'' input.


'''Clarification''' - Postpone button in the campaign does not postpone the restart. It only postpones the campaign i.e. the user could receive the campaign again if the configuration allows it, but the '''restart is not postponed'''.

.NOTES
Context:            InteractiveUser
Version:            3.2.2.0 - Enhanced documentation and fixed PATH vulnerability
                    3.2.1.0 - Fixing RA UID problem due to the same name of macOS Remote Action
                    3.2.0.0 - Updated description
                    3.1.0.0 - Fixed logic to evaluate pending restarts and modified input parameter name 'DeviceUptimeInDays' to 'NumberOfDaysSinceLastReboot'
                    3.0.2.0 - Fixed input TestPendingRestart logic
                    3.0.1.0 - Fixed problem with date format
                    3.0.0.0 - Added "Test Pending Reboot" features and renamed an input parameter
                    2.1.0.0 - Added Nexthink Documentation link to Nexthink Library page
                    2.0.0.0 - Reworked input parameters to enable flexible configuration of presenting campaign
                    1.0.1.0 - Fixed documentation
                    1.0.0.0 - Initial release
Last Generated:     13 May 2022 - 10:36:26
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$NumberOfDaysSinceLastReboot,
    [Parameter(Mandatory = $true)][string]$TestPendingRestart,
    [Parameter(Mandatory = $true)][string]$ShowCampaign,
    [Parameter(Mandatory = $true)][string]$CampaignId,
    [Parameter(Mandatory = $true)][string]$PostponeGracePeriodInDays,
    [Parameter(Mandatory = $true)][string]$RestartDelayInSeconds
)
# End of parameters definition

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"

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

New-Variable -Name 'MIN_UPTIME_DAYS' -Value 0 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MAX_UPTIME_DAYS' -Value 60 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MIN_RESTART_DELAY_SECONDS' -Value 45 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MAX_RESTART_DELAY_SECONDS' -Value 86400 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MIN_POSTPONE_DAYS' -Value 1 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MAX_POSTPONE_DAYS' -Value 30 `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'RA_ALREADY_EXECUTED_REG_KEY' `
    -Value 'HKCU:\Software\Nexthink\Act\RestartDevice' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'RA_ALREADY_EXECUTED_REG_PROPERTY' `
    -Value 'RestartScriptExecuted' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SOFTWARE_INSTALLATION_REG_KEY' `
    -Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'WINDOWS_UPDATE_REG_KEY' `
    -Value 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'JOIN_DOMAIN_REG_KEY' `
    -Value 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'JOIN_DOMAIN_REG_VALUE' `
    -Value 'JoinDomain' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'JOIN_DOMAIN_SPN_REG_VALUE' `
    -Value 'AvoidSpnSet' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'COMPUTER_NAME_REG_KEY' `
    -Value 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'COMPUTER_NAME_REG_VALUE' -Value 'ComputerName' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'ACTIVE_COMPUTER_NAME_REG_KEY' `
    -Value 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SCCM_WMI_NAMESPACE' `
    -Value 'ROOT\ccm\ClientSDK' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_WMI_CLASS' `
    -Value 'CCM_ClientUtilities' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'SCCM_WMI_NAME' `
    -Value 'DetermineIfRebootPending' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SHUTDOWN_EXE' `
    -Value "$env:SystemRoot\System32\shutdown.exe" `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'SHOW_CAMPAIGN' `
    -Value @{Always = 'Always'
             DuringGracePeriod = 'DuringGracePeriod'
             Never = 'Never'
             OnlyFirstExecution = 'OnlyFirstExecution'} `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    try {
        Add-NexthinkCampaignDLL
        Test-RunningAsInteractiveUser
        Test-SupportedOSVersion
        Test-InputParameters -InputParameters $InputParameters

        Invoke-DeviceRestart -InputParameters $InputParameters
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

function Test-RunningAsInteractiveUser {

    if (Confirm-CurrentUserIsLocalSystem) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script must be run as InteractiveUser. "
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

function Test-BooleanParameter ([string]$ParamName, [string]$ParamValue) {
    $value = $ParamValue.ToLower()
    if ($value -ne 'true' -and $value -ne 'false') {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It must be 'true' or 'false'. "
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

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Test-GUIDParameter ([string]$ParamName, [string]$ParamValue) {
    if (-not ($ParamValue -as [guid])) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. Only UID values are accepted. "
    }
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

function Test-WOW6432Process {

    return (Test-Path Env:\PROCESSOR_ARCHITEW6432)
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

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-ForbiddenParameterCombination -InputParameters $InputParameters
    Test-ParamInAllowedRange `
        -ParamName 'NumberOfDaysSinceLastReboot' `
        -ParamValue $InputParameters.NumberOfDaysSinceLastReboot `
        -LowerLimit $MIN_UPTIME_DAYS `
        -UpperLimit $MAX_UPTIME_DAYS
    Test-ParamInAllowedRange `
        -ParamName 'RestartDelayInSeconds' `
        -ParamValue $InputParameters.RestartDelayInSeconds `
        -LowerLimit $MIN_RESTART_DELAY_SECONDS `
        -UpperLimit $MAX_RESTART_DELAY_SECONDS
    Test-ParamInAllowedRange `
        -ParamName 'PostponeGracePeriodInDays' `
        -ParamValue $InputParameters.PostponeGracePeriodInDays `
        -LowerLimit $MIN_POSTPONE_DAYS `
        -UpperLimit $MAX_POSTPONE_DAYS
    Test-BooleanParameter `
        -ParamName 'TestPendingRestart' `
        -ParamValue $InputParameters.TestPendingRestart
    Test-StringSet `
        -ParamName 'ShowCampaign' `
        -ParamValue $InputParameters.ShowCampaign `
        -ValidValues $SHOW_CAMPAIGN.Keys
    Test-IsValidCampaignParameter `
        -ParamName 'CampaignId' `
        -ParamValue $InputParameters.CampaignId
}

function Test-ForbiddenParameterCombination ([hashtable]$InputParameters) {
    if ($InputParameters.ShowCampaign -ne 'Never' -and `
        ([string]::IsNullOrEmpty((Format-StringValue -Value $InputParameters.CampaignId)) -or `
        $InputParameters.CampaignId -eq [guid]::Empty.Guid)) {
        throw 'Parameter CampaignId cannot be empty or empty guid value. '
    }
}

function Test-IsValidCampaignParameter ([string]$ParamName, [string]$ParamValue) {
    $string = Format-StringValue -Value $ParamValue
    if ([string]::IsNullOrEmpty($string)) { return }

    Test-GUIDParameter -ParamName $ParamName -ParamValue $string
}

#
# Campaign management
#
function Invoke-Campaign ([string]$CampaignId, [int]$Delay) {
    $response = Get-CampaignResponse -CampaignId $CampaignId
    $status = Get-CampaignResponseStatus -Response $response

    switch ($status) {
        'fully' {
            $answer = Get-CampaignResponseAnswer -Response $response -QuestionName 'Restart Device'
            if ($answer -eq 'Postpone') {
                Invoke-UserPostponeAction
                return
            }
            Invoke-DeviceRestartWithDelay -Delay $Delay
        }
        'timeout' { throw 'Timeout on getting an answer from the user. ' }
        { $_ -eq 'postponed' -or $_ -eq 'declined' } { Invoke-UserPostponeAction }
        'connectionfailed' { throw 'Unable to connect to the Collector component that controls campaign notifications. ' }
        'notificationfailed' { throw 'Unable to notify the Collector component that controls campaign notifications. ' }
        default { throw "Failed to handle campaign response: $response. " }
    }
}

#
# Restart management
#
function Invoke-DeviceRestart ([hashtable]$InputParameters) {
    if (-not (Test-RestartIsRequired -Uptime $InputParameters.NumberOfDaysSinceLastReboot `
                                     -TestPendingRestart ([bool]::Parse($InputParameters.TestPendingRestart)))) {
        Remove-AlreadyExecutedRegistry
        return
    }

    if (Test-CampaignShouldBeDisplayed -InputParameters $InputParameters) {
        Invoke-Campaign -CampaignId $InputParameters.CampaignId `
                        -Delay $InputParameters.RestartDelayInSeconds
        return
    }

    Invoke-DeviceRestartWithDelay -Delay $InputParameters.RestartDelayInSeconds
    Remove-AlreadyExecutedRegistry
}

function Test-RestartIsRequired ([int]$Uptime, [bool]$TestPendingRestart) {
    if (Test-DeviceUptimeExpired -NumberOfDaysSinceLastReboot $Uptime) { return $true }
    if ($TestPendingRestart -and (Test-PendingRestart)) { return $true }

    Write-StatusMessage -Message 'Restart was not needed. '
    return $false
}

function Test-DeviceUptimeExpired ([int]$NumberOfDaysSinceLastReboot) {
    if ($NumberOfDaysSinceLastReboot -eq 0) { return $true }

    $today = Get-Date
    $deviceInfo = Get-WmiObject -Class Win32_OperatingSystem
    $restartDate = $deviceInfo.ConvertToDateTime($deviceInfo.LastBootUpTime)

    return [math]::Truncate(($today - $restartDate).TotalHours) -gt ($NumberOfDaysSinceLastReboot * 24)
}

function Test-PendingRestart {
    return (Test-SoftwareInstallation) -or `
           (Test-PendingHotfixInstallation) -or `
           (Test-DomainJoined) -or `
           (Test-ComputerRenaming) -or `
           (Test-SCCMReboot)
}

function Test-SoftwareInstallation {
    return $null -ne (Get-Item -Path $SOFTWARE_INSTALLATION_REG_KEY -ErrorAction SilentlyContinue)
}

function Test-PendingHotfixInstallation {
    return $null -ne (Get-Item -Path $WINDOWS_UPDATE_REG_KEY -ErrorAction SilentlyContinue)
}

function Test-DomainJoined {
    return (Test-RegistryKeyProperty -Key $JOIN_DOMAIN_REG_KEY `
                                     -Property $JOIN_DOMAIN_REG_VALUE) -or `
           (Test-RegistryKeyProperty -Key $JOIN_DOMAIN_REG_KEY `
                                     -Property $JOIN_DOMAIN_SPN_REG_VALUE)
}

function Test-ComputerRenaming {
    if (-not (Test-RegistryKeyProperty -Key $COMPUTER_NAME_REG_KEY `
                                       -Property $COMPUTER_NAME_REG_VALUE)) {
        Write-StatusMessage -Message "$COMPUTER_NAME_REG_KEY\$COMPUTER_NAME_REG_VALUE registry missing. "
        return $false
    }

    if (-not (Test-RegistryKeyProperty -Key $ACTIVE_COMPUTER_NAME_REG_KEY `
                                       -Property $COMPUTER_NAME_REG_VALUE)) {
        Write-StatusMessage -Message "$ACTIVE_COMPUTER_NAME_REG_KEY\$COMPUTER_NAME_REG_VALUE registry missing. "
        return $false
    }

    $computerName = Get-RegistryKeyProperty -Key $COMPUTER_NAME_REG_KEY `
                                            -Property $COMPUTER_NAME_REG_VALUE
    $activeComputerName = Get-RegistryKeyProperty -Key $ACTIVE_COMPUTER_NAME_REG_KEY `
                                                  -Property $COMPUTER_NAME_REG_VALUE

    return $computerName -ne $activeComputerName
}

function Test-SCCMReboot {
    $wmiMethod = Invoke-WmiMethod -Namespace $SCCM_WMI_NAMESPACE `
                                  -Class $SCCM_WMI_CLASS `
                                  -Name $SCCM_WMI_NAME `
                                  -ErrorAction SilentlyContinue

    return $wmiMethod.ReturnValue -eq 0 -and `
           ($wmiMethod.RebootPending -or $wmiMethod.IsHardRebootPending)
}

function Remove-AlreadyExecutedRegistry {
    Get-Item -Path $RA_ALREADY_EXECUTED_REG_KEY -ErrorAction SilentlyContinue |
        Remove-Item -Force
}

function Test-CampaignShouldBeDisplayed ([hashtable]$InputParameters) {
    switch ($InputParameters.ShowCampaign) {
        $SHOW_CAMPAIGN.Always { return $true }
        $SHOW_CAMPAIGN.DuringGracePeriod {
            return -not (Test-PostponeGracePeriodExpired -PostponeGracePeriodInDays $InputParameters.PostponeGracePeriodInDays)
        }
        $SHOW_CAMPAIGN.OnlyFirstExecution { return Test-IsFirstExecution }
        $SHOW_CAMPAIGN.Never { return $false }
    }
}

function Test-PostponeGracePeriodExpired ([int]$PostponeGracePeriodInDays) {
    if (Test-IsFirstExecution) { return $false }
    $firstRun = Get-FirstExecutionDate
    $today = Get-Date

    return [math]::Truncate(($today - $firstRun).TotalHours) -gt ($PostponeGracePeriodInDays * 24)
}

function Test-IsFirstExecution {
    return -not (Test-RegistryKeyProperty -Key $RA_ALREADY_EXECUTED_REG_KEY `
                                          -Property $RA_ALREADY_EXECUTED_REG_PROPERTY)
}

function Get-FirstExecutionDate {
    return [datetime](Get-RegistryKeyProperty -Key $RA_ALREADY_EXECUTED_REG_KEY `
                                              -Property $RA_ALREADY_EXECUTED_REG_PROPERTY)
}

function Invoke-UserPostponeAction {
    Set-AlreadyExecutedRegistry
    Write-StatusMessage -Message 'The user decided to postpone the restart. '
}

function Invoke-DeviceRestartWithDelay ([int]$Delay) {
    [void](Invoke-Process -FilePath $SHUTDOWN_EXE `
                          -Arguments "/g /t $Delay /f")
    Write-StatusMessage -Message 'Restart initiated. '
}

function Set-AlreadyExecutedRegistry {
    if (Test-RegistryKeyProperty -Key $RA_ALREADY_EXECUTED_REG_KEY `
                                 -Property $RA_ALREADY_EXECUTED_REG_PROPERTY) { return }
    Set-RegistryKey -Key $RA_ALREADY_EXECUTED_REG_KEY `
                    -Property $RA_ALREADY_EXECUTED_REG_PROPERTY `
                    -Type 'String' -Value (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

# SIG # Begin signature block
# MIImzgYJKoZIhvcNAQcCoIImvzCCJrsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD4j6YqYqlvdu7u
# rq3Bl/B7G9kcQyaAkcVXDjdwa1Ffn6CCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIU6TCCFOUCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC2Ni89KQdB
# Q1B0ggc0uOsuJA3pamb1pinOOiQYxoKBGDANBgkqhkiG9w0BAQEFAASCAgA5pDON
# w5eGZLenYSnRgienv5sT7kBZSNUqlJW4IexkLmUmTM6SxoikfsztyH5iaBFhVnqb
# ZRyzTlGFd6+67vbWklIlDS70h+gzqIuLE5hW+zN/06pQ2u4qPlBiG5Qlk3538e0M
# yJRKKWWFkWNrCgQb2QIHcA+r6huqRQEBN79NuZVwEBE+Xaqnq+vSNsg4hnjGJzJC
# /p+ypLSj0cHbD8/Pm1usYdvlb/Z+i4y0jbZvH4xlGfY8BTpT9NqttXBVG9zYtfuu
# hu9PpgU5JEGJlf4Cb6oetKrJ10+W84LJn5/83D+LEcE7FToMeZq9Jblz47n29Dul
# R+gIxL4DFbjN0wfB7UAk2PpszksYndFQZ7sPDcilTX/HaoJP+5V4YwjHfS4LPLVp
# W1Tumm6hlm3DyjuCpQ8tRBSCSMx9rRfzj+gSLwRUdWif0Q7ITuy62ZrKgM0KyyhP
# u1JJENMxYhmK0+D+BrYxuyf3WpCCnkIcX0YhGghtvEJpxH9Nss7jkZf7keCLBmVL
# Xd6Z4MCO3+AzCj7p735VRKL2eAY3pF5mpT+6nNwR6vwIN/ZoS+0809L8cmqPqioX
# fBIMhCUOoTteGzmUKdcQeAh531YN5/Y71BNp3r6LQ1tFelX0sKQge0gLwM/j6CKZ
# Aenj8zkZQLRNq4QoBJz34f7PmfD4Wn2DqGVJwaGCEbIwghGuBgorBgEEAYI3AwMB
# MYIRnjCCEZoGCSqGSIb3DQEHAqCCEYswghGHAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCCaS0fShpyO9PgsPYELG7Oy9CE4vNQhcTqM1jJvyVXA4gIQUTxpiCb/I9SY
# 71bvddltrBgPMjAyMjA1MTMwODM2MzJaoIINfDCCBsYwggSuoAMCAQICEAp6Soie
# yZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0
# IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAwMDBa
# Fw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAyMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0M+7M
# XGzj4CUu0jHkPECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pGbumj
# S0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzrsvGD
# 0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJfD1De
# 1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU4S8D
# 7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g7a5/
# KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtDich+
# X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0MdI1DN
# kdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/H+gr
# 5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw40KV
# 6J67m0uy4rZBPeevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTngIsp
# QnL3ebLdhOon7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAMBgNV
# HRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcwCAYG
# Z4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91jGog
# j57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMwUTBP
# oE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEEgYMw
# gYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggrBgEF
# BQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0BAQsF
# AAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZiz9d
# 5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZy6HC
# 6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiKn+8R
# yTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB89Bem
# h2RPPkaJFmMga8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5PELkw
# NuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV41pj+
# VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKOKGuk
# zp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+NbTm
# tQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px38qX
# sdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX4IvT
# nMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwwggauMIIElqAD
# AgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMjAz
# MjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3RlZCBHNCBS
# U0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdRodbSg9GeTKJtoLDM
# g/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhXqAJ9/UO0hNoR8XOx
# s+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69OxtXXnHwZljZQp09ns
# ad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ3V+0VAshaG43IbtA
# rF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLFuk4fsbVYTXn+149z
# k6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD40NjgHt1biclkJg6
# OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpURK1h0QCirc0PO30qh
# HGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/STKvvmz3+DrhkKvp1
# KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfcYd6T/jnA+bIwpUzX
# 6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31fI7tk42PgpuE+9sJ0
# sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a50g5rmQzSM7TNsQID
# AQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUuhbZbU2F
# L3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08w
# DgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEB
# BGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsG
# AQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAH1ZjsCTtm+Y
# qUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaopafxpwc8dB+k+YMjY
# C+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXONASIlzpVpP0d3+3J0
# FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9nXzQcAp876i8dU+6
# WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4mwbfeKuv2nrF5mYGj
# VoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4cku0+jSbl3ZpHxcpzp
# SwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2QJshIUDQtxMkzdwd
# eDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmHQXh6OOmc4d0j/R0o
# 08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZynDwN7+YAN8gFk8n
# +2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+v6TR81fZvAT6gt4y
# 3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8mJb2VVQrH4D6wPIO
# K+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MYIDdjCCA3ICAQEwdzBjMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0
# IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAKekqI
# nsmZQpAGYzhNhpedMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjIwNTEzMDgzNjMyWjArBgsqhkiG
# 9w0BCRACDDEcMBowGDAWBBSFCPOGUVyz0wd9trS3wH8bSl5B3jAvBgkqhkiG9w0B
# CQQxIgQgtHK5FaH0xuvzgqe7Fq66y1z7CA4AgC7VwHq2tXjc1LkwNwYLKoZIhvcN
# AQkQAi8xKDAmMCQwIgQgnaaQFcNJxsGJeEW6NYKtcMiPpCk722q+nCvSU5J55jsw
# DQYJKoZIhvcNAQEBBQAEggIACxx0l18xi/4KLxXryuzJYdKeuanOrmwktR4mrRpR
# bz0E67FPCCZwmcee3gVWbTfFh51rp9745tey6EIacM0C7XBMFANSesceWO4uA+QL
# zs+ZrorxGbmYYhjmFTrOe9oGTDccsnGWPScI+ms8hEtZ3FJ1+T6Nwpv3MBnWBQad
# x7f/iXA12dO8t4h+WCg8gDjtLJLx51WPqqP2xYGgT9Lcv5T2327N55ePGNe74FiU
# TdPbHfq+RGIz6Xs4OW7znhygDwY1JmyL+VrIyO7b6a+jh5WoUN8MixIcqmVF32nZ
# 7Ww+6s9t0KjIiHslpJjt6yA9RkOJDZ0UWf6dqmTqpvZXEefNjbzq+uH2b/fiI/83
# N+JfCIrYl7Ood3zatGy7VV3Ch/Nc5nUw2CIwICEbkycEQ1vawHp+mnKm9cO1Mc2x
# fgMBzo0M6MIaELyGXgqDC0uGDs/5e20v5jBdbezNjKAQgIzlEeBcQlqjKzVQRPnj
# MPf4lF1kRW62+COByn91Vda3NIbVi7wF4qIqCpLzOeUhiv7FIDgE7IwHbYhFn/ty
# 4JdA7drUI9ZVlh5lbIN9NOk41hpXkyFgajG+F7Zm4Ch8ppmnB/P6iOQS7VWs6ehG
# zXSq34dZwbMaGU9Mr23GcTm9UYrDmfI8Phvr2xrVv8jqFPGKcGs5xXWf7l/pptoi
# OPM=
# SIG # End signature block
