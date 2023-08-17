<#
.SYNOPSIS
Gets information about the speed of the network.

.DESCRIPTION
Gets information about the speed of the network by measuring the Web RTT against an external URL and a business URL. It also checks whether the connection is metered or not.

.FUNCTIONALITY
On-demand

.INPUTS
ID  Label                           Description
1   MaximumDelayInSeconds           Maximum random delay set to avoid network overload. Provide number of seconds lower than 600
2   ExternalURL                     The external URL to be checked the Web RTT against
3   WebRTTThreshold                 The time threshold for the external URL Web RTT
4   BusinessURL                     The URL in the corporate environment to be checked the Web RTT against
5   BusinessWebRTTThreshold         The time threshold for the business URL Web RTT
6   Proxy                           Proxy address to use as a parameter in the Invoke-WebRequest call for the ExternalURL. Leave empty ("") if not needed

.OUTPUTS
ID  Label                           Type            Description
1   LastWebRTTToExternalURL         Millisecond     URL Web RTT of the last execution
2   AverageWebRTTToExternalURL      Millisecond     The average external URL Web RTT measured between all executions within the current day
3   TimesExternalURLAboveWebRTTThresholdInt             All the times that the external URL Web RTT has been above the threshold within the current day
4   LastWebRTTToBusinessURL         Millisecond     Business URL Web RTT of the last execution
5   AverageWebRTTToBusinessURL      Millisecond     The average business URL Web RTT measured between all executions within the current day
6   TimesBusinessURLAboveWebRTTThresholdInt             All the times that the business URL Web RTT has been above the threshold within the current day
7   TypeOfConnection                String          Type of physical connection
8   MeteredConnection               Bool            Whether the connection is metered or unrestricted

.FURTHER INFORMATION
This Remote Action is designed to be executed on physical devices, not VMs. If the connection is made via virtual adapter the Remote Action might fail.
This Remote Action uses Microsoft Windows performance counters (using "Get-Counter" CmdLet) to obtain the currently active physical network adapter in case there is more than one connected. In some cases, the counters might provide empty data and there is a need to run the Remote Action on the affected device(s) again.
The Remote Action stores network speed data for the last 7 days under the following path":" - "%LOCALAPPDATA%\\Nexthink\\NetworkSpeed"
The fields "Average Web RTT to business URL", "Average Web RTT to external URL", "Times business URL above Web RTT threshold" and "Times external URL above Web RTT threshold" are calculated based on the CSV data stored for the same day of the Remote Action execution date, plus the data obtained during current execution.

.NOTES
Context:            InteractiveUser
Version:            2.0.2.1 - Removed the default execution triggers for API and Manual
                    2.0.1.1 - Fixed typo on documentation
                    2.0.1.0 - Updated output datatypes
                    2.0.0.0 - Added input parameter 'Proxy'
                    1.3.1.0 - Enhancement error handling
                    1.3.0.0 - Refactored physical network adapter detection logic to be accurate
                    1.2.0.0 - Improved connection profile matching for better results
                    1.1.2.0 - Fixed 'Get-ProfileInfo' functionality to get the correct profile information
                    1.1.1.1 - Updated default values
                    1.1.1.0 - Changed variable names and allowed execution on devices with virtual adapters
                    1.1.0.0 - Allowed 'ExternalURL' and 'BusinessURL' to be empty  in case just one of them wants to be tested
                    1.0.1.0 - Improved error messages
                    1.0.0.0 - Initial release
Last Generated:     28 Apr 2023 - 17:04:00
Copyright (C) 2023 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$MaximumDelayInSeconds,
    [Parameter(Mandatory = $true)][string]$ExternalURL,
    [Parameter(Mandatory = $true)][string]$WebRTTThreshold,
    [Parameter(Mandatory = $true)][string]$BusinessURL,
    [Parameter(Mandatory = $true)][string]$BusinessWebRTTThreshold,
    [Parameter(Mandatory = $true)][string]$Proxy
)
# End of parameters definition

$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0\"

#
# Constants definition
#
$CSV_DEFAULT_DELIMITER = ';'
Set-Variable -Name 'CSV_DEFAULT_DELIMITER' -Option ReadOnly -Scope Script -Force

$CSV_DEFAULT_ENCODING = 'UTF8'
Set-Variable -Name 'CSV_DEFAULT_ENCODING' -Option ReadOnly -Scope Script -Force

$CSV_TIMESTAMP_FIELD_NAME = 'Timestamp'
Set-Variable -Name 'CSV_TIMESTAMP_FIELD_NAME' -Option ReadOnly -Scope Script -Force

$DATE_ONLY_FORMAT_DASHES = 'dd-MM-yyyy'
Set-Variable -Name 'DATE_ONLY_FORMAT_DASHES' -Option ReadOnly -Scope Script -Force

$DATE_TIME_FORMAT_DASHES = 'dd-MM-yyyy HH:mm:ss.fff'
Set-Variable -Name 'DATE_TIME_FORMAT_DASHES' -Option ReadOnly -Scope Script -Force

$ERROR_EXCEPTION_TYPE = @{Environment = '[Environment error]'
    Input = '[Input error]'
    Internal = '[Internal error]'
}
Set-Variable -Name 'ERROR_EXCEPTION_TYPE' -Option ReadOnly -Scope Script -Force

$LOCAL_SYSTEM_IDENTITY = 'S-1-5-18'
Set-Variable -Name 'LOCAL_SYSTEM_IDENTITY' -Option ReadOnly -Scope Script -Force

$MAX_SCRIPT_DELAY_SEC = 600
Set-Variable -Name 'MAX_SCRIPT_DELAY_SEC' -Option ReadOnly -Scope Script -Force

$REMOTE_ACTION_DLL_PATH = "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll"
Set-Variable -Name 'REMOTE_ACTION_DLL_PATH' -Option ReadOnly -Scope Script -Force

$TLS_12 = 3072
Set-Variable -Name 'TLS_12' -Option ReadOnly -Scope Script -Force

$WINDOWS_VERSIONS = @{Windows7 = '6.1'
    Windows8 = '6.2'
    Windows81 = '6.3'
    Windows10 = '10.0'
    Windows11 = '10.0'
}
Set-Variable -Name 'WINDOWS_VERSIONS' -Option ReadOnly -Scope Script -Force

$LOG_REMOTE_ACTION_NAME = 'Get-NetworkSpeed'
Set-Variable -Name 'LOG_REMOTE_ACTION_NAME' -Option ReadOnly -Scope Script -Force

$MAX_RTT_THRESHOLD = 1000
Set-Variable -Name 'MAX_RTT_THRESHOLD' -Option ReadOnly -Scope Script -Force

$CSV_NETWORK_SPEED_DATA_FILENAME = 'nxt_network_speed_data_aggregated.csv'
Set-Variable -Name 'CSV_NETWORK_SPEED_DATA_FILENAME' -Option ReadOnly -Scope Script -Force

$CSV_NETWORK_SPEED_DATA_PATH = (Join-Path -Path $env:LocalAppData -ChildPath "Nexthink\NetworkSpeed\$CSV_NETWORK_SPEED_DATA_FILENAME")
Set-Variable -Name 'CSV_NETWORK_SPEED_DATA_PATH' -Option ReadOnly -Scope Script -Force

$CSV_FILTER_BY_LAST_DAYS = 7
Set-Variable -Name 'CSV_FILTER_BY_LAST_DAYS' -Option ReadOnly -Scope Script -Force

$CSV_URL_RTT_FIELD_NAME = 'URLRTT'
Set-Variable -Name 'CSV_URL_RTT_FIELD_NAME' -Option ReadOnly -Scope Script -Force

$CSV_BUSINESS_URL_RTT_FIELD_NAME = 'BusinessURLRTT'
Set-Variable -Name 'CSV_BUSINESS_URL_RTT_FIELD_NAME' -Option ReadOnly -Scope Script -Force

$NETWORK_ADAPTER_COUNTER_ID = 1820
Set-Variable -Name 'NETWORK_ADAPTER_COUNTER_ID' -Option ReadOnly -Scope Script -Force

$BYTES_PER_SECOND_COUNTER_ID = 388
Set-Variable -Name 'BYTES_PER_SECOND_COUNTER_ID' -Option ReadOnly -Scope Script -Force

$PERF_COUNTER_NAMES_CODE = '[DllImport("pdh.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern UInt32 PdhLookupPerfNameByIndex(string szMachineName, uint dwNameIndex, System.Text.StringBuilder szNameBuffer, ref uint pcchNameBufferSize);'
Set-Variable -Name 'PERF_COUNTER_NAMES_CODE' -Option ReadOnly -Scope Script -Force

$COUNTER_NAME_CHARACTERS_REPLACE = @{
    '(' = '['
    ')' = ']'
    '#' = ''
    '|' = ''
    '/' = ''
}
Set-Variable -Name 'COUNTER_NAME_CHARACTERS_REPLACE' -Option ReadOnly -Scope Script -Force

# As documented in https://www.powershellmagazine.com/2013/04/04/pstip-detecting-wi-fi-adapters/
$WIFI_MEDIA_TYPES = @{
    1 = $true
    9 = $true
    12 = $true
}
Set-Variable -Name 'WIFI_MEDIA_TYPES' -Option ReadOnly -Scope Script -Force

$CABLE_MEDIA_TYPES = @{
    2 = $true
    11 = $true
    14 = $true
    17 = $true
    18 = $true
}
Set-Variable -Name 'CABLE_MEDIA_TYPES' -Option ReadOnly -Scope Script -Force

$MOBILE_MEDIA_TYPES = @{
    8 = $true
}
Set-Variable -Name 'MOBILE_MEDIA_TYPES' -Option ReadOnly -Scope Script -Force

$WIFI_MEDIA_NAME = 'WiFi'
Set-Variable -Name 'WIFI_MEDIA_NAME' -Option ReadOnly -Scope Script -Force

$CABLE_MEDIA_NAME = 'Cable'
Set-Variable -Name 'CABLE_MEDIA_NAME' -Option ReadOnly -Scope Script -Force

$MOBILE_MEDIA_NAME = 'Mobile'
Set-Variable -Name 'MOBILE_MEDIA_NAME' -Option ReadOnly -Scope Script -Force

$UNKNOWN_MEDIA_NAME = 'Unknown'
Set-Variable -Name 'UNKNOWN_MEDIA_NAME' -Option ReadOnly -Scope Script -Force

# As documented in https://docs.microsoft.com/en-us/uwp/api/windows.networking.connectivity.networkcosttype?view=winrt-19041
$METERED_COST_VALUES = (@{
    2 = $true
    3 = $true
})
Set-Variable -Name 'METERED_COST_VALUES' -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    Start-NxtLogging -RemoteActionName $LOG_REMOTE_ACTION_NAME
    $exitCode = 0
    $output = Initialize-Output

    try {
        Add-NexthinkRemoteActionDLL

        Test-RunningAsInteractiveUser
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows10'
        Test-InputParameters -InputParameters $InputParameters

        Wait-RandomTime -MaximumDelayInSeconds $InputParameters.MaximumDelayInSeconds
        Update-NetworkSpeed -InputParameters $InputParameters -Output $output
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -Output $output
        Stop-NxtLogging -Result $exitCode
    }

    return $exitCode
}

#
# Template functions
#
function Start-NxtLogging ([string]$RemoteActionName) {
    if (Test-PowerShellVersion -MinimumVersion 5) {
        $logFile = "$(Get-LogPath)$RemoteActionName.log"

        Start-NxtLogRotation -LogFile $logFile
        Start-Transcript -Path $logFile -Append | Out-Null
        Write-NxtLog -Message "Running Remote Action $RemoteActionName"
    }
}

function Test-PowerShellVersion ([int]$MinimumVersion) {
    if ((Get-Host).Version.Major -ge $MinimumVersion) {
        return $true
    }
}

function Get-LogPath {

    if (Confirm-CurrentUserIsLocalSystem) {
        return "$env:ProgramData\Nexthink\RemoteActions\Logs\"
    }
    return "$env:LocalAppData\Nexthink\RemoteActions\Logs\"
}

function Confirm-CurrentUserIsLocalSystem {

    $currentIdentity = Get-CurrentIdentity
    return $currentIdentity -eq $LOCAL_SYSTEM_IDENTITY
}

function Get-CurrentIdentity {

    return [security.principal.windowsidentity]::GetCurrent().User.ToString()
}

function Start-NxtLogRotation ([string]$LogFile) {
    if (Test-Path -Path $LogFile) {
        $logSize = (Get-Item -Path $LogFile).Length
        if ($logSize -gt 1000000) {
            Remove-Item -Path "$($LogFile).001" -Force -ErrorAction SilentlyContinue
            Rename-Item -Path $LogFile -NewName "$($LogFile).001" -Force
        }
    }
}

function Write-NxtLog ([string]$Message, [object]$Object) {
    if (Test-PowerShellVersion -MinimumVersion 5) {
        $currentDate = Get-Date -Format 'yyyy/MM/dd hh:mm:ss'
        if ($Object) {
            $jsonObject = $Object | ConvertTo-Json -Compress -Depth 100
            Write-Information -MessageData "$currentDate - $Message $jsonObject"
        } else {
            Write-Information -MessageData "$currentDate - $Message"
        }
    }
}

function Add-NexthinkRemoteActionDLL {

    if (-not (Test-Path -Path $REMOTE_ACTION_DLL_PATH)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink Remote Action DLL not found. "
    }
    Add-Type -Path $REMOTE_ACTION_DLL_PATH
}

function Test-RunningAsInteractiveUser {

    if (Confirm-CurrentUserIsLocalSystem) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) This script must be run as InteractiveUser. "
    }
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

function Wait-RandomTime ([int]$MaximumDelayInSeconds) {
    if ($MaximumDelayInSeconds -gt 0) {
        $seconds = Get-Random -Minimum 0 -Maximum $MaximumDelayInSeconds
        Start-Sleep -Seconds $seconds
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

function Stop-NxtLogging ([string]$Result) {
    if (Test-PowerShellVersion -MinimumVersion 5) {
        if ($Result -eq 0) {
            Write-NxtLog -Message 'Remote Action execution was successful'
        } else {
            Write-NxtLog -Message 'Remote Action execution failed'
        }
        Stop-Transcript | Out-Null
    }
}

function Confirm-StringIsNotEmpty ([string]$Value) {
    return -not [string]::IsNullOrEmpty((Format-StringValue -Value $Value))
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Test-URL ([string]$ParamName, [string]$ParamValue) {
    if (Confirm-StringIsNotEmpty -Value $ParamValue) {
        $uri = $ParamValue -as [uri]
        if ($null -ne $uri -and $uri.IsWellFormedOriginalString()) { return }
    }

    throw "$($ERROR_EXCEPTION_TYPE.Input) Parameter '$ParamName' with value '$ParamValue' is not a correct URL format. "
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

function Test-CollectionNullOrEmpty ([psobject[]]$Collection) {
    return $null -eq $Collection -or ($Collection | Measure-Object).Count -eq 0
}

function Get-OrderedDataFromCsvFile ([string]$Path, [string]$Delimiter, [string]$Field, [string]$Order) {
    if (-not (Test-Path -Path $Path)) { return }

    $orderingSet = @{'asc' = $null
                     'desc' = $null}

    $csvData = Import-Csv -Path $Path -Delimiter $Delimiter

    if ($orderingSet.ContainsKey($Order.ToLower())) {
        try {
            if ($Order -eq 'asc') {
                $csvData = $csvData | Sort-Object -Property $Field
            } else {
                $csvData = $csvData | Sort-Object -Property $Field -Descending
            }
        } catch {
            throw "$($ERROR_EXCEPTION_TYPE.Internal) Unable to sort. Check that the file is a csv. "
        }
    } else {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Ordering value '$Order' not allowed. Allowed values are: $($orderingSet.Keys -join ', '). "
    }

    return $csvData
}

function Get-CsvDataFilteredByDate ([object[]]$CsvData, [datetime]$SinceDate) {
    [object[]]$dataFiltered = @()
    foreach ($obj in $CsvData) {
        [datetime]$objectDate = Format-Date -DateString $obj.$CSV_TIMESTAMP_FIELD_NAME `
                                            -DateFormat $DATE_TIME_FORMAT_DASHES
        if ($objectDate -ge $SinceDate) { $dataFiltered += $obj }
    }
    return $dataFiltered
}

function Format-Date ([string]$DateString, [string]$DateFormat) {
    try {
        return ([datetime]::ParseExact($DateString, $DateFormat,
                                       [globalization.cultureinfo]::InvariantCulture,
                                       [globalization.datetimestyles]::None))
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) '$DateFormat' is an invalid date format for '$DateString' input date. "
    }
}

function Set-SecurityProtocol {

    [net.servicepointmanager]::SecurityProtocol = [enum]::ToObject([net.securityprotocoltype], $TLS_12)
}

function Get-TodayMidNightDate {

    $dateOnly = (Get-Date -Format $DATE_ONLY_FORMAT_DASHES)
    return (Format-Date -DateString "$dateOnly 00:00:00.000" `
                        -DateFormat $DATE_TIME_FORMAT_DASHES)
}

function Get-AverageFromCsvData ([string]$FieldName, [object[]]$CsvData, [bool]$DiscardZero=$false) {
    [object[]]$itemsToSum = $CsvData | Select-Object -ExpandProperty $FieldName `
                                                     -ErrorAction SilentlyContinue
    $total = 0
    $count = $itemsToSum.Count
    if (Test-CollectionNullOrEmpty -Collection $itemsToSum) { return $total }
    if ($DiscardZero) {
        $count = 0
        foreach ($item in $itemsToSum) {
            $intValue = $item -as [int]
            if ($intValue -ne 0) {
                $total += $intValue
                $count += 1
            }
        }
        if ($count -eq 0) { return 0 }
    } else {
        foreach ($item in $itemsToSum) { $total += ($item -as [int]) }
    }

    return $total / $count
}

function Get-CountFromCsvData ([string]$FieldName, [string]$Operator='eq', [psobject]$MatchCountValue, [object[]]$CsvData) {
    $count = 0
    if ((Confirm-StringIsNotEmpty -Value $Operator) -and ($null -ne $MatchCountValue)) {
        $type = $MatchCountValue.GetType().FullName
        if (($type -eq 'System.String') -and (-not (Confirm-StringIsNotEmpty -Value $MatchCountValue))) { return $count }
        if (($null -ne $CsvData) -or ($CsvData.Count -ne 0)) {
            $comparisonSet = @{'eq' = $null
                               'ne' = $null
                               'le' = $null
                               'ge' = $null
                               'lt' = $null
                               'gt' = $null}

            if (-not ($comparisonSet.ContainsKey($Operator.ToLower()))) {
                throw "$($ERROR_EXCEPTION_TYPE.Internal) Operator value $Operator not allowed. Valid values are: $($orderingSet.Keys -join ' '). "
            }

            $pipe = "`$CsvData"
            $selectObject = [string]::Empty
            $comparison = [string]::Empty
            $dynamicType = $null
            switch ($type) {
                'System.String' {
                    $comparison = "`$" + "_.$FieldName -$Operator '$MatchCountValue'"
                }
                'System.Int32' {
                    $dynamicType = 'int'
                    $comparison = "`$" + "_.Cast$FieldName -$Operator $MatchCountValue"
                    $selectObject += " | Select-Object -Property @{ label='Cast$FieldName';expression={ `$" + "_.$FieldName -as [$dynamicType] }}"
                }
                'System.Single' {
                    $dynamicType = 'float'
                    $comparison = "`$" + "_.Cast$FieldName -$Operator $MatchCountValue"
                    $selectObject += " | Select-Object -Property @{ label='Cast$FieldName';expression={ `$" + "_.$FieldName -as [$dynamicType] }}"
                }
                'System.Double' {
                    $dynamicType = 'double'
                    $comparison = "`$" + "_.Cast$FieldName -$Operator $MatchCountValue"
                    $selectObject += " | Select-Object -Property @{ label='Cast$FieldName';expression={ `$" + "_.$FieldName -as [$dynamicType] }}"
                }
                default { return }
            }

            $pipe += $selectObject + " | Where-Object { $comparison }"

            $execPipe = [scriptblock]::Create($pipe)
            if ($null -eq $execPipe) {
                return $count
            }

            [object[]]$result = $(Invoke-Command -ScriptBlock $execPipe)
            $count = $result.Count
        }
    }

    return $count
}

function Save-DataToCsvFile ([string]$Path, [string]$Delimiter, [object[]]$CsvObjects, [switch]$Override) {
    Initialize-Folder -Path (Split-Path -Path $Path -Parent)

    [object[]]$csvData = $null

    if (Test-Path -Path $Path) {
        if (-not $Override.IsPresent) {
            $csvData += Get-DataFromCsvFile -Path $Path `
                                            -Delimiter $Delimiter
        }
        Remove-File -Path $Path
    }

    $csvData += $CsvObjects
    $csvData | Export-Csv -Path $Path `
                          -Delimiter $Delimiter `
                          -Encoding $CSV_DEFAULT_ENCODING `
                          -NoTypeInformation -NoClobber
}

function Initialize-Folder ([string]$Path) {
    try {
        if (-not (Test-Path -Path $Path)) {
            [void](New-Item -Path $Path -ItemType 'Directory' -Force -ErrorAction Stop)
        }
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Error creating folder at $Path. "
    }
}

function Get-DataFromCsvFile ([string]$Path, [string]$Delimiter) {
    if (Test-Path -Path $Path) { return (Import-Csv -Path $Path -Delimiter $Delimiter) }
}

function Remove-File ([string]$Path) {
    if ([string]::IsNullOrEmpty($Path) -or `
        (-not (Test-Path -Path $Path))) { return }

    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}

#
# Get Network Speed functions
#
function Initialize-Output {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    return @{
        LastWebRTTToExternalURL = [timespan]0
        AverageWebRTTToExternalURL = [timespan]0
        TimesExternalURLAboveWebRTTThreshold = [int]0
        LastWebRTTToBusinessURL = [timespan]0
        AverageWebRTTToBusinessURL = [timespan]0
        TimesBusinessURLAboveWebRTTThreshold = [int]0
        TypeOfConnection = [string]::Empty
        MeteredConnection = $false
    }
}

function Test-InputParameters ([hashtable]$InputParameters) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    if (-not (Confirm-StringIsNotEmpty -Value $InputParameters.BusinessURL) -and `
        -not (Confirm-StringIsNotEmpty -Value $InputParameters.ExternalURL)) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Both 'BusinessURL' and 'ExternalURL' are empty, please provide at least one of them for the Remote Action to run. "
    }
    if (Confirm-StringIsNotEmpty -Value $InputParameters.ExternalURL) {
        Test-URL -ParamName 'ExternalURL' -ParamValue $InputParameters.ExternalURL
    }
    if (Confirm-StringIsNotEmpty -Value $InputParameters.BusinessURL) {
        Test-URL -ParamName 'BusinessURL' -ParamValue $InputParameters.BusinessURL
    }
    Test-ParamInAllowedRange `
        -ParamName 'MaximumDelayInSeconds' `
        -ParamValue $InputParameters.MaximumDelayInSeconds `
        -LowerLimit 0 `
        -UpperLimit $MAX_SCRIPT_DELAY_SEC
    Test-ParamInAllowedRange `
        -ParamName 'WebRTTThreshold' `
        -ParamValue $InputParameters.WebRTTThreshold `
        -LowerLimit 0 `
        -UpperLimit $MAX_RTT_THRESHOLD
    Test-ParamInAllowedRange `
        -ParamName 'BusinessWebRTTThreshold' `
        -ParamValue $InputParameters.BusinessWebRTTThreshold `
        -LowerLimit 0 `
        -UpperLimit $MAX_RTT_THRESHOLD

    if (Confirm-StringIsNotEmpty -Value $InputParameters.Proxy) {
        Test-URL -ParamName 'Proxy' -ParamValue $InputParameters.Proxy
    }
}

function Update-NetworkSpeed ([hashtable]$InputParameters, [hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    Update-MeteredValue -Output $Output
    Update-CsvData -InputParameters $InputParameters -Output $Output
}

function Update-MeteredValue ([hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    Set-InterfaceAssembly

    $currentProfile = Get-CurrentProfile
    $profileMediaType = Get-PhysicalMediaType
    if (-not ($profileMediaType.Allowed)) {
        $Output.TypeOfConnection = $UNKNOWN_MEDIA_NAME
        Write-StatusMessage -Message 'Could not get physical adapter type for active connection. The device might be using virtual adapters or be in a full VPN environment. '
    } else {
        $Output.TypeOfConnection = $profileMediaType.Name
    }

    $connectionCost = Get-ConnectionCost -ConnectionProfile $currentProfile
    if ($METERED_COST_VALUES.ContainsKey($connectionCost.NetworkCostType.value__)) {
        $Output.MeteredConnection = $true
    }
}

function Set-InterfaceAssembly {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    try {
        [void][Windows.Networking.Connectivity.NetworkInformation,Windows,ContentType=WindowsRuntime]
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Unable to load 'windows.networking.connectivity.networkinformation assembly'. "
    }
}

function Get-CurrentProfile {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $currentProfile = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()

    if ($null -eq $currentProfile) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Unable to retrieve current connection profile. "
    }

    return $currentProfile
}

function Get-PhysicalMediaType {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $mediaInfo = @{Allowed = $false
                   Name = [string]::Empty}

    $networkAdapter = Get-PhysicalNetworkAdapter

    [int]$mediaKey = $networkAdapter.NdisPhysicalMedium
    if ($WIFI_MEDIA_TYPES.ContainsKey($mediaKey)) {
        $mediaInfo.Name = $WIFI_MEDIA_NAME
        $mediaInfo.Allowed = $true
    }
    if ($CABLE_MEDIA_TYPES.ContainsKey($mediaKey)) {
        $mediaInfo.Name = $CABLE_MEDIA_NAME
        $mediaInfo.Allowed = $true
    }
    if ($MOBILE_MEDIA_TYPES.ContainsKey($mediaKey)) {
        $mediaInfo.Name = $MOBILE_MEDIA_NAME
        $mediaInfo.Allowed = $true
    }

    Write-NxtLog -Message "Media: $($mediaInfo.Name)"
    return $mediaInfo
}

function Get-PhysicalNetworkAdapter {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    [array]$activePhysicalAdapters = Get-ActivePhysicalAdapters

    if (Test-CollectionNullOrEmpty -Collection $activePhysicalAdapters) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Could not get any physical network adapters. "
    }

    if ($activePhysicalAdapters.Count -gt 1) {
        Get-PhysicalAdapterCurrentlyUsed -Adapters $activePhysicalAdapters
    } else {
        return $activePhysicalAdapters[0]
    }
}

function Get-ActivePhysicalAdapters {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    return @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
}

function Get-PhysicalAdapterCurrentlyUsed ([array]$Adapters) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $mostUsedAdapter = $null
    $lastCounterStats = 0

    foreach ($item in $Adapters) {
        $counterValue = Get-AdapterCounterBytesPerSecond -Adapter $item

        if ($counterValue -gt $lastCounterStats) {
            $mostUsedAdapter = $item
            $lastCounterStats = $counterValue
        }
    }

    if ($null -eq $mostUsedAdapter) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Could not get active physical adapter due to lack of performance counter data. Please try running the Remote Action on this device again. "
    }

    Write-NxtLog -Message "Most used Aadapter: $mostUsedAdapter"
    return $mostUsedAdapter
}

function Get-AdapterCounterBytesPerSecond ([object]$Adapter) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    [string[]]$possibleCounterInstanceNames = Get-PossibleAdapterCounterInstanceNames -Adapter $Adapter

    foreach ($instanceName in $possibleCounterInstanceNames) {
        $counterName = Get-FormattedCounterName -InstanceName $instanceName

        $counterData = @(Get-Counter -Counter $counterName -ErrorAction SilentlyContinue)

        if (-not (Test-CollectionNullOrEmpty -Collection $counterData)) {
            if (-not (Test-CollectionNullOrEmpty -Collection $counterData.CounterSamples)) {
                return ($counterData.CounterSamples)[0].CookedValue
            }
        }
    }
}

function Get-PossibleAdapterCounterInstanceNames ([object]$Adapter) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    return @(
        Get-AdapterCounterInstanceName -AdapterName $Adapter.InterfaceDescription
        Get-AdapterCounterInstanceName -AdapterName $Adapter.InterfaceAlias
        Get-AdapterCounterInstanceName -AdapterName $Adapter.InterfaceName
        Get-AdapterCounterInstanceName -AdapterName $Adapter.Name
    )
}

function Get-AdapterCounterInstanceName ([string]$AdapterName) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $formattedName = $AdapterName

    foreach ($key in $COUNTER_NAME_CHARACTERS_REPLACE.Keys) {
        $formattedName = $formattedName.Replace($key, $COUNTER_NAME_CHARACTERS_REPLACE[$key])
    }

    Write-NxtLog -Message "Formatted Name: $formattedName"
    return $formattedName
}

function Get-FormattedCounterName ([string]$InstanceName) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $localizedCounterName = Get-PerformanceCounterLocalName -ID $NETWORK_ADAPTER_COUNTER_ID
    $localizedCounterTypeName = Get-PerformanceCounterLocalName -ID $BYTES_PER_SECOND_COUNTER_ID

    return "\${localizedCounterName}(${instanceName})\${localizedCounterTypeName}".ToLower()
}

function Get-PerformanceCounterLocalName ([uint32]$ID) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $buffer = New-Object -Type text.stringbuilder(1024)

    [uint32]$bufferSize = $buffer.Capacity

    $perfCounter = Add-Type -MemberDefinition $PERF_COUNTER_NAMES_CODE `
                            -Name 'PerfCounter' `
                            -Namespace 'Utility' `
                            -PassThru

    $resultValue = $perfCounter::PdhLookupPerfNameByIndex($env:COMPUTERNAME, $ID, $buffer, [ref]$bufferSize)

    if ($resultValue -eq 0) {
        $buffer.ToString().Substring(0, $bufferSize - 1)
    } else {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Unable to get network adapter performance counter localized name. "
    }
}

function Get-ConnectionCost ([object]$ConnectionProfile) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $connectionCost = $ConnectionProfile.GetConnectionCost()

    return $connectionCost
}

function Update-CsvData ([hashtable]$InputParameters, [hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $csvData = Get-CsvLastData
    $RTTData = Get-RTTData -InputParameters $InputParameters -Output $Output

    $updatedData = @(Add-LatestDataToCsv -CsvData $csvData -NewData $RTTData)
    Update-WithLatestData -RTTThreshold $InputParameters.WebRTTThreshold `
                          -BusinessRTTThreshold $InputParameters.BusinessWebRTTThreshold `
                          -CsvData $updatedData -Output $Output
    Save-DataHistoryToCsv -CsvData $updatedData
}

function Get-CsvLastData {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $csv = Get-OrderedDataFromCsvFile -Path $CSV_NETWORK_SPEED_DATA_PATH `
                                      -Delimiter $CSV_DEFAULT_DELIMITER `
                                      -Field $CSV_TIMESTAMP_FIELD_NAME `
                                      -Order 'desc'

    $sinceDate = (Get-Date).AddDays(-$CSV_FILTER_BY_LAST_DAYS)

    return (Get-CsvDataFilteredByDate -CsvData $csv -SinceDate $sinceDate)
}

function Get-RTTData ([hashtable]$InputParameters, [hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $RTTData = @{URLRTT = 0
                 BusinessURLRTT = 0
                 Timestamp = $null}

    if (Confirm-StringIsNotEmpty -Value $InputParameters.ExternalURL) {
        Write-NxtLog -Message 'Checking External URL'
        [int]$RTTData.URLRTT = Get-RTT -URL $InputParameters.ExternalURL -Proxy $InputParameters.Proxy
    }
    if (Confirm-StringIsNotEmpty -Value $InputParameters.BusinessURL) {
        Write-NxtLog -Message 'Checking Internal URL'
        [int]$RTTData.BusinessURLRTT = Get-RTT -URL $InputParameters.BusinessURL
    }
    if (( $RTTData.URLRTT -eq 0 ) -and ( $RTTData.BusinessURLRTT -eq 0 )) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Unable to measure External and Business URLs. "
    }

    $RTTData.Timestamp = Get-Date -Format $DATE_TIME_FORMAT_DASHES

    $Output.LastWebRTTToExternalURL = [timespan]::FromMilliseconds($RTTData.URLRTT)
    $Output.LastWebRTTToBusinessURL = [timespan]::FromMilliseconds($RTTData.BusinessURLRTT)

    return $RTTData
}

function Get-RTT ([string]$URL, [string]$Proxy) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    try {
        Set-SecurityProtocol

        [uri]$blockInput = $URL
        $requestScriptBlock = Get-RequestScriptBlock -Proxy $Proxy

        $measurement = Measure-Command -Expression $requestScriptBlock -InputObject $blockInput
    } catch {
        Write-StatusMessage -Message "Unable to measure Web RTT for $URL. Reason: $_ "
        return 0
    }

    Write-NxtLog -Message "RTT in Milliseconds in URL $URL : $measurement.TotalMilliseconds"
    return $measurement.TotalMilliseconds
}

function Get-RequestScriptBlock ([string]$Proxy) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"
    Write-NxtLog -Message "Proxy: $Proxy"

    if (([string]::IsNullOrEmpty($Proxy)) -or ($Proxy -eq "''") -or ($Proxy -eq '""')) {
        Write-NxtLog -Message "Getting info without Proxy"
        return { $request = Invoke-WebRequest -Uri $_ -Verbose:$false -UseBasicParsing }
    }

    Write-NxtLog -Message "Getting info with Proxy"
    return { $request = Invoke-WebRequest -Uri $_ -Verbose:$false -UseBasicParsing -ProxyUseDefaultCredentials -Proxy $Proxy }
}

function Add-LatestDataToCsv ([object[]]$CsvData, [hashtable]$NewData) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $newCsvObject = New-Object -TypeName 'psobject' -Property $NewData

    if (($null -eq $CsvData) -or ($CsvData.Count -eq 0)) {
        $latestCsvData = @($newCsvObject)
    } else {
        $latestCsvData = ,$newCsvObject + $CsvData
    }

    return $latestCsvData
}

function Update-WithLatestData ([int]$RTTThreshold, [int]$BusinessRTTThreshold, [object[]]$CsvData, [hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $todayData = Get-TodayData -CsvData $CsvData

    if (($null -eq $todayData) -or ($todayData.Count -eq 0)) { return }

    Update-AveragesFromCsvData -CsvData $todayData -Output $Output
    Update-TimesAboveThreshold -RTTThreshold $RTTThreshold `
                               -BusinessRTTThreshold $BusinessRTTThreshold `
                               -CsvData $todayData `
                               -Output $Output
}

function Get-TodayData ([object[]]$CsvData) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    return (Get-CsvDataFilteredByDate -CsvData $CsvData -SinceDate (Get-TodayMidNightDate))
}

function Update-AveragesFromCsvData ([object[]]$CsvData, [hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $Output.AverageWebRTTToExternalURL = [timespan]::FromMilliseconds((Get-AverageFromCsvData -FieldName $CSV_URL_RTT_FIELD_NAME `
                                                                                              -CsvData $CsvData `
                                                                                              -DiscardZero $true))
    $Output.AverageWebRTTToBusinessURL = [timespan]::FromMilliseconds((Get-AverageFromCsvData -FieldName $CSV_BUSINESS_URL_RTT_FIELD_NAME `
                                                                                              -CsvData $CsvData `
                                                                                              -DiscardZero $true))
}

function Update-TimesAboveThreshold ([int]$RTTThreshold, [float]$BusinessRTTThreshold, [object[]]$CsvData, [hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    $Output.TimesExternalURLAboveWebRTTThreshold = Get-CountFromCsvData -FieldName $CSV_URL_RTT_FIELD_NAME `
                                                                        -Operator 'gt' `
                                                                        -MatchCountValue $RTTThreshold `
                                                                        -CsvData $CsvData
    $Output.TimesBusinessURLAboveWebRTTThreshold = Get-CountFromCsvData -FieldName $CSV_BUSINESS_URL_RTT_FIELD_NAME `
                                                                        -Operator 'gt' `
                                                                        -MatchCountValue $BusinessRTTThreshold `
                                                                        -CsvData $CsvData
}

function Save-DataHistoryToCsv ([object[]]$CsvData) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    Save-DataToCsvFile -Path $CSV_NETWORK_SPEED_DATA_PATH `
                       -Delimiter $CSV_DEFAULT_DELIMITER `
                       -CsvObjects $CsvData `
                       -Override
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$Output) {
    Write-NxtLog -Message "Calling $($MyInvocation.MyCommand)"

    [nxt]::WriteOutputDuration('LastWebRTTToExternalURL', $Output.LastWebRTTToExternalURL)
    [nxt]::WriteOutputDuration('AverageWebRTTToExternalURL', $Output.AverageWebRTTToExternalURL)
    [nxt]::WriteOutputUInt32('TimesExternalURLAboveWebRTTThreshold', $Output.TimesExternalURLAboveWebRTTThreshold)
    [nxt]::WriteOutputDuration('LastWebRTTToBusinessURL', $Output.LastWebRTTToBusinessURL)
    [nxt]::WriteOutputDuration('AverageWebRTTToBusinessURL', $Output.AverageWebRTTToBusinessURL)
    [nxt]::WriteOutputUInt32('TimesBusinessURLAboveWebRTTThreshold', $Output.TimesBusinessURLAboveWebRTTThreshold)
    [nxt]::WriteOutputString('TypeOfConnection', $Output.TypeOfConnection)
    [nxt]::WriteOutputBool('MeteredConnection', $Output.MeteredConnection)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

# SIG # Begin signature block
# MIIu8AYJKoZIhvcNAQcCoIIu4TCCLt0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBxm9agAVEFQeMm
# 37P4NN4S1qtFuvZdQIV0z6EtoC8+nqCCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIdCzCCHQcCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBPruZPpLvL
# ZP/stP/h5DqSmDaaBncR9dKoVEz+TrOOujANBgkqhkiG9w0BAQEFAASCAgB/uzW+
# NVWvtFug8q3eGkUCWgnvM27QSifqW1SItuKP2sWVTe2QNtfQHxqvKBGPiTMpVs9X
# eAztnGnH3pUXKGKImZ+4UIp5oDtvPwziVgWjCinlbBjgYno0Ux9Wl1DF2gtf/POP
# 67SXHldnQ/EE59dDu06xHUG5NmT/0hdkoo1ASK4YcxguEETFjuD/nyD2yZmKUeFV
# kJUFi20LhcV/wzak8/tEDFdyt5h/ACTweqE1HWBpEGyavWt/Y9MBFU9U2eOADQ2y
# oWaXFC8OfcN/ViBpH1x331xFZh9kppj8b4L4wmXtVuv+2N2cjBAA0N7h2YeY1Cwa
# NS0mjpIENXRHZEO0+QF3Cj8ygtyEBW6surFMeKA28Swsj6FZ928zaaQRol0S1Ep7
# xee7LGJcuh7fWwUssch9fnZEXUkoTV9UOgOO1MzMtNeWnK0m3/OZ+A8MXj1qdBLa
# BU7qVYXQp7mXOovi0nPSQ9FWI1+ZASFRr8kIwfHy/KZMelHGfR44aQfxpWF4L+Xp
# iKWEZ3jrxoamR+3cOeOkilLxPD/Xrsv8qI2hSSZdeMtXZr9kYBu7rKnnsl/hRDcX
# 4MgwSxInsb9E9idx4nupxDUDHUWZOmkOryr8zzYg4eFLjqBR1/Z8tB0XnyxzEpUQ
# YUxBVtxndSe/ufYLvAdejiBgckBgOgPCbfZUP6GCGdQwghnQBgorBgEEAYI3AwMB
# MYIZwDCCGbwGCSqGSIb3DQEHAqCCGa0wghmpAgEDMQ0wCwYJYIZIAWUDBAIBMIHc
# BgsqhkiG9w0BCRABBKCBzASByTCBxgIBAQYJKwYBBAGgMgIDMDEwDQYJYIZIAWUD
# BAIBBQAEIAWljOc+BjRQsvT0YTLX3QkGs4z7m9JDJqM1OcdKLsNqAhQEBH/7+Iks
# QQzGVBAXKZT2nEyxRRgPMjAyMzA0MjgxNTA0MDFaMAMCAQGgV6RVMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKDBBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDDCBHbG9i
# YWxzaWduIFRTQSBmb3IgQWR2YW5jZWQgLSBHNKCCFWcwggZYMIIEQKADAgECAhAB
# wpx69HqmAlgOrzKxI7EdMA0GCSqGSIb3DQEBCwUAMFsxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRp
# bWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MB4XDTIyMDQwNjA3NDQxMloXDTMz
# MDUwODA3NDQxMlowUzELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24g
# bnYtc2ExKTAnBgNVBAMMIEdsb2JhbHNpZ24gVFNBIGZvciBBZHZhbmNlZCAtIEc0
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAo96mIRIWErwo4AT3s9Sw
# 0wFoj1O2GFhbcaBe2NZMc+BX8LkMB/eHuSmD/vDVdaFI/z2wHEC8glVoSDoMRus/
# wyyYNM/EmJtwG4YRjV4VfKEN2tZ3fa/sfpwU7KW/KWrriika/g6fLLoWTVhaY3EM
# 2y60cArnRhBC7ntFfP5kRZSv4OtQslJnH3FDN/HiGINAEFeaFdfy8muem8lW22eD
# GHj3ZaQFzOYThRT+X4lnAWH72saDKNaNTt00LBgDAYRI3RZ4JeHWSGmtXDWWIR6g
# w08TABfLwl7ckk0EYsl49d6nsYQKnnQ6gtyAlLcBbauoOZ4aXcF8AQZdkHs+XUoo
# yikQsbNZzwG4ITDH2bX0lyw2rlLHszIjboOm+dQk91b4YXV0TvIGqyKEyP1k5V8V
# pdwndKrS0Om0SHjXmMy7H/jWRsN1dfqeRcaVdWsHB6hE3VZ2KM5KTQJ5a0+R4vys
# neu8iq96a2xkNEbxzHgcvCf0dWinM8k6F36KTkQ+g/O9AgMBAAGjggGeMIIBmjAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FEk7Z7VXopnmdBl6DFksPgjqIHuLMEwGA1UdIARFMEMwQQYJKwYBBAGgMgEeMDQw
# MgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRv
# cnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEBBIGDMIGAMDkGCCsGAQUFBzAB
# hi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQw
# QwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgwFoAU6hbGaefjy1dFOTOk8EC+
# 0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWduLmNv
# bS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQAIiKTq
# hYgzWGt+/ABVItNvQ2lvfP6+Q4Y3Dp9T2lGe0DzjG5nXUVEZD1GQDtvumkbPfQrg
# xuwVgus+rswD+lntj6VKohk+wl/9FoMxVlIoS1/ERYNh65YMIDCifUXqlm2y/HS4
# /UxhlGqnsOqpvziOmHZ1B6b7pdwLb3V6ZOkw15GQYtDhyxnk6C8niECMh9s/2xWw
# SI3ijZWMJ/OsSYewfOnEpeDZ3L72DRW43mOdfZYrraSulGA30EiZqNu9L070AI+3
# /EjathBAxD8521V3vQs8rDagSpkU4NAxHonSJwpwUN2tb2T6b40a9lD0FhMwDBjO
# 2GhC1VXjWl/AoIG8GbxEsGOKfsArHlVu5x0eE2SZZmQJg+mB5j4r/eR87EO7m281
# YpNkmrtYuK8Ebii7CljjhTkl1OOLFXMBOh3LXZH8nkUuh7XwRpyUw2it+g7rR9mp
# JdaKCtie76yiXqYunFjRvVG/EnLQEZtMz5tSv6fqSpQi/Np0s0XUswnWaERAKh+K
# bNrlaXEAEvjJ3+qYqSpqj9Sa4B+smeHoXT55PEWkDgqGFKAV5ZIggfKCjvOqyZxf
# HEl0/CG1KOCBDf+3f5iDwGDTAcVmzGG8wqQLAzc2mjIlwsXmg5T80Hm/g9O8U7Xj
# /s/hcT4F22KPJL3vU6rynlMMP3xr8OolOF9yqjCCBlkwggRBoAMCAQICDQHsHJJA
# 3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBS
# b290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2Jh
# bFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBbMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFs
# U2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0s691g1+pR1LHYTpjfDkjeW10
# /DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuAZm3RKErBLLu5cPJyroz3mVpd
# dq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nuMc+8ijtuasSI8O6X9tzzGKBL
# mRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9sVRTB4uZbrhUmYqoMZI78np9
# /A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6HPXpl69FWqS69+1g9tYX6U5lN
# W3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3E1LZJTTtlu/4Z+oIvo9Jev+Q
# sdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8NubX2bVb+ih0JPiQOZybH/LIN
# oJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57UQgZvGxjVNupkrs799QXm4mbQ
# DgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9MwMB3pkl+XFu6ZxdAkxgPM8C
# jwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8yLJN22TwRZ+6wT9Uo9h2ApVs
# ao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W1j0ZsJfqjFCRba9Xhn4QNx1r
# GhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+0MO9ZZYwHwYDVR0jBBgwFoAU
# rmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzAB
# hiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDYGA1UdHwQvMC0w
# K6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yNi5jcmwwRwYD
# VR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
# bHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4ICAQB/4ojZV2cr
# Ql+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85xhZrGUBJJQge5Jv31qQNjx6W
# 8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs0LLP7MJWZR29f/begsi3n2HT
# tUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTtchBxdnDSD5bz6jdXlJEYr9yN
# mTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vckS3RafXKGNbMCVx+LnPy7rEze
# +t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghzn16h1pnO6X1LlizMFmsYzeRZ
# N4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzOe3ygxayvUQbwEccdMMVRVmDo
# fJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7ASvUh/mIQ7R0w/PbM6kgnfIt1
# Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmNtyUgDhtRoNRjqoPqbHJhSsn6
# Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aNbYy2ce1SIf4+9p+fORqurNIv
# eiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXEQ0H5JeIsEH6B+Q2Up33ytQn1
# 2GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBUcwggQvoAMCAQICDQHyQEJAzv0i
# 2+lscfwwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290
# IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNp
# Z24wHhcNMTkwMjIwMDAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAwHgYDVQQLExdH
# bG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEG
# A1UEAxMKR2xvYmFsU2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AJUH6HPKZvnsFMp7PPcNCPG0RQssgrRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ
# 0cay/xTOURQh7ErdG1rG1ofuTToVBu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJm
# L025eShNUhqKGoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm5
# 66qjuL++gmNQ0PAYid/kD3n16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqM
# PKq0pPbzlUoSB239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68
# UARjNN9rkxi+azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFy
# Vm4uiMVRQkQVlO6jxTiWm05OWgtH8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QK
# bNQCTXTAFO39OfuD8l4UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0a
# EYdwgQqomnUdnjqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXK
# bWQULHpYT9NLCEnFlWQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu
# 3GduyYsRtYQUigAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjggEmMIIBIjAO
# BgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUrmwFo5MT
# 4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUj/BLf6guRSSuTVD6Y5qL3uLdG7ww
# PgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFs
# c2lnbi5jb20vcm9vdHIzMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vcm9vdC1yMy5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYI
# KwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkv
# MA0GCSqGSIb3DQEBDAUAA4IBAQBJrF7Fg/Nay2EqTZdKFSmf5BSQqgn5xHqfNRiK
# CjMVbXKHIk5BP20Knhiu2+Jf/JXRLJgUO47B8DZZefONgc909hik5OFoz+9/ZVlC
# 6cpVObzTxSbucTj61yEDD7dO2VtgakO0fQnQYGHdqu0AXk4yHuCybJ48ssK7mNOQ
# dmpprRrcqInaWE/SwosySs5U+zjpOwcLdQoR2wt8JSfxrCbPEVPm3MbiYTUy9M7d
# g+MZOuvCaKNyAMgkPE64UzyxF6vmNSz500Ip5l9gA6xCYaaxV2ozQt81MYbKPjcr
# 2sTaJPVOEvK2ubdH6rsgrWEWt6Az4y2Jp7yzPAF/IxqACTTpMIIDXzCCAkegAwIB
# AgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4GA1UECxMXR2xvYmFs
# U2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMT
# Ckdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4MTAwMDAwWjBMMSAw
# HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEGA1UEChMKR2xvYmFs
# U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEP
# ADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8RgJDx7KKnQRfJMsu
# S+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsTgHeMCOFJ0mpiLx9e
# +pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmmKPZpO/bLyCiR5Z2K
# YVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zdQQ4gOsC0p6Hpsk+Q
# LjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZXriX7613t2Saer9f
# wRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAwDgYDVR0PAQH/BAQD
# AgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+oLkUkrk1Q+mOai97i
# 3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZURUm7lgAJQayzE4aG
# KAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMpjjM5RcOO5LlXbKr8
# EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK6fBdRoyV3XpYKBov
# Hd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQXmcIfeg7jLQitChws
# /zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecsMx86OyXShkDOOyyG
# eMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpHWD9fMYIDSTCCA0UC
# AQEwbzBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEx
# MC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBH
# NAIQAcKcevR6pgJYDq8ysSOxHTALBglghkgBZQMEAgGgggEtMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDArBgkqhkiG9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaEN
# BgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQxIgQgCa0/JBBRnxK0uDC17osonUgU
# zmV0ZWOf7cmAuLcfqDcwgbAGCyqGSIb3DQEJEAIvMYGgMIGdMIGaMIGXBCCvgDHt
# bss5FERIlb0LHQzrEpWU214MLG32vnKxJUJH0DBzMF+kXTBbMQswCQYDVQQGEwJC
# RTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2ln
# biBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNAIQAcKcevR6pgJYDq8ysSOx
# HTANBgkqhkiG9w0BAQsFAASCAYB5nzEJJORYQm3B9pTm77RFLXydj1XDy3LH+wYJ
# DKSKfQI60mZ3T5Wg5xBp0SI+USlpC3XL3BznCqeEqhlgCaT0ugJqfYJRR0vUk3wo
# INJH43voUEIfCgHvEYOoANxWUo02UAB2Z4xc4DyjSZkXxp0aY0Rf5uK1NpUgFVvC
# lIVBGPzz1tR4joGNhu3jE7jv42CzCPPefiFbIYBNMGB2BjGSqYIid0HBSTtm6U77
# TM0TywmQtyg2iL6fYlS9IXxbemJWk90Ird+W82DcfVnCbo6vokq0gDK0QfXlYzmF
# Kc9HW7JPhZMK/MXAp9+8DH6sRpoTdTXTLcTmNPyO4PzTPpBpe5SDo+Y/2WDWQS3W
# mx+CV/rhveL16EHIWntTUOWsrP0K3dbFilo1uqYs55xDFyzKjfiNicqq9Ge4bHwG
# AgcuBwFQnCTvkBwij2b3HrLcwABmki2kum2FL6LlONhEf0ZOMy1enJEFEw3I3k/n
# fs+dZaty+WDa4OvLgAKCrQV4B7g=
# SIG # End signature block
