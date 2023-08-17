<#
.SYNOPSIS
Retrieves Wi-Fi signal quality, quality average, strength and network congestion information as well as engages the user in case of low Wi-Fi signal.

.DESCRIPTION
Informs users who are not connected to a corporate network and have a connection strength lower than the threshold specified that their connection is not good for optimal work. In addition gets feedback on the usefulness of the campaign.

.FUNCTIONALITY
On-demand

.INPUTS
ID  Label                           Description
1   CorporateNetworks               Comma-separated list of SSIDs which are defined as corporate. It can be empty
2   AcceptableSignalQuality         Minimum signal quality percentage to consider the current wireless network as good (0 to 100)
3   NearbyNetworksAcceptableSignalQualityMinimum signal quality percentage to consider nearby networks to be competing with the current wireless network (0 to 100)
4   NearbyNetworksMaximumSignalDifferenceMaximum signal percentage difference between the current wireless network and the available networks to consider them as competing (0 to 100)
5   AlertUserAfterBadSignals        Number of times (1 to 200) the signal has to be under the acceptable threshold during current day to notify the user via a campaign
6   AnonymizeBSSID                  If set to 'true' BSSID data for Wifi networks will not be displayed 'ANONYMIZED' will be shown
7   CampaignId                      Campaign to show to recommend to get closer to the router. Use an empty GUID (00000000-0000-0000-0000-000000000000) to avoid campaign

.OUTPUTS
ID  Label                           Type            Description
1   ConnectedToCorporateWiFi        Bool            If the device is connected to a wireless network categorized as corporate
2   WiFiSignalQuality               Ratio           Signal quality percentage as presented by Windows
3   WiFiSignalQualityAverage        Ratio           Wi-Fi signal quality average during the current day
4   WiFiStrengthInDbm               Float           Signal strength in dBm
5   BadSignalCount                  Int             Number of times the Wi-Fi signal quality was below the acceptable signal threshold during the current day
6   BadSignalPercentage             Ratio           Percentage of time the Wi-Fi signal quality was below the acceptable signal threshold during the current day
7   WiFiSpeed                       BitRate         Speed of the connected wireless network in Mbps (Megabits per second)
8   WiFiRadioType                   String          Radio type used by the device's adapter connected to the active wireless network
9   WiFiChannel                     Int             Channel used by the active wireless network
10  CoChannelCongestion             Bool            If there is noise caused by competing networks using the same channel as the active wireless network
11  CoChannelsList                  StringList      Details of the co-channel competing networks if there are any. The list is in CSV format
12  AdjacentChannelsCongestion      Bool            If there is noise caused by competing networks using adjacent channels with respect to the active wireless network
13  AdjacentChannelsList            StringList      Details of the adjacent competing networks if there are any. The list is in CSV format
14  UserConsideredTipAsUseful       String          If the user answered to the campaign affirmatively

.FURTHER INFORMATION
The Remote Action stores WiFi data for the last 7 days under the following path":"
- "%LOCALAPPDATA%\\Nexthink\\WiFiStrength"

The fields "WiFi Signal Quality Average" and "Bad Signal Percentage" are calculated based on the CSV data stored for the same day of the Remote Action execution date, plus the data obtained during current execution.

If AnonymizeBSSID input is set to true, BSSID data will be displayed in the output as "ANONYMIZED"

Further information about wireless network noise and congestion in [https://www.metageek.com/training/resources/adjacent-channel-congestion.html this article].

.NOTES
Context:            InteractiveUser
Version:            4.1.0.1 - Fixed typo in Test-MinimumWindowsVersion
                    4.1.0.0 - Added compatibility for Windows 8.1 devices
                    4.0.0.0 - Option to Anonymize BSSID for displayed networks added
                    3.0.3.0 - Improved campaign error handling
                    3.0.2.0 - Fixed netsh regex to avoid errors in different languages
                    3.0.1.2 - Updated scheduling information
                    3.0.1.1 - Updated yaml adding dynamic parameters capabilities to 'CorporateNetworks' input parameter
                    3.0.1.0 - Fixed Wi-Fi data retrieval by obtaining the numeric values in the right format
                    3.0.0.0 - Added co-channel and adjacent channel congestion analysis features
                    2.0.0.0 - Added CSV exporting functionality and new outputs
                    1.1.2.0 - Fixed typo
                    1.1.1.0 - Downgraded campaign minimum version
                    1.1.0.0 - Added message information when campaign is launched
                    1.0.0.0 - Initial release
Last Generated:     26 Apr 2022 - 18:50:33
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$CorporateNetworks,
    [Parameter(Mandatory = $true)][string]$AcceptableSignalQuality,
    [Parameter(Mandatory = $true)][string]$NearbyNetworksAcceptableSignalQuality,
    [Parameter(Mandatory = $true)][string]$NearbyNetworksMaximumSignalDifference,
    [Parameter(Mandatory = $true)][string]$AlertUserAfterBadSignals,
    [Parameter(Mandatory = $true)][string]$AnonymizeBSSID,
    [Parameter(Mandatory = $true)][string]$CampaignId
)
# End of parameters definition

$env:Path = 'C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\'

#
# Constants definition
#
New-Variable -Name 'CAMPAIGN_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtcampaignaction.dll" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'CAMPAIGN_TIMEOUT' `
    -Value 60 `
    -Option ReadOnly -Scope Script
New-Variable -Name 'CSV_DEFAULT_DELIMITER' `
    -Value ';' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'CSV_DEFAULT_ENCODING' `
    -Value 'UTF8' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'CSV_TIMESTAMP_FIELD_NAME' `
    -Value 'Timestamp' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'DATE_ONLY_FORMAT_DASHES' `
    -Value 'dd-MM-yyyy' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'DATE_TIME_FORMAT_DASHES' `
    -Value 'dd-MM-yyyy HH:mm:ss.fff' `
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
New-Variable -Name 'WINDOWS_VERSIONS' `
    -Value @{Windows7 = '6.1'
             Windows8 = '6.2'
             Windows81 = '6.3'
             Windows10 = '10.0'
             Windows11 = '10.0'} `
    -Option ReadOnly -Scope Script

New-Variable -Name 'MAX_WI_FI_STRENGTH' `
    -Value 100 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MIN_BAD_SIGNAL_ALERT_LIMIT' `
    -Value 1 `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'MAX_BAD_SIGNAL_ALERT_LIMIT' `
    -Value 200 `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'LIST_SEPARATOR' `
    -Value ',' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NETSH_EXE' `
    -Value "$env:SystemRoot\System32\netsh.exe" `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ARGUMENTS_WIFI_DATA' `
    -Value 'wlan show interfaces' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ARGUMENTS_WIFI_NETWORKS' `
    -Value 'wlan show network mode=bssid' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'FREQUENCY_RANGES_2_4_GHZ' `
    -Value @{1 = @(2401, 2423); 2 = @(2406, 2428); 3 = @(2411, 2433)
             4 = @(2416, 2438); 5 = @(2421, 2443); 6 = @(2426, 2448)
             7 = @(2431, 2453); 8 = @(2436, 2458); 9 = @(2441, 2463)
             10 = @(2446, 2468); 11 = @(2451, 2473); 12 = @(2456, 2478)
             13 = @(2461, 2483); 14 = @(2473, 2495)} `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'FREQUENCY_RANGES_5_GHZ' `
    -Value @{32 = @(5150, 5170); 34 = @(5150, 5190); 36 = @(5170, 5190); 38 = @(5170, 5210); 40 = @(5190, 5210)
             42 = @(5170, 5250); 44 = @(5210, 5230); 46 = @(5210, 5250); 48 = @(5230, 5250); 50 = @(5170, 5330)
             52 = @(5250, 5270); 54 = @(5250, 5290); 56 = @(5270, 5290); 58 = @(5250, 5330); 60 = @(5290, 5310)
             62 = @(5290, 5330); 64 = @(5310, 5330); 68 = @(5330, 5350); 96 = @(5470, 5490); 100 = @(5490, 5510)
             102 = @(5490, 5530); 104 = @(5510, 5530); 106 = @(5490, 5570); 108 = @(5530, 5550); 110 = @(5530, 5570)
             112 = @(5550, 5570); 114 = @(5490, 5650); 116 = @(5570, 5590); 118 = @(5570, 5610); 120 = @(5590, 5610)
             122 = @(5570, 5650); 124 = @(5610, 5630); 126 = @(5610, 5650); 128 = @(5630, 5650); 132 = @(5650, 5670)
             134 = @(5650, 5690); 136 = @(5670, 5690); 138 = @(5650, 5730); 140 = @(5690, 5710); 142 = @(5690, 5730)
             144 = @(5710, 5730); 149 = @(5735, 5755); 151 = @(5735, 5775); 153 = @(5755, 5775); 155 = @(5735, 5815)
             157 = @(5775, 5795); 159 = @(5775, 5815); 161 = @(5795, 5815); 165 = @(5815, 5835)} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NETSH_ROW_SSID_REGEX' `
    -Value '^\s*SSID\s*:\s(?<Value>[^\n]+)' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ROW_WIFI_SPEED_REGEX' `
    -Value '^[^\(]+\([^\)]+\)\s+:\s(?<Value>[^\n]+)' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ROW_SIGNAL_PERCENTAGE_REGEX' `
    -Value '^[^:]+:\s(?<Value>\d+)%' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ROW_RADIO_TYPE_REGEX' `
    -Value '^.*:\s(?<Value>802\.11(?:a|b|g|n|ac))' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ROW_CHANNEL_REGEX' `
    -Value '^(?!.+\(.+\)).+\s:\s(?<Value>\d{1,3})$' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'NETSH_ROW_BSSID_REGEX' `
    -Value '^\s*BSSID.*:\s(?<Value>(?:(?:[a-f]|\d){2}:){5}(?:[a-f]|\d){2})' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'BSSID_DATA_SECTION_TOTAL_ROWS' `
    -Value 6 `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NETSH_WIFI_DATA_FILTERS' `
    -Value @{SSID = @{RegEx = $NETSH_ROW_SSID_REGEX
                      Type = 'string'}
             BSSID = @{RegEx = $NETSH_ROW_BSSID_REGEX
                       Type = 'string'}
             Signal = @{RegEx = $NETSH_ROW_SIGNAL_PERCENTAGE_REGEX
                        Type = 'int'}
             Speed = @{RegEx = $NETSH_ROW_WIFI_SPEED_REGEX
                       Type = 'array'}
             RadioType = @{RegEx = $NETSH_ROW_RADIO_TYPE_REGEX
                           Type = 'string'}
             Channel = @{RegEx = $NETSH_ROW_CHANNEL_REGEX
                         Type = 'int'}} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'NETSH_BSSID_DATA_FILTERS' `
    -Value @{BSSID = @{RegEx = $NETSH_ROW_BSSID_REGEX
                       Type = 'string'}
             Signal = @{RegEx = $NETSH_ROW_SIGNAL_PERCENTAGE_REGEX
                        Type = 'int'}
             RadioType = @{RegEx = $NETSH_ROW_RADIO_TYPE_REGEX
                           Type = 'string'}
             Channel = @{RegEx = $NETSH_ROW_CHANNEL_REGEX
                         Type = 'int'}} `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'CSV_WIFI_DATA_FILENAME' `
    -Value 'nxt_wifi_data_aggregated.csv' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'CSV_WIFI_DATA_PATH' `
    -Value (Join-Path -Path $env:LocalAppData `
                      -ChildPath "Nexthink\WiFiStrength\$CSV_WIFI_DATA_FILENAME") `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'CSV_FILTER_BY_LAST_DAYS' `
    -Value 7 `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    [hashtable]$output = Initialize-Output

    try {
        Add-NexthinkDLLs
        Test-RunningAsInteractiveUser
        Test-MinimumSupportedOSVersion -WindowsVersion 'Windows7'
        Test-InputParameters -InputParameters $InputParameters

        Update-Output -InputParameters $InputParameters -Output $output
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -Output $output
    }

    return $exitCode
}

#
# Template functions
#
function Add-NexthinkDLLs {

    if (-not (Test-Path -Path $REMOTE_ACTION_DLL_PATH)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink Remote Action DLL not found. "
    }
    if (-not (Test-Path -Path $CAMPAIGN_DLL_PATH)) {
        throw "$($ERROR_EXCEPTION_TYPE.Environment) Nexthink Campaign DLL not found. "
    }
    Add-Type -Path $REMOTE_ACTION_DLL_PATH
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

function Test-GUIDParameter ([string]$ParamName, [string]$ParamValue) {
    if (-not ($ParamValue -as [guid])) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. Only UID values are accepted. "
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

function Split-SeparatedValue ([string]$Value, [string]$Separator) {
    [string]$formattedString = Format-StringValue -Value $Value
    $valueList = $formattedString.Split($Separator, [stringsplitoptions]::RemoveEmptyEntries)
    [string[]]$result = @()

    if (Test-CollectionNullOrEmpty -Collection $valueList) { return $result }

    foreach ($value in $valueList) {
        $result += $value.Trim()
    }

    return $result
}

function Format-StringValue ([string]$Value) {
    return $Value.Replace('"', '').Replace("'", '').Trim()
}

function Get-DataFromCsvFile ([string]$Path, [string]$Delimiter) {
    if (Test-Path -Path $Path) { return (Import-Csv -Path $Path -Delimiter $Delimiter) }
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

function Confirm-StringIsNotEmpty ([string]$Value) {
    return -not [string]::IsNullOrEmpty((Format-StringValue -Value $Value))
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

function Remove-File ([string]$Path) {
    if ([string]::IsNullOrEmpty($Path) -or `
        (-not (Test-Path -Path $Path))) { return }

    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}

function Convert-DataSetToCsvStringList ([hashtable[]]$DataSet, [string]$Delimiter) {
    [string[]]$stringList = @()

    $allHeaders = $DataSet | Select-Object -ExpandProperty 'Keys'

    if ((Test-CollectionNullOrEmpty -Collection $DataSet) -or `
        (Test-CollectionNullOrEmpty -Collection $allHeaders)) { return $stringList }

    $uniqueHeaders = $allHeaders | Select-Object -Unique

    if (($allHeaders.Count / $DataSet.Count) -ne $uniqueHeaders.Count) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Cannot convert dataset to CSV table. Data is inconsistent. "
    }

    $stringList += $uniqueHeaders -join $Delimiter

    foreach ($item in $DataSet) {
        $stringList += $item.Values -join $Delimiter
    }

    return $stringList
}

function Get-CollectionItemsByIndexes ([array]$Collection, [int]$StartIndex, [int]$EndIndex) {
    if (Test-CollectionNullOrEmpty -Collection $Collection) { return }

    $limit = $Collection.Count - 1
    if ($StartIndex -lt 0 -or $StartIndex -gt $limit -or `
        $EndIndex -lt 0 -or $EndIndex -gt $limit) {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Invalid collection indexes. They are out of range [0-$($limit)]. "
    }

    return $Collection[$StartIndex..$EndIndex]
}

function Test-EmptyGUID ([string]$Guid) {
    return $Guid -eq [guid]::Empty.Guid
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

function Edit-StringListResult ([string[]]$StringList) {
    return $(if ($StringList.Count -gt 0) { $StringList } else { '-' })
}

#
# Wi-Fi signal functions
#
function Initialize-Output {
    return @{ConnectedToCorporateWiFi = $false
             WiFiSignalQuality = [float]0
             WiFiSignalQualityAverage = [float]0
             WiFiStrengthInDbm = [float]0
             BadSignalCount = 0
             BadSignalPercentage = [float]0
             WiFiSpeed = [float]0
             WiFiRadioType = '-'
             WiFiChannel = 0
             CoChannelCongestion = $false
             CoChannelsList = @()
             AdjacentChannelsCongestion = $false
             AdjacentChannelsList = @()
             UserConsideredTipAsUseful = '-'}
}

function Test-InputParameters ([hashtable]$InputParameters) {
    Test-GUIDParameter `
        -ParamName 'CampaignId' `
        -ParamValue $InputParameters.CampaignId
    Test-ParamInAllowedRange `
        -ParamName 'AcceptableSignalQuality' `
        -ParamValue $InputParameters.AcceptableSignalQuality `
        -LowerLimit 0 `
        -UpperLimit $MAX_WI_FI_STRENGTH
    Test-ParamInAllowedRange `
        -ParamName 'AlertUserAfterBadSignals' `
        -ParamValue $InputParameters.AlertUserAfterBadSignals `
        -LowerLimit $MIN_BAD_SIGNAL_ALERT_LIMIT `
        -UpperLimit $MAX_BAD_SIGNAL_ALERT_LIMIT
    Test-ParamInAllowedRange `
        -ParamName 'NearbyNetworksAcceptableSignalQuality' `
        -ParamValue $InputParameters.NearbyNetworksAcceptableSignalQuality `
        -LowerLimit 0 `
        -UpperLimit $MAX_WI_FI_STRENGTH
    Test-ParamInAllowedRange `
        -ParamName 'NearbyNetworksMaximumSignalDifference' `
        -ParamValue $InputParameters.NearbyNetworksMaximumSignalDifference `
        -LowerLimit 0 `
        -UpperLimit $MAX_WI_FI_STRENGTH
    Test-BooleanParameter `
        -ParamName 'AnonymizeBSSID' `
        -ParamValue $InputParameters.AnonymizeBSSID
}

function Update-Output ([hashtable]$InputParameters, [hashtable]$Output) {
    [hashtable]$wiFiData = Get-WiFiData -AcceptableSignal $InputParameters.AcceptableSignalQuality

    Update-WiFiInfo -InputParameters $InputParameters `
                    -WiFiData $wiFiData `
                    -Output $Output

    Update-NetworkCongestionData -InputParameters $InputParameters `
                                 -WiFiData $wiFiData `
                                 -Output $Output

    Update-CampaignResults -InputParameters $InputParameters `
                           -Output $Output
}

function Get-WiFiData ([int]$AcceptableSignal) {
    $netShOutput = @(Get-NetShOutput -Arguments $NETSH_ARGUMENTS_WIFI_DATA)

    [hashtable]$wiFiData = Get-FilteredDataFromNetShRows -NetShRows $netShOutput `
                                                         -FilterData $NETSH_WIFI_DATA_FILTERS

    if (Test-CollectionNullOrEmpty -Collection $wiFiData.Values) {
        throw 'Could not filter Wi-Fi data from NetSh output. '
    }

    $wiFiData.SignalDbm = Convert-SignalPercentageToDbm -SignalPercentage $wiFiData.Signal
    $wiFiData.Speed = Get-MinimumWiFiSpeed -SpeedData $wiFiData.Speed
    $wiFiData.SignalBelowThreshold = ($wiFiData.Signal -lt $AcceptableSignal)
    $wiFiData.Timestamp = (Get-Date -Format $DATE_TIME_FORMAT_DASHES)

    return $wiFiData
}

function Get-NetShOutput ([string]$Arguments) {
    $output = Invoke-Process -FilePath $NETSH_EXE `
                             -Arguments $Arguments
    if ($output.ExitCode -ne 0) {
        throw "There was a problem calling '$NETSH_EXE $Arguments'. "
    }

    return Split-SeparatedValue -Value $output.StdOut `
                                -Separator ([environment]::NewLine)
}

function Get-FilteredDataFromNetShRows ([array]$NetShRows, [hashtable]$FilterData) {
    Test-NetShOutputMatchesAllFilters -NetShOutput $NetShRows -FilterData $FilterData

    $filteredData = @{}
    foreach ($filter in $FilterData.Keys) {
        $value = Get-NetShOutputMatchingValues -NetShOutput $NetShRows `
                                               -RegEx $FilterData.$filter.Regex

        [string]$filterType = $FilterData.$filter.Type
        $filteredData.$filter = (Get-FilteredDataByType -OriginalValues $value -FilterType $filterType)
    }

    return $filteredData
}

function Get-FilteredDataByType ([object]$OriginalValues, [string]$FilterType) {
    if ('array' -eq $FilterType) { return $OriginalValues -as [array] }
    $singleValue = Get-SingleValueFromArray -OriginalValues $OriginalValues
    switch ($filterType) {
        'string' { return $singleValue -as [string] }
        'int' { return $singleValue -as [int] }
        'float' { return $singleValue -as [float] }
    }
    throw 'Unknown value type. '
}

function Get-SingleValueFromArray ([object]$OriginalValues) {
    if (-not (Test-ValueIsAnArray -ValueToCheck $OriginalValues)) { return $OriginalValues }
    if (Test-ArrayIsSingleElement -ArrayToCheck $OriginalValues) { return $OriginalValues[0] }
    throw 'Not possible to retrieve one unique value from a multiple values array. '

}

function Test-ValueIsAnArray ([object]$ValueToCheck) {
    if ($ValueToCheck.GetType().BaseType.Name -eq 'array') { return $true }
    return $false
}

function Test-ArrayIsSingleElement ([array]$ArrayToCheck) {
    if ($ArrayToCheck.Length -gt 1) { return $false }
    return $true
}

function Test-NetShOutputMatchesAllFilters ([array]$NetShOutput, [hashtable]$FilterData) {
    foreach ($key in $FilterData.Keys) {
        if (-not ($NetShOutput -match $FilterData.$key.RegEx)) {
            throw 'NetSh data is malformed or user might not be connected via Wi-Fi. '
        }
    }
}

function Get-NetShOutputMatchingValues ([array]$NetShOutput, [string]$RegEx) {
    $matchingRows = @($NetShOutput -match $RegEx)

    if (Test-CollectionNullOrEmpty -Collection $matchingRows) { return }

    $values = @()
    foreach ($row in $matchingRows) {
        if ($row -match $RegEx) { $values += $Matches.Value }
    }

    return $values
}

function Convert-SignalPercentageToDbm ([int]$SignalPercentage) {
    return (($SignalPercentage / 2) - 100)
}

function Get-MinimumWiFiSpeed ([array]$SpeedData) {
    if (($SpeedData | Measure-Object).Count -ne 2) {
        Write-StatusMessage 'Could not obtain supported Wi-Fi speed. '
        return 0.0
    }

    return (Convert-MegaBitToBit -MegaBitValue $([math]::Min($SpeedData[0], $SpeedData[1])))
}

function Convert-MegaBitToBit ([float]$MegaBitValue) {
    return $MegaBitValue * 1000000
}

function Update-WiFiInfo ([hashtable]$InputParameters, [hashtable]$WiFiData, [hashtable]$Output) {
    [object[]]$allCsvData = Get-WiFiCsvLastAggregatedData -WiFiDataToAggregate $WiFiData

    $corporateList = Split-SeparatedValue -Value $InputParameters.CorporateNetworks `
                                          -Separator $LIST_SEPARATOR
    $Output.ConnectedToCorporateWiFi = Test-WiFiIsCorporate -WiFiName $WiFiData.SSID `
                                                            -CorporateList $corporateList
    $Output.WiFiSignalQuality = $WiFiData.Signal / 100
    $Output.WiFiStrengthInDbm = $WiFiData.SignalDbm
    $Output.WiFiSpeed = $WiFiData.Speed
    $Output.WiFiChannel = $WiFiData.Channel
    $Output.WiFiRadioType = $WiFiData.RadioType

    Update-WiFiInfoAveragesFromCsvData -Output $Output -CsvData $allCsvData
    Save-WiFiDataHistoryToCsv -CsvData $allCsvData
}

function Get-WiFiCsvLastAggregatedData ([hashtable]$WiFiDataToAggregate) {
    [object[]]$csv = Get-DataFromCsvFile -Path $CSV_WIFI_DATA_PATH `
                                         -Delimiter $CSV_DEFAULT_DELIMITER
    $csv += New-Object -TypeName 'psobject' -Property $WiFiDataToAggregate
    $sinceDate = (Get-Date).AddDays(-$CSV_FILTER_BY_LAST_DAYS)

    return Get-CsvDataFilteredByDate -CsvData $csv -SinceDate $sinceDate
}

function Test-WiFiIsCorporate ([string]$WiFiName, [string[]]$CorporateList) {
    return [bool]($CorporateList -match "^$WiFiName$")
}

function Update-WiFiInfoAveragesFromCsvData ([hashtable]$Output, [object[]]$CsvData) {
    [object[]]$csvDataLastDay = (Get-CsvDataFilteredByDate -CsvData $CsvData `
                                                           -SinceDate (Get-TodayMidNightDate))

    if (Test-CollectionNullOrEmpty -Collection $csvDataLastDay) { return }

    $Output.WiFiSignalQualityAverage = (Get-AverageFromCsvData -FieldName 'Signal' `
                                                               -CsvData $csvDataLastDay) / 100
    $Output.BadSignalCount = Get-CountFromCsvData -FieldName 'SignalBelowThreshold' `
                                                  -MatchCountValue 'True' `
                                                  -CsvData $csvDataLastDay
    $Output.BadSignalPercentage = $Output.BadSignalCount / $csvDataLastDay.Count
}

function Save-WiFiDataHistoryToCsv ([object[]]$CsvData) {
    Save-DataToCsvFile -Path $CSV_WIFI_DATA_PATH `
                       -Delimiter $CSV_DEFAULT_DELIMITER `
                       -CsvObjects $CsvData `
                       -Override
}

function Update-NetworkCongestionData ([hashtable]$InputParameters, [hashtable]$WiFiData, [hashtable]$Output) {
    if ($WiFiData.Signal -lt $InputParameters.AcceptableSignalQuality) { return }

    $currentSignalMinusDifference = $WiFiData.Signal - $InputParameters.NearbyNetworksMaximumSignalDifference
    $minimumSignal = [math]::Max($currentSignalMinusDifference, $InputParameters.NearbyNetworksAcceptableSignalQuality)

    $competingNetworks = @(Get-CompetingNetworks -Channel $WiFiData.Channel `
                                                 -MinimumSignal $minimumSignal `
                                                 -BssIdToExclude $WiFiData.BSSID `
                                                 -AnonymizeBSSID ([bool]::parse($InputParameters.AnonymizeBSSID)))

    $coChannelNetworks = @(Get-CoChannelNetworks -Networks $competingNetworks `
                                                 -Channel $WiFiData.Channel)

    $adjacentNetworks = @(Get-AdjacentNetworks -Networks $competingNetworks `
                                               -Channel $WiFiData.Channel)

    $Output.CoChannelCongestion = -not (Test-CollectionNullOrEmpty -Collection $coChannelNetworks)
    $Output.AdjacentChannelsCongestion = -not (Test-CollectionNullOrEmpty -Collection $adjacentNetworks)
    $Output.CoChannelsList = @(Convert-DataSetToCsvStringList -DataSet $coChannelNetworks `
                                                              -Delimiter $CSV_DEFAULT_DELIMITER)
    $Output.AdjacentChannelsList = @(Convert-DataSetToCsvStringList -DataSet $adjacentNetworks `
                                                                    -Delimiter $CSV_DEFAULT_DELIMITER)
}

function Get-CompetingNetworks ([int]$Channel, [float]$MinimumSignal, [string]$BssIdToExclude, [bool]$AnonymizeBSSID) {
    $networksUsingSameBand = Get-NetworksFromBandByChannel -Channel $Channel

    $networkstoshow = $networksUsingSameBand | Where-Object { $_.Signal -ge $MinimumSignal -and `
                                                              $_.BSSID -ne $BssIdToExclude }

    if ($AnonymizeBSSID) {
        foreach ($network in $networkstoshow) {
            if($network.BSSID) { $network.BSSID = 'ANONYMIZED' }
        }
    }

    return $networkstoshow
}

function Get-NetworksFromBandByChannel ([int]$Channel) {
    $networksAvailable = Get-AvailableNetworks
    $frequencies = Get-FrequenciesByChannel -Channel $Channel

    return ($networksAvailable | Where-Object { $frequencies.Keys -contains $_.Channel })
}

function Get-AvailableNetworks {
    $networks = @()
    $netShOutput = @(Get-NetShOutput -Arguments $NETSH_ARGUMENTS_WIFI_NETWORKS)

    if (Test-CollectionNullOrEmpty -Collection $netShOutput) {
        throw 'Could not obtain available networks information from NetSh. '
    }

    $index = 0
    $count = $netShOutput.Count
    while ($index -lt $count) {
        if ($netShOutput[$index] -match $NETSH_ROW_BSSID_REGEX) {
            $networks += Get-BssIdDataFromNetShOutput -NetShOutput $netShOutput `
                                                      -BssIdIndex $index
        }
        $index++
    }

    return $networks
}

function Get-BssIdDataFromNetShOutput ([array]$NetShOutput, [int]$BssIdIndex) {
    $bssIdDataEndIndex = $BssIdIndex + ($BSSID_DATA_SECTION_TOTAL_ROWS - 1)

    $netShBssIdRows = Get-CollectionItemsByIndexes -Collection $NetShOutput `
                                                   -StartIndex $BssIdIndex `
                                                   -EndIndex $bssIdDataEndIndex

    return Get-FilteredDataFromNetShRows -NetShRows $netShBssIdRows `
                                         -FilterData $NETSH_BSSID_DATA_FILTERS
}

function Get-FrequenciesByChannel ([int]$Channel) {
    if ($FREQUENCY_RANGES_2_4_GHZ.ContainsKey($Channel)) {
        return $FREQUENCY_RANGES_2_4_GHZ
    } elseif ($FREQUENCY_RANGES_5_GHZ.ContainsKey($Channel)) {
        return $FREQUENCY_RANGES_5_GHZ
    }
    throw "Unknown network channel '$Channel'. It does not belong to 2.4Ghz nor 5Ghz bands. "
}

function Get-CoChannelNetworks ([array]$Networks, [int]$Channel) {
    return @($Networks | Where-Object { $_.Channel -eq $Channel })
}

function Get-AdjacentNetworks ([array]$Networks, [int]$Channel) {
    $adjacentNetworks = @()
    $currentChannelRange = Get-ChannelFrequencyRange -Channel $Channel

    foreach ($net in $Networks) {
        if ($net.Channel -eq $Channel) { continue }

        $netFreqRange = Get-ChannelFrequencyRange -Channel $net.Channel

        if (Test-CollidingRanges -FirstRange $currentChannelRange -SecondRange $netFreqRange) {
            $adjacentNetworks += $net
        }
    }

    return $adjacentNetworks
}

function Get-ChannelFrequencyRange ([int]$Channel) {
    $frequencies = Get-FrequenciesByChannel -Channel $Channel
    return $frequencies.$Channel
}

function Test-CollidingRanges ([int[]]$FirstRange, [int[]]$SecondRange) {
    return ($FirstRange[0] -gt $SecondRange[1] -and $FirstRange[1] -lt $SecondRange[0]) -or `
           ($FirstRange[0] -lt $SecondRange[1] -and $FirstRange[1] -gt $SecondRange[0])
}

function Update-CampaignResults ([hashtable]$InputParameters, [hashtable]$Output) {
    if ((Test-EmptyGUID -Guid $InputParameters.CampaignId) -or `
        $Output.ConnectedToCorporateWiFi) { return }

    if ($Output.WiFiSignalQuality -lt (($InputParameters.AcceptableSignalQuality / 100) -as [float]) -and `
        $Output.BadSignalCount -ge $InputParameters.AlertUserAfterBadSignals) {
        $Output.UserConsideredTipAsUseful = Invoke-Campaign -CampaignId $InputParameters.CampaignId
        Write-StatusMessage -Message 'Campaign was launched on the device. '
    }
}

#
# Campaign management
#
function Invoke-Campaign ([string]$CampaignId) {
    $response = Get-CampaignResponse -CampaignId $CampaignId
    $status = Get-CampaignResponseStatus -Response $response

    switch ($status) {
        'fully' {
            if ((Get-CampaignResponseAnswer -Response $response -QuestionName 'WiFiSignalQuality') -eq 'Ok') {
                return (Get-CampaignResponseAnswer -Response $response -QuestionName 'UserFeedback')
            }
            Write-StatusMessage -Message 'The user declined to provide feedback on the recommendations. '
            return '-'
        }
        'timeout' {
            Write-StatusMessage -Message 'Timeout on getting an answer from the user. '
            return '-'
        }
        'postponed' {
            Write-StatusMessage -Message 'The user postponed the campaign. '
            return '-'
        }
        'declined' {
            Write-StatusMessage -Message 'The user declined the campaign. '
            return '-'
        }
        'connectionfailed' { throw 'Unable to connect to the Collector component that controls campaign notifications. ' }
        'notificationfailed' { throw 'Unable to notify the Collector component that controls campaign notifications. ' }
        default { throw "Failed to handle campaign response: $response. " }
    }
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$Output) {
    [nxt]::WriteOutputBool('ConnectedToCorporateWiFi', $Output.ConnectedToCorporateWiFi)
    [nxt]::WriteOutputRatio('WiFiSignalQuality', $Output.WiFiSignalQuality)
    [nxt]::WriteOutputRatio('WiFiSignalQualityAverage', $Output.WiFiSignalQualityAverage)
    [nxt]::WriteOutputFloat('WiFiStrengthInDbm', $Output.WiFiStrengthInDbm)
    [nxt]::WriteOutputUInt32('BadSignalCount', $Output.BadSignalCount)
    [nxt]::WriteOutputRatio('BadSignalPercentage', $Output.BadSignalPercentage)
    [nxt]::WriteOutputBitRate('WiFiSpeed', $Output.WiFiSpeed)
    [nxt]::WriteOutputString('WiFiRadioType', $Output.WiFiRadioType)
    [nxt]::WriteOutputUInt32('WiFiChannel', $Output.WiFiChannel)

    [nxt]::WriteOutputBool('CoChannelCongestion', $Output.CoChannelCongestion)
    [string[]]$coChannelsList = Edit-StringListResult -StringList $Output.CoChannelsList
    [nxt]::WriteOutputStringList('CoChannelsList', $coChannelsList)

    [nxt]::WriteOutputBool('AdjacentChannelsCongestion', $Output.AdjacentChannelsCongestion)
    [string[]]$adjacentChannelsList = Edit-StringListResult -StringList $Output.AdjacentChannelsList
    [nxt]::WriteOutputStringList('AdjacentChannelsList', $adjacentChannelsList)

    [nxt]::WriteOutputString('UserConsideredTipAsUseful', $Output.UserConsideredTipAsUseful)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))

# SIG # Begin signature block
# MIImzwYJKoZIhvcNAQcCoIImwDCCJrwCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpaggfMmSnRgfi
# 681F6erbw/wNopXHnMRA5Pik0IU3SqCCETswggPFMIICraADAgECAhACrFwmagtA
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
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD/ZkEGS2Ho
# RxTM2uMOwsXYUWMD/Tz3olM1nwhqpPO9HjANBgkqhkiG9w0BAQEFAASCAgAr7Y13
# TSZyMJ0Ws2HL/2tI3cF+z5wQeogtNn5mVX7jggIdpWf0HOTOGCG3thAJzr+7d0aE
# B3DrFfGqcd2TPY3n4V7PFct43JGS3GwQZae8aFCk3zrkSKOl1bWSkn3zNs45AOWT
# CW/A4twJjVRgVKMYPu0LgiShkztMwAQPe1s6qPa4WZ6wxFB5usiwJ0GI73WXJLFM
# lpdn5V0IVsx3xvzs90DOeQp2vcWL0VtdUGG04bMp52uUFMPYZQ3u01SzOHeTPOeC
# vC9eMNJYO0kxBKXAyxVaeYdmE5UO+piv5p8C3Ibw/ttTvEqWjWiuFH51cQ2LOiq3
# Brq18xjX0JwM0cUd9tu692xw4j2J6sWqHI8YpWIX8l3A30o0s4Y99iyGQWkPrICt
# g21vxvSrVhuUG6OnWFgZPNlTCwNp1AXGJY4JpFg/xiuxXEcAx93PtPP7LV/ZMvCg
# 43mX9NIscdwFjD93xVCJLNJ8ZqgMTT9jOE92hVlMFHxLvx+McI+vLBPEUvErAvVM
# ufVYjdcmxSRxDa2aOmrqIOzh0qlEesea4SDfIb9LoGth2eX7oeoF/kBX6elcje9a
# Yq/N+YIAbOhBSijI2UJAm9eovKJtycOi+5Cw68e0N18X8j3t4LGzZi/dtzWvrxeK
# b99Jm+VhfsUoxJ6UtBOVwMdhWg4vl0zOwRM/gqGCEbMwghGvBgorBgEEAYI3AwMB
# MYIRnzCCEZsGCSqGSIb3DQEHAqCCEYwwghGIAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCBXt+B8yUp/q1Vy4bSvmGM7j2pyaZvQ0P4P1Li9Biu4MAIRAJqwG+UJNFn7
# nUSdPu2ftG0YDzIwMjIwNDI2MTY1MDM1WqCCDXwwggbGMIIErqADAgECAhAKekqI
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
# KoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTIyMDQyNjE2NTAzNVowKwYLKoZI
# hvcNAQkQAgwxHDAaMBgwFgQUhQjzhlFcs9MHfba0t8B/G0peQd4wLwYJKoZIhvcN
# AQkEMSIEIBlOfkf7bP/TZTKYOFZqz1JeajEfG/f0VPQMOcD3zie/MDcGCyqGSIb3
# DQEJEAIvMSgwJjAkMCIEIJ2mkBXDScbBiXhFujWCrXDIj6QpO9tqvpwr0lOSeeY7
# MA0GCSqGSIb3DQEBAQUABIICAEISnsyNm1Tijqi6pJC9KnDCHXlO9RqK32u8tjv6
# GVfLH4RZaeI1Cq0UYpBmZaDwunEsZVB5xmnG/gH7oXwNljLzbkG6y9YtxbUvXIW6
# 9BYrS9Rzolg9O28/jbmVYQ57escsUpsp/1IzDq0IJnsNeL6mmTE9FzSHsU9dMMJL
# wrZ3RSO9Oh+OYp+a8jhGH047AvtNm1P3re5YKzf2Xt/FfSNukMLDhL+D5m28ffp9
# fQkC6MwJQt4bGu4eB7IY0aq65kup/nIp92YRKOVckQ39FomgczTA1K0VyvGQYRMK
# +Rw4u/Igro21aXlrFLXC5/HRugc630nRwjZMN9KROdD9dhqhwF3YcacSvom6BWBB
# 2/oo1DfNDCY/UFEqpiSqkXutgblwwRr1pV5y0Cb3trFCVS1RHr/p4hCIxWk8aaK1
# NKJLmqATzMuHQy5iCh1VrY33Z8r9RQ9CdQD6IfpwnkHRlGIcXYRh0a9j67Sa5D3K
# vv9An/lvlthi1TRlY8zpQ9PcSz5OQc3c0LVpoAJ7eP1TiRSARrdRY31OyU40nvFg
# AyejZRi20CNA7vOqnSitu8wqeeUjVtoxmzq2ORpcmkKBydjmtK/UCv2Ctv9BcBUV
# WraKdSvorrDXn9d+oPvT5adWE/fjEuUUHiMSnRLGTrKEqCYRZgScAz+vg/dOKUIv
# b5Bo
# SIG # End signature block
