<#
.SYNOPSIS
Obtains information about the warranty of Dell and Lenovo devices.

.DESCRIPTION
Retrieves warranty information of Dell and/or Lenovo devices, via REST APIs.
The warranty data obtained can be also related to the laptop batteries.

.FUNCTIONALITY
On-demand

.INPUTS
ID  Label                           Description
1   MaximumDelayInSeconds           Maximum delay in seconds to avoid overloading the vendor servers with too many API requests occuring at the same time
2   DellClientID                    Dell Client ID
3   DellClientSecret                Dell Client Secret token
4   DellDeviceWarrantyItemNumbers   List of Dell's device warranty item numbers from where to retrieve the information. The elements should be separated by comma
5   DellBatteryWarrantyItemNumbers  List of Dell's battery warranty item numbers from where to retrieve the information. The elements should be separated by comma
6   LenovoClientToken               Lenovo Client token
7   LenovoDeviceWarrantyProductCodesList of Lenovo's device warranty product codes from where to retrieve the information. The elements should be separated by comma
8   LenovoBatteryWarrantyProductCodesList of Lenovo's battery warranty product codes from where to retrieve the information. The elements should be separated by comma

.OUTPUTS
ID  Label                           Type            Description
1   PurchaseOrShipDate              String          Date when the device was purchased
2   DeviceWarrantyEndDate           String          Date when the device's warranty ends
3   DaysBeforeDeviceWarrantyEnds    Int             Number of days left for the device warranty to expire
4   DeviceWarrantyExpired           Bool            If the device's warranty is expired or not
5   BatteryWarrantyEndDate          String          Date when the battery's warranty ends
6   DaysBeforeBatteryWarrantyEnds   Int             Number of days left for the battery warranty to expire
7   BatteryWarrantyExpired          Bool            If the battery's warranty is expired or not
8   DeviceAgeInYears                Int             Number of years related to the age of the device

.FURTHER INFORMATION
This Remote Action could fail in environments with a restricted network, due to the lack of communication with the corresponding vendor's API.
The dates presented in the output fields are all in UTC time zone and with the following format":" Year/Month/Day Hours:minutes:seconds (24 hours).
The Warranty Item Number found in the API response is known as the SKU number on the Dell Invoice. Choose the SKUs for the support item that relates to the device warranties for each purchased model. Do the same for the batteries, which are typically included with shorter warranty period. These SKU values are what should be used in DeviceWarrantyItemNumbers input parameters.

.NOTES
Context:            InteractiveUser
Version:            3.0.2.0 - Fixed typo on the LenovoBatteryWarrantyProductCodes input description
                    3.0.1.0 - Fixed millisecond removal from API retrieved date
                    3.0.0.0 - Renamed Dell input parameters to align with API object names
                    2.0.0.1 - Renamed the method to process JSON response from API's
                    2.0.0.0 - Added support for Lenovo devices and introduced "DeviceAgeInYears" output
                    1.0.0.0 - Initial release
Last Generated:     30 Jun 2022 - 17:02:35
Copyright (C) 2022 Nexthink SA, Switzerland
#>

#
# Input parameters definition
#
param(
    [Parameter(Mandatory = $true)][string]$MaximumDelayInSeconds,
    [Parameter(Mandatory = $true)][string]$DellClientID,
    [Parameter(Mandatory = $true)][string]$DellClientSecret,
    [Parameter(Mandatory = $true)][string]$DellDeviceWarrantyItemNumbers,
    [Parameter(Mandatory = $true)][string]$DellBatteryWarrantyItemNumbers,
    [Parameter(Mandatory = $true)][string]$LenovoClientToken,
    [Parameter(Mandatory = $true)][string]$LenovoDeviceWarrantyProductCodes,
    [Parameter(Mandatory = $true)][string]$LenovoBatteryWarrantyProductCodes
)
# End of parameters definition
$env:Path = "$env:SystemRoot\system32;$env:SystemRoot;$env:SystemRoot\System32\Wbem;$env:SystemRoot\System32\WindowsPowerShell\v1.0"

#
# Constants definition
#
New-Variable -Name 'DATE_STRING_FORMAT' `
    -Value 'yyyy/MM/dd HH:mm:ss' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'DEFAULT_DATE' `
    -Value ([datetime]::ParseExact('01/01/1970 00:00:00.000Z',
                                   'dd/MM/yyyy HH:mm:ss.fffK',
                                   [globalization.cultureinfo]::InvariantCulture,
                                   [globalization.datetimestyles]::None)) `
    -Option ReadOnly -Scope Script
New-Variable -Name 'DEFAULT_USER_AGENT' `
    -Value 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36 Edg/84.0.522.40' `
    -Option ReadOnly -Scope Script
New-Variable -Name 'ERROR_EXCEPTION_TYPE' `
    -Value @{Environment = '[Environment error]'
             Input = '[Input error]'
             Internal = '[Internal error]'} `
    -Option ReadOnly -Scope Script
New-Variable -Name 'LOCAL_SYSTEM_IDENTITY' `
    -Value 'S-1-5-18' -Option ReadOnly -Scope Script
New-Variable -Name 'MAX_SCRIPT_DELAY_SEC' `
    -Value 600 `
    -Option ReadOnly -Scope Script
New-Variable -Name 'REMOTE_ACTION_DLL_PATH' `
    -Value "$env:NEXTHINK\RemoteActions\nxtremoteactions.dll" `
    -Option ReadOnly -Scope Script
New-Variable -Name 'TLS_12' `
    -Value 3072 `
    -Option ReadOnly -Scope Script
New-Variable -Name 'WEB_REQUEST_TIMEOUT_MILLISECONDS' `
    -Value 20000 `
    -Option ReadOnly -Scope Script

New-Variable -Name 'SUPPORTED_VENDORS' `
    -Value @('Dell', 'Lenovo') `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'DELL_API_AUTHENTICATION_URL' `
    -Value 'https://apigtwb2c.us.dell.com/auth/oauth/v2/token' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'DELL_API_ASSET_URL' `
    -Value 'https://apigtwb2c.us.dell.com/PROD/sbil/eapi/v5/asset-entitlements' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'DELL_PRODUCT_CODE_FIELD_NAME' `
    -Value 'itemNumber' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'DELL_PRODUCT_END_DATE_FIELD_NAME' `
    -Value 'endDate' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'LENOVO_API_URL' `
    -Value 'https://supportapi.lenovo.com/v2.5/warranty' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'LENOVO_BASE_PRODUCT_TYPE_VALUE' `
    -Value 'BASE' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'LENOVO_PRODUCT_CODE_FIELD_NAME' `
    -Value 'ID' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'LENOVO_PRODUCT_END_DATE_FIELD_NAME' `
    -Value 'End' `
    -Option ReadOnly -Scope Script -Force

New-Variable -Name 'API_GENERIC_DATE_STRUCTURE_REGEX' `
    -Value '(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?Z' `
    -Option ReadOnly -Scope Script -Force
New-Variable -Name 'API_GENERIC_DATE_FORMAT' `
    -Value 'yyyy-MM-ddTHH:mm:ssK' `
    -Option ReadOnly -Scope Script -Force

#
# Invoke Main
#
function Invoke-Main ([hashtable]$InputParameters) {
    $exitCode = 0
    [hashtable]$outputData = Initialize-OutputData

    try {
        Add-NexthinkRemoteActionDLL
        Test-RunningAsInteractiveUser
        Test-SupportedOSVersion

        Test-SupportedVendor
        Test-InputParameters -InputParameters $InputParameters

        Update-OutputData -InputParameters $InputParameters `
                          -OutputData $outputData
    } catch {
        Write-StatusMessage -Message $_
        $exitCode = 1
    } finally {
        Update-EngineOutputVariables -OutputData $outputData
    }

    return $exitCode
}

function Initialize-OutputData {
    return @{PurchaseOrShipDate = '-'
             DeviceWarrantyEndDate = '-'
             DaysBeforeDeviceWarrantyEnds = 0
             DeviceWarrantyExpired = $false
             BatteryWarrantyEndDate = '-'
             DaysBeforeBatteryWarrantyEnds = 0
             BatteryWarrantyExpired = $false
             DeviceAgeInYears = 0}
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

function Test-AlphanumericParameter ([string]$ParamName, [string]$ParamValue) {
    if ($ParamValue -notmatch "^[a-zA-Z0-9]+$") {
        throw "$($ERROR_EXCEPTION_TYPE.Input) Error in parameter '$ParamName'. It is not an alphanumeric string. "
    }
}

function Test-StringNullOrEmpty ([string]$ParamName, [string]$ParamValue) {
    if ([string]::IsNullOrEmpty((Format-StringValue -Value $ParamValue))) {
        throw "$($ERROR_EXCEPTION_TYPE.Input) '$ParamName' cannot be empty nor null. "
    }
}

function Wait-RandomTime ([int]$MaximumDelayInSeconds) {
    if ($MaximumDelayInSeconds -gt 0) {
        $seconds = Get-Random -Minimum 0 -Maximum $MaximumDelayInSeconds
        Start-Sleep -Seconds $seconds
    }
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

function Test-CollectionNullOrEmpty ([psobject[]]$Collection) {
    return $null -eq $Collection -or ($Collection | Measure-Object).Count -eq 0
}

function Set-URLParameters ([string]$URL, [hashtable]$Parameters) {
    Add-WebAssembly

    if ($null -eq $Parameters -or `
        (Test-CollectionNullOrEmpty -Collection $Parameters.Values)) {
        return $URL
    }

    $parametrizedUrl = $URL

    foreach ($paramKey in $Parameters.Keys) {
        $paramValue = [web.httputility]::UrlEncode($Parameters.$paramKey)

        if (Confirm-StringIsNotEmpty -Value $paramValue) {
            if ($parametrizedUrl -eq $URL) { $parametrizedUrl += '?' }
            else { $parametrizedUrl += '&' }

            $parametrizedUrl += "${paramKey}=${paramValue}"
        }
    }

    return $parametrizedUrl
}

function Add-WebAssembly {

    try { Add-Type -AssemblyName system.web }
    catch { throw "$($ERROR_EXCEPTION_TYPE.Environment) Web assembly not found. " }
}

function Invoke-APIRequest ([string]$URL, [hashtable]$Headers, [string]$Method, [string]$ContentType, [int]$ContentLength = -1) {
    try {
        Set-SecurityProtocol

        $webRequest = New-WebRequest -URL $URL `
                                     -Headers $Headers `
                                     -Method $Method `
                                     -ContentType $ContentType `
                                     -ContentLength $ContentLength

        $response = Get-WebResponse -Request $webRequest
        $responseStream = $response.GetResponseStream()
        $streamReader = New-Object -TypeName 'io.streamreader' `
                                   -ArgumentList $responseStream

        return $streamReader.ReadToEnd()
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Failed to make '$Method' API request. "
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

function New-WebRequest ([string]$URL, [hashtable]$Headers = $null, [string]$Method = 'GET', [string]$ContentType = 'application/text', [int]$ContentLength = -1) {

    [System.Net.ServicePointManager]::CheckCertificateRevocationList = $true

    try {
        $webRequest = [net.webrequest]::Create($URL)
        $webRequest.Timeout = $WEB_REQUEST_TIMEOUT_MILLISECONDS
        $webRequest.Method = $Method
        $webRequest.ContentType = $ContentType
        if ($ContentLength -gt -1 ) { $webRequest.ContentLength = $ContentLength }
        $webRequest.Proxy.Credentials = [net.credentialcache]::DefaultNetworkCredentials
        $webRequest.UserAgent = $DEFAULT_USER_AGENT

        Set-WebRequestHeaders -WebRequest $webRequest -Headers $Headers

        return $webRequest
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Unable to create a new web request for '$URL'. "
    }
}

function Set-WebRequestHeaders ([net.webrequest]$WebRequest, [hashtable]$Headers) {
    if ($null -eq $Headers -or (Test-CollectionNullOrEmpty $Headers.Keys)) { return }

    foreach ($headerName in $Headers.Keys) {
        $WebRequest.Headers.Set($headerName, $Headers.$headerName)
    }
}

function Get-WebResponse ([psobject]$Request) {
    return $Request.GetResponse()
}

function Convert-JsonStringToObject ([string]$JsonString) {
    Add-WebExtensions

    try {
        $json = New-Object web.script.serialization.javascriptserializer
        return $json.DeserializeObject($JsonString)
    } catch {
        throw "$($ERROR_EXCEPTION_TYPE.Internal) Impossible to load JSON content '$Path'. "
    }
}

function Add-WebExtensions {

    try { Add-Type -AssemblyName system.web.extensions }
    catch { throw "$($ERROR_EXCEPTION_TYPE.Environment) Web extensions not found. " }
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

function Test-SupportedVendor {
    $deviceVendor = (Get-DeviceData).Manufacturer
    $supportedVendorMatch = Get-SupportedVendorName -Vendor $deviceVendor

    if (Confirm-StringIsNotEmpty -Value $supportedVendorMatch) { return }

    $supportedVendorsJoined = $SUPPORTED_VENDORS -join ','
    throw "Unsupported vendor '$deviceVendor'. Supported vendors are: $supportedVendorsJoined. "
}

function Get-DeviceData {
    try {
        return Get-WmiObject -Class 'Win32_Bios'
    } catch {
        throw 'Could not obtain device data from BIOS WMI class. '
    }
}

function Get-SupportedVendorName ([string]$Vendor) {
    foreach ($supportedVendor in $SUPPORTED_VENDORS) {
        if ($Vendor -match $supportedVendor) { return $supportedVendor }
    }
}

#
# Input parameter validation
#
function Test-InputParameters ([hashtable]$InputParameters) {
    Test-ParamInAllowedRange -ParamName 'MaximumDelayInSeconds' `
                             -ParamValue $InputParameters.MaximumDelayInSeconds `
                             -LowerLimit 0 `
                             -UpperLimit $MAX_SCRIPT_DELAY_SEC
    Test-InputParametersByVendor -InputParameters $InputParameters
}

function Test-InputParametersByVendor ([hashtable]$InputParameters) {
    $deviceVendor = (Get-DeviceData).Manufacturer
    $supportedVendorMatch = Get-SupportedVendorName -Vendor $deviceVendor

    switch ($supportedVendorMatch) {
        'Dell' {
    Test-AlphanumericParameter -ParamName 'DellClientID' `
                               -ParamValue $InputParameters.DellClientID
    Test-AlphanumericParameter -ParamName 'DellClientSecret' `
                               -ParamValue $InputParameters.DellClientSecret
}
        'Lenovo' {
            Test-StringNullOrEmpty -ParamName 'LenovoClientToken' `
                                   -ParamValue $InputParameters.LenovoClientToken
        }
    }
}

function Update-OutputData ([hashtable]$InputParameters, [hashtable]$OutputData) {
    $warrantyData = Get-WarrantyData -InputParameters $InputParameters

    $OutputData.PurchaseOrShipDate = ($warrantyData.PurchaseOrShipDate).ToString($DATE_STRING_FORMAT)
    $OutputData.DeviceWarrantyEndDate = ($warrantyData.DeviceWarrantyEndDate).ToString($DATE_STRING_FORMAT)
    $OutputData.BatteryWarrantyEndDate = ($warrantyData.BatteryWarrantyEndDate).ToString($DATE_STRING_FORMAT)

    $OutputData.DaysBeforeDeviceWarrantyEnds = Get-WarrantyDaysLeft `
                                                   -WarrantyEndDate $warrantyData.DeviceWarrantyEndDate
    $OutputData.DeviceWarrantyExpired = Test-WarrantyExpired `
                                            -WarrantyEndDate $warrantyData.DeviceWarrantyEndDate

    $OutputData.DaysBeforeBatteryWarrantyEnds = Get-WarrantyDaysLeft `
                                                    -WarrantyEndDate $warrantyData.BatteryWarrantyEndDate
    $OutputData.BatteryWarrantyExpired = Test-WarrantyExpired `
                                            -WarrantyEndDate $warrantyData.BatteryWarrantyEndDate
    $OutputData.DeviceAgeInYears = Get-DeviceAgeInYears -PurchaseOrShipDate $warrantyData.PurchaseOrShipDate
}

function Get-WarrantyData ([hashtable]$InputParameters) {
    $deviceData = Get-DeviceData
    $warrantyData = @{}

    $supportedVendorMatch = Get-SupportedVendorName -Vendor $deviceData.Manufacturer

    Wait-RandomTime -MaximumDelayInSeconds $InputParameters.MaximumDelayInSeconds

    switch ($supportedVendorMatch) {
        'Dell' {
            $warrantyData = Get-DellWarrantyData -InputParameters $InputParameters `
                                                 -SerialNumber $deviceData.SerialNumber
        }
        'Lenovo' {
            $warrantyData = Get-LenovoWarrantyData -InputParameters $InputParameters `
                                                   -SerialNumber $deviceData.SerialNumber
    }
    }

    return $warrantyData
}

#
# DELL API data management
#
function Get-DellWarrantyData ([hashtable]$InputParameters, [string]$SerialNumber) {
    $warrantyDataRaw = Get-DellWarrantyDataFromAPI -DellClientID $InputParameters.DellClientID `
                                                   -DellClientSecret $InputParameters.DellClientSecret `
                                                   -SerialNumber $SerialNumber

    $deviceProductCodes = Split-SeparatedValue -Value $InputParameters.DellDeviceWarrantyItemNumbers `
                                               -Separator ','

    $batteryProductCodes = Split-SeparatedValue -Value $InputParameters.DellBatteryWarrantyItemNumbers `
                                                -Separator ','

    return Get-DellWarrantyDataFormatted -DeviceProductCodes $deviceProductCodes `
                                         -BatteryProductCodes $batteryProductCodes `
                                         -WarrantyData $warrantyDataRaw
}

function Get-DellWarrantyDataFromAPI ([string]$DellClientID, [string]$DellClientSecret, [string]$SerialNumber) {
    $token = Get-DellAPIOAuthToken -ClientID $DellClientID `
                                   -ClientSecret $DellClientSecret

    $headers = @{Authorization = "Bearer $token"}
    $urlParameters = @{servicetags = $SerialNumber}
    $parametrizedUrl = Set-URLParameters -URL $DELL_API_ASSET_URL `
                                         -Parameters $urlParameters

    $response =  Invoke-APIRequest -URL $parametrizedUrl `
                                   -Headers $headers `
                                   -Method 'GET' `
                                   -ContentType 'application/json'

    return Convert-JsonStringToObject -JsonString $response
}

function Get-DellAPIOAuthToken ([string]$ClientID, [string]$ClientSecret) {
    $urlParameters = @{client_id = $ClientID
                       client_secret = $ClientSecret
                       grant_type = 'client_credentials'}

    $parametrizedUrl = Set-URLParameters -URL $DELL_API_AUTHENTICATION_URL `
                                         -Parameters $urlParameters

    $response = Invoke-APIRequest -URL $parametrizedUrl `
                                  -Headers $null `
                                  -Method 'POST' `
                                  -ContentType 'application/x-www-form-urlencoded'
    $jsonData = Convert-JsonStringToObject -JsonString $response
    return $jsonData.access_token
}

function Get-DellWarrantyDataFormatted ([array]$DeviceProductCodes,
                                        [array]$BatteryProductCodes,
                                        [hashtable]$WarrantyData) {
    $deviceEntitlements = @(Get-ProductsFilteredByCode -Products $WarrantyData.entitlements `
                                                       -ProductCodesFilterList $DeviceProductCodes `
                                                       -ProductCodeFieldName $DELL_PRODUCT_CODE_FIELD_NAME)

    $batteryEntitlements = @(Get-ProductsFilteredByCode -Products $WarrantyData.entitlements `
                                                        -ProductCodesFilterList $BatteryProductCodes `
                                                        -ProductCodeFieldName $DELL_PRODUCT_CODE_FIELD_NAME)

    return @{PurchaseOrShipDate = Format-WarrantyDate -WarrantyDate $WarrantyData.shipDate
             DeviceWarrantyEndDate = Get-ProductLatestWarrantyEndDate -Products $deviceEntitlements `
                                                                      -EndDateFieldName $DELL_PRODUCT_END_DATE_FIELD_NAME
             BatteryWarrantyEndDate = Get-ProductLatestWarrantyEndDate -Products $batteryEntitlements `
                                                                       -EndDateFieldName $DELL_PRODUCT_END_DATE_FIELD_NAME}
}

function Get-ProductsFilteredByCode ([array]$Products,
                                     [array]$ProductCodesFilterList,
                                     [string]$ProductCodeFieldName) {
    if (Test-CollectionNullOrEmpty -Collection $Products) {
        throw 'Could not get warranty entitlements list. The products list received was empty. '
    }

    if (Test-CollectionNullOrEmpty -Collection $ProductCodesFilterList) { return $Products }

    $filteredProducts = @($Products | Where-Object { $ProductCodesFilterList -contains $_.$ProductCodeFieldName })

    if (Test-CollectionNullOrEmpty -Collection $filteredProducts) {
        $filterListString = $ProductCodesFilterList -join ','
        Write-StatusMessage "No entitlements found matching product code(s): '$filterListString'. "
    }

    return $filteredProducts
}

#
# Lenovo API data management
#
function Get-LenovoWarrantyData ([hashtable]$InputParameters, [string]$SerialNumber) {
    $warrantyDataRaw = Get-LenovoWarrantyDataFromAPI -LenovoClientToken $InputParameters.LenovoClientToken `
                                                     -SerialNumber $SerialNumber

    $deviceProductCodes = Split-SeparatedValue -Value $InputParameters.LenovoDeviceWarrantyProductCodes `
                                               -Separator ','

    $batteryProductCodes = Split-SeparatedValue -Value $InputParameters.LenovoBatteryWarrantyProductCodes `
                                                -Separator ','

    return Get-LenovoWarrantyDataFormatted -DeviceProductCodes $deviceProductCodes `
                                           -BatteryProductCodes $batteryProductCodes `
                                           -WarrantyData $warrantyDataRaw
    }

function Get-LenovoWarrantyDataFromAPI ([string]$LenovoClientToken, [string]$SerialNumber) {
    $headers = @{'ClientID' = $LenovoClientToken}
    $urlParameters = @{Serial = $SerialNumber}
    $parametrizedUrl = Set-URLParameters -URL $LENOVO_API_URL `
                                         -Parameters $urlParameters

    $response =  Invoke-APIRequest -URL $parametrizedUrl `
                                   -Headers $headers `
                                   -Method 'POST' `
                                   -ContentType 'application/x-www-form-urlencoded' `
                                   -ContentLength 0

    return Convert-JsonStringToObject -JsonString $response
}

function Get-LenovoWarrantyDataFormatted ([array]$DeviceProductCodes,
                                          [array]$BatteryProductCodes,
                                          [hashtable]$WarrantyData) {
    $allBaseEntitlements = $WarrantyData.Warranty | Where-Object { $_.Type -eq $LENOVO_BASE_PRODUCT_TYPE_VALUE }

    $deviceEntitlements = Get-ProductsFilteredByCode -Products $allBaseEntitlements `
                                                     -ProductCodesFilterList $DeviceProductCodes `
                                                     -ProductCodeFieldName $LENOVO_PRODUCT_CODE_FIELD_NAME

    $batteryEntitlements = Get-ProductsFilteredByCode -Products $allBaseEntitlements `
                                                      -ProductCodesFilterList $BatteryProductCodes `
                                                      -ProductCodeFieldName $LENOVO_PRODUCT_CODE_FIELD_NAME

    return @{PurchaseOrShipDate = Format-WarrantyDate -WarrantyDate $WarrantyData.Shipped
             DeviceWarrantyEndDate = Get-ProductLatestWarrantyEndDate `
                                         -Products $deviceEntitlements `
                                         -EndDateFieldName $LENOVO_PRODUCT_END_DATE_FIELD_NAME
             BatteryWarrantyEndDate = Get-ProductLatestWarrantyEndDate `
                                          -Products $batteryEntitlements `
                                          -EndDateFieldName $LENOVO_PRODUCT_END_DATE_FIELD_NAME}
}

#
# Warranty dates management
#
function Get-ProductLatestWarrantyEndDate ([array]$Products, [string]$EndDateFieldName) {
    $warrantyEndDate = $DEFAULT_DATE

    foreach ($product in $Products) {
        $productEndDate = Format-WarrantyDate -WarrantyDate $product.$EndDateFieldName
        if ($productEndDate -gt $warrantyEndDate) {
            $warrantyEndDate = $productEndDate
        }
    }

    return $warrantyEndDate
}

function Format-WarrantyDate ([string]$WarrantyDate) {
    if ($WarrantyDate -match $API_GENERIC_DATE_STRUCTURE_REGEX) {
        $cleanDateString = $Matches[0] -replace $Matches[0], "$($Matches[1])Z"
        return Format-Date -DateString $cleanDateString `
                           -DateFormat $API_GENERIC_DATE_FORMAT
    }

    throw "Unexpected warranty date: '$WarrantyDate'. "
}

function Get-WarrantyDaysLeft ([datetime]$WarrantyEndDate) {
    $daysBeforeExpiration = (New-TimeSpan -Start (Get-Date) `
                                          -End $WarrantyEndDate).Days
    return $(if ($daysBeforeExpiration -gt 0) { $daysBeforeExpiration } else { 0 })
}

function Test-WarrantyExpired ([datetime]$WarrantyEndDate) {
    return (Get-WarrantyDaysLeft -WarrantyEndDate $WarrantyEndDate) -le 0
}

function Get-DeviceAgeInYears ([datetime]$PurchaseOrShipDate) {
    return [math]::Truncate((New-TimeSpan -Start $PurchaseOrShipDate -End (Get-Date)).Days / 365)
}

#
# Nexthink Output management
#
function Update-EngineOutputVariables ([hashtable]$OutputData) {
    [nxt]::WriteOutputString('PurchaseOrShipDate', $OutputData.PurchaseOrShipDate)
    [nxt]::WriteOutputString('DeviceWarrantyEndDate', $OutputData.DeviceWarrantyEndDate)
    [nxt]::WriteOutputUInt32('DaysBeforeDeviceWarrantyEnds', $OutputData.DaysBeforeDeviceWarrantyEnds)
    [nxt]::WriteOutputBool('DeviceWarrantyExpired', $OutputData.DeviceWarrantyExpired)
    [nxt]::WriteOutputString('BatteryWarrantyEndDate', $OutputData.BatteryWarrantyEndDate)
    [nxt]::WriteOutputUInt32('DaysBeforeBatteryWarrantyEnds', $OutputData.DaysBeforeBatteryWarrantyEnds)
    [nxt]::WriteOutputBool('BatteryWarrantyExpired', $OutputData.BatteryWarrantyExpired)
    [nxt]::WriteOutputUInt32('DeviceAgeInYears', $OutputData.DeviceAgeInYears)
}

#
# Main script flow
#
[environment]::Exit((Invoke-Main -InputParameters $MyInvocation.BoundParameters))
# SIG # Begin signature block
# MIIshAYJKoZIhvcNAQcCoIIsdTCCLHECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCARhQpcai93Kz4k
# gAFJP2eKZ1aIr7qD1SmOS+1O5BLa2KCCETswggPFMIICraADAgECAhACrFwmagtA
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
# uOsOBEPX9f6m8GLUmWqlwcHwZJSAMYIanzCCGpsCAQEwgYAwbDELMAkGA1UEBhMC
# VVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0
# LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgRVYgQ29kZSBTaWduaW5nIENBIChTSEEy
# KQIQChoNG3KPlLi3cBQgfCoKxDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3
# AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisG
# AQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAzd2DX9UyE
# oIeOiCQlWDjL0IvvMPX3hv+4vZ3JPfQXOzANBgkqhkiG9w0BAQEFAASCAgCZq6Wz
# E3jYSIJyfA8Qk3IfhF9q4Fc2vMLwMe3bWqQSg8ID5g661mjDdO9pd2hr5EGZZS2v
# Ww39Ax45cNEFIpN3l79Rf1/LAzD8hui9lCXg3X4TUevcrx9fnQqVWv2qJYZsUXi5
# pf3pRrAGyeY7NxK3AhRkGJz5sYZyMU5ySOyTR4cdGFhCPaEAq6gBsv0m0jyjVtll
# QHHVmL8qXIJ57jhcsz1kZNcMnv7hWz6UCErlxW2en7+U6pcItiBxVBXHAb23TOc0
# 0UW8Fd2mRLa4P4MxzZztzRMjY/mNPpWGYO35v831xk5c7BzkcxkXXscOvkzVIrcu
# vXqoOOJ+UEggH/2CX8BDuAyiSHYVf/p3gAuD/z+1amBm58myM7ZiKQ8q5RmH/EHH
# KoWWn9VbRygdIXnPlTYu5+uk2L2abefHFnFcxEfhvdICoZKSg/Y5T96TEEWBfmWF
# fFr98Ejr0vkOsL23MvgiZ5B32lve3rfZJ24PvF15NQal62vlceJhCkEnGuWzIkzQ
# Hu3aCE2cgr3C6wrrqEaOpcbnwNMWIKB8FOzqMKC2XOHS3ojaj09KEhZVNA8QpO+m
# rWNB9rAM+3V1D+PikrtE0DA8i4OZcP0/a6mucJUCUE6taXXZuROk8nA5YYkGs1mW
# aolaizuZC7oczRUXWOXOaUh9NetR15N5EaJdJaGCF2gwghdkBgorBgEEAYI3AwMB
# MYIXVDCCF1AGCSqGSIb3DQEHAqCCF0Ewghc9AgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCBfJxtUOxvinxWOqsQMzy7WLKw9tQ5rd9Z0cyj4/SCzeQIRAMaE6Wjf5fB8
# 8szyvLfINOEYDzIwMjIwNjMwMTUwMjQyWqCCEzEwggbGMIIErqADAgECAhAKekqI
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
# Divl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBbEwggSZoAMCAQICEAEkCvseOAuK
# FvFLcZ3008AwDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UE
# AxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDYwOTAwMDAwMFoX
# DTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNl
# cnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQw
# H/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6
# dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXG
# XuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXn
# Mcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy
# 19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFY
# F/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+Skjqe
# PdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFg
# qrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJR
# R3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7Gr
# hotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCAV4wggFa
# MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9P
# MB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNy
# dDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATANBgkqhkiG9w0BAQwFAAOCAQEAmhYCpQHvgfsNtFiyeK2oIxnZ
# czfaYJ5R18v4L0C5ox98QE4zPpA854kBdYXoYnsdVuBxut5exje8eVxiAE34SXpR
# TQYy88XSAConIOqJLhU54Cw++HV8LIJBYTUPI9DtNZXSiJUpQ8vgplgQfFOOn0XJ
# IDcUwO0Zun53OdJUlsemEd80M/Z1UkJLHJ2NltWVbEcSFCRfJkH6Gka93rDlkUcD
# rBgIy8vbZol/K5xlv743Tr4t851Kw8zMR17IlZWt0cu7KgYg+T9y6jbrRXKSeil7
# FAM8+03WSHF6EBGKCHTNbBsEXNKKlQN2UVBT1i73SkbDrhAscUywh7YnN0RgRDGC
# A3YwggNyAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQQIQCnpKiJ7JmUKQBmM4TYaXnTANBglghkgBZQMEAgEF
# AKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8X
# DTIyMDYzMDE1MDI0MlowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQUhQjzhlFcs9MH
# fba0t8B/G0peQd4wLwYJKoZIhvcNAQkEMSIEIOlK5SBMc3Baj9bJbXeR1UXQaql9
# WmEqLGn73om42cyAMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIJ2mkBXDScbBiXhF
# ujWCrXDIj6QpO9tqvpwr0lOSeeY7MA0GCSqGSIb3DQEBAQUABIICAGnm06r/194j
# 9Ycxc/IOFAwrGrLG27XlS5tmq2gTJvo0kN8TvibDAWiazkm+R0Q04lzXGCRHdqVv
# 5OrM8hoUPIgftRxLX+oatdQSIt7/RigkSRR/buqjN74FPMpiPweI1Ga6j+xEtgEK
# QOtY4iqMBr5jyOnl8FVOkn9GWrdS+aR08KDCKlWodjUwh7ghA7wMLOdQeMwdusza
# JHRGtPGnj5/O3ExyGFxdnBR76dXdf+3vV/4YkuahL0njl3R6QcvYYLblfwQ2wZQN
# AxNHicgMjeuFk9pQaWw0KVt+Va3xy3J5OhSImQbXWRN6sjWJ7YuoOzMtEWGO3JN8
# thkOBwIxwSSGwzFXZEjGUlzbWt/JjmKJd8LDj18R8wRYk/Rvwq6UfsLIO4qZ/FP2
# 6EehhZiUrtyCxqZ4fCw2aMQ0mWMMG4wEjslAzn/2q2iGfXEb2Gyen7+aZ3rwLajj
# xszx6T2OgJrVok1OLYoZujVskQOT8Z8hMXsguJ2JWAyMYbO+MBE0KHC9LtJ9XIps
# z0RCpt8mT4MOAWJoYMcPVmY1i6aJT50wAi35KVYzLDeQiMubZwLKjmDOOnyJUV0j
# Z0b3zvwpkui42R9Xkaiodzo5xvpNxJpaDnaBTmjh9CRmISblxOOhoJvS6TowCiwb
# Uynlju91wIcgDqeyY5kQQLub39RoOkzq
# SIG # End signature block
