function Get-HpProactiveInsightsHardware {
    [CmdletBinding()]
    param ()

    $SettingsFile = "$env:HOMEPATH\Documents\HpProactiveInsights.json"

    if (Test-Path $SettingsFile) {
        $Global:HpProactiveInsights = Get-Content $SettingsFile | ConvertFrom-Json
    }
    else {
        Write-Warning 'No settings file found, please run Set-HpProactiveInsights first.'
        throw
    }

    if ($Global:HpProactiveInsights.access_token) {
        #Do nothing
    }
    else {
        Write-Warning 'Error getting access token. Try running Get-HpProactiveInsightsAuthCode first.'
        throw
    }

    $ApiPath = '/analytics/v1/reports/hwinv/details/type/grid'
    $Uri = $Global:HpProactiveInsights.apiScheme + '://' + $Global:HpProactiveInsights.apiHost + $ApiPath

    $Uri
 
    $Headers = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $($Global:HpProactiveInsights.access_token)"
    }

    $Result = Invoke-RestMethod -Method Post -Headers $Headers -Uri $Uri
    Write-Verbose -Verbose 'Results are stored in the variable $Result.  Try running: $Result.resources | OGV'
}

Get-HpProactiveInsightsHardware