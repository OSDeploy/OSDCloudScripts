function Get-HPProactiveInsightsHardware {
    [CmdletBinding()]
    param ()

    $SettingsFile = "$env:HOMEPATH\Documents\HPProactiveInsightsConfig.json"

    if (Test-Path $SettingsFile) {
        $Global:HPProactiveInsights = Get-Content $SettingsFile | ConvertFrom-Json
    }
    else {
        Write-Warning 'No settings file found, please run Set-HPProactiveInsights first.'
        throw
    }

    if ($Global:HPProactiveInsights.access_token) {
        #Do nothing
    }
    else {
        Write-Warning 'Error getting access token. Try running Get-HPProactiveInsightsAuthCode first.'
        throw
    }

    $ApiPath = '/analytics/v1/reports/hwinv/details/type/grid'
    $Uri = $Global:HPProactiveInsights.apiScheme + '://' + $Global:HPProactiveInsights.apiHost + $ApiPath

    $Uri
 
    $Headers = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $($Global:HPProactiveInsights.access_token)"
    }

    $Result = Invoke-RestMethod -Method Post -Headers $Headers -Uri $Uri
    Write-Verbose -Verbose 'Results are stored in the variable $Result.  Try running: $Result.resources | OGV'
}

Get-HPProactiveInsightsHardware