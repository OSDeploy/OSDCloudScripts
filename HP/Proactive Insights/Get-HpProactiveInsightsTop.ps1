function Get-HpProactiveInsightsTop {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('BSOD')]
        [System.String]
        $Report
    )

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

    switch ($Report) {
        BSOD { $ApiPath = '/analytics/v1/reports/hwbluescreen/topDevicesWithError/type/grid?count=10' }
        Default {}
    }

    $Uri = $Global:HpProactiveInsights.apiScheme + '://' + $Global:HpProactiveInsights.apiHost + $ApiPath

    $Uri
 
    $Headers = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $($Global:HpProactiveInsights.access_token)"
    }

    $Body = @{
        "startIndex" = 0
        "count" = 10
    }

    $Global:Result = Invoke-RestMethod -Method Post -Headers $Headers -Uri $Uri
    Write-Verbose -Verbose 'Results are stored in the variable $Result.  Try running: $Result.resources | OGV'
    $Global:Result.resources | OGV
}

Get-HpProactiveInsightsTop -Report BSOD