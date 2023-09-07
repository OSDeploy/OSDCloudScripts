﻿function Get-HpProactiveInsightsAuthCode {
    [CmdletBinding()]
    param ()

    if (Test-Path "$env:HOMEPATH\Documents\HpProactiveInsights.json") {
        $Global:HpProactiveInsights = Get-Content "$env:HOMEPATH\Documents\HpProactiveInsights.json" | ConvertFrom-Json
    }
    else {
        Write-Warning "No settings file found, please run Set-HpProactiveInsights first."
        Break
    }

    $Url = $Global:HpProactiveInsights.auth_code_uri + '?response_type=code' + "&client_id=$($Global:HpProactiveInsights.client_id)" + "&redirect_uri=$($Global:HpProactiveInsights.redirect_uri)" + "&scope=$($Global:HpProactiveInsights.scope)" + "&state=$($Global:HpProactiveInsights.state)"
    Write-Verbose -Verbose $Url
    Start-Process "microsoft-edge:$($Url)"

    $Global:HpProactiveInsights.auth_code = Read-Host "`nEnter the auth code from your response url $($Global:HpProactiveInsights.redirect_uri)?state=$($Global:HpProactiveInsights.state)&code=********"

    if ($Global:HpProactiveInsights.auth_code) {
        $Global:HpProactiveInsights | ConvertTo-Json | Out-File "$env:HOMEPATH\Documents\HpProactiveInsights.json" -Encoding ascii -Force
        Write-Verbose "Get-HpProactiveInsightsAccessToken: Generates an Access Token for HP TechPulse API"
    }
    else {
        throw
    }
}

Get-HpProactiveInsightsAuthCode