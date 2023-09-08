function Get-HPProactiveInsightsAuthCode {
    [CmdletBinding()]
    param ()

    $SettingsFile = "$env:HOMEPATH\Documents\HPProactiveInsightsConfig.json"

    if (Test-Path $SettingsFile) {
        $Global:HPProactiveInsights = Get-Content $SettingsFile | ConvertFrom-Json
    }
    else {
        Write-Warning "No settings file found, please run Set-HPProactiveInsights first."
        Break
    }

    $Url = $Global:HPProactiveInsights.auth_code_uri + '?response_type=code' + "&client_id=$($Global:HPProactiveInsights.client_id)" + "&redirect_uri=$($Global:HPProactiveInsights.redirect_uri)" + "&scope=$($Global:HPProactiveInsights.scope)" + "&state=$($Global:HPProactiveInsights.state)"
    Write-Verbose -Verbose $Url
    Start-Process "microsoft-edge:$($Url)"

    $Global:HPProactiveInsights.auth_code = Read-Host "`nEnter the auth code from your response url $($Global:HPProactiveInsights.redirect_uri)?state=$($Global:HPProactiveInsights.state)&code=********"

    if ($Global:HPProactiveInsights.auth_code) {
        $Global:HPProactiveInsights | ConvertTo-Json | Out-File $SettingsFile -Encoding ascii -Force
        Write-Verbose "Get-HPProactiveInsightsAccessToken: Generates an Access Token for HP TechPulse API"
    }
    else {
        throw
    }
}

Get-HPProactiveInsightsAuthCode