function Get-HPProactiveInsightsAccessToken {
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

    if ($Global:HPProactiveInsights.auth_code) {
        #$code = $Global:HPProactiveInsights.auth_code
    }
    else {
        Write-Warning "No auth code found, please run Get-HPProactiveInsightsAuthCode first."
        Break
    }

    $Body = @{
        "grant_type" = "authorization_code"
        "code" = $Global:HPProactiveInsights.auth_code
        "redirect_uri" = $Global:HPProactiveInsights.redirect_uri
        "client_id" = $Global:HPProactiveInsights.client_id
        "client_secret" = $Global:HPProactiveInsights.client_secret
    }

    try {
        $AccessToken = Invoke-RestMethod -Method Post -Body $Body -Uri $Global:HPProactiveInsights.access_token_uri -Headers @{'Content-Type' = 'application/x-www-form-urlencoded'} -ErrorAction Stop
    }
    catch {
        Write-Warning 'Error getting access token. Try running Get-HPProactiveInsightsAuthCode first.'
        throw $_.Exception
    }

    if ($AccessToken.access_token) {
        $Global:HPProactiveInsights.access_token = $AccessToken.access_token
        $Global:HPProactiveInsights | ConvertTo-Json | Out-File $SettingsFile -Encoding ascii -Force
    }
    else {
        Write-Warning 'Error getting access token. Try running Get-HPProactiveInsightsAuthCode first.'
        throw
    }
    if ($AccessToken.refresh_token) {
        $Global:HPProactiveInsights.refresh_token = $AccessToken.refresh_token
        $Global:HPProactiveInsights | ConvertTo-Json | Out-File $SettingsFile -Encoding ascii -Force
    }
    else {
        Write-Warning 'Error getting access token. Try running Get-HPProactiveInsightsAuthCode first.'
        throw
    }
    return $AccessToken
}

Get-HPProactiveInsightsAccessToken