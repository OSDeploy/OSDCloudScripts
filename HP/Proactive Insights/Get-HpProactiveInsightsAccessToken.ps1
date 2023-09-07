function Get-HpProactiveInsightsAccessToken {
    [CmdletBinding()]
    param ()

    if (Test-Path "$env:HOMEPATH\Documents\HpProactiveInsights.json") {
        $Global:HpProactiveInsights = Get-Content "$env:HOMEPATH\Documents\HpProactiveInsights.json" | ConvertFrom-Json
    }
    else {
        Write-Warning "No settings file found, please run Set-HpProactiveInsights first."
        Break
    }

    if ($Global:HpProactiveInsights.auth_code) {
        #$code = $Global:HpProactiveInsights.auth_code
    }
    else {
        Write-Warning "No auth code found, please run Get-HpProactiveInsightsAuthCode first."
        Break
    }

    $Body = @{
        "grant_type" = "authorization_code"
        "code" = $Global:HpProactiveInsights.auth_code
        "redirect_uri" = $Global:HpProactiveInsights.redirect_uri
        "client_id" = $Global:HpProactiveInsights.client_id
        "client_secret" = $Global:HpProactiveInsights.client_secret
    }

    try {
        $AccessToken = Invoke-RestMethod -Method Post -Body $Body -Uri $Global:HpProactiveInsights.access_token_uri -Headers @{'Content-Type' = 'application/x-www-form-urlencoded'} -ErrorAction Stop
    }
    catch {
        Write-Warning 'Error getting access token. Try running Get-HpProactiveInsightsAuthCode first.'
        throw $_.Exception
    }

    if ($AccessToken.access_token) {
        $Global:HpProactiveInsights.access_token = $AccessToken.access_token
        $Global:HpProactiveInsights | ConvertTo-Json | Out-File "$env:HOMEPATH\Documents\HpProactiveInsights.json" -Encoding ascii -Force
    }
    else {
        Write-Warning 'Error getting access_token.'
        throw
    }
    if ($AccessToken.refresh_token) {
        $Global:HpProactiveInsights.refresh_token = $AccessToken.refresh_token
        $Global:HpProactiveInsights | ConvertTo-Json | Out-File "$env:HOMEPATH\Documents\HpProactiveInsights.json" -Encoding ascii -Force
    }
    else {
        Write-Warning 'Error getting refresh_token.'
        throw
    }
    return $AccessToken
}