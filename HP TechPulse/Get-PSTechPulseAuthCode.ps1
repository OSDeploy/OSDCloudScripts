[CmdletBinding()]
param ()

if (Test-Path "$env:HOMEPATH\Documents\PSTechPulseSettings.json") {
    $Global:PSTechPulseSettings = Get-Content "$env:HOMEPATH\Documents\PSTechPulseSettings.json" | ConvertFrom-Json
}
else {
    Write-Warning "No settings file found, please run Set-PSTechPulseSettings first."
    Break
}

$Url = $Global:PSTechPulseSettings.auth_code_uri + '?response_type=code' + "&client_id=$($Global:PSTechPulseSettings.client_id)" + "&redirect_uri=$($Global:PSTechPulseSettings.redirect_uri)" + "&scope=$($Global:PSTechPulseSettings.scope)" + "&state=$($Global:PSTechPulseSettings.state)"
Write-Verbose -Verbose $Url
Start-Process "microsoft-edge:$($Url)"

$Global:PSTechPulseSettings.auth_code = Read-Host "`nEnter the auth code from your response url $($Global:PSTechPulseSettings.redirect_uri)?state=$($Global:PSTechPulseSettings.state)&code=********"

if ($Global:PSTechPulseSettings.auth_code) {
    $Global:PSTechPulseSettings | ConvertTo-Json | Out-File "$env:HOMEPATH\Documents\PSTechPulseSettings.json" -Encoding ascii -Force
    Write-Verbose "Get-PSTechPulseAccessToken: Generates an Access Token for HP TechPulse API"
}
else {
    throw
}