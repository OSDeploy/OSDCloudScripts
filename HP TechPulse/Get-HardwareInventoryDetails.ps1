[CmdletBinding()]
param ()

if (Test-Path "$env:HOMEPATH\Documents\PSTechPulseSettings.json") {
    $Global:PSTechPulseSettings = Get-Content "$env:HOMEPATH\Documents\PSTechPulseSettings.json" | ConvertFrom-Json
}
else {
    Write-Warning "No settings file found, please run Set-PSTechPulseSettings first."
    Break
}

$ApiBase = 'https://daas.api.hp.com'
$ApiPath = '/analytics/v1/reports/hwinv/details/type/grid'
$Uri = "$($ApiBase)$($ApiPath)"

$Headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $($Global:PSTechPulseSettings.access_token)"
}

$TechPulse = Invoke-RestMethod -Method Post -Headers $Headers -Uri $Uri
Write-Verbose -Verbose 'Results are stored in the variable $TechPulse.  Try running: $Techpulse.resources | OGV'