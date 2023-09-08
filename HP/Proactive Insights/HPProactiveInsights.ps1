function Get-HPProactiveInsightsConfig {
    [CmdletBinding()]
    param ()

    return "$($HOME)\Documents\HPProactiveInsightsConfig.json"
}
function Test-HPProactiveInsightsConfig {
    [CmdletBinding()]
    param ()

    $ConfigFile = Get-HPProactiveInsightsConfig

    if (Test-Path $ConfigFile) {
        Return $true
    }
    else {
        Write-Verbose "Configuration does not exist at $ConfigFile"
        Write-Verbose 'Run New-HPProactiveInsightsConfig first'
        Return $false
    }
}
function New-HPProactiveInsightsConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('ClientID')]
        [System.String]
        $client_id,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias('ClientSecret')]
        [System.String]
        $client_secret,

        [Alias('AuthURL')]
        [System.String]
        $auth_code_uri = 'https://daas.api.hp.com/oauth/v1/authorize',

        [Alias('AccessTokenURL')]
        [System.String]
        $access_token_uri = 'https://daas.api.hp.com/oauth/v1/token',

        [System.String]
        $apiScheme = 'https',

        [System.String]
        $apiHost = 'daas.api.hp.com',

        [System.String]
        $apiBasePath = '/analytics/v1',

        [Alias('CallbackURL')]
        [System.String]$redirect_uri = 'https://127.0.0.1:5000/',
        
        [System.String]$scope = 'Read',
        [System.String]$State = 'DCEeFWf45A53sdfKef424'
    )

    $ConfigFile = Get-HPProactiveInsightsConfig

    $Global:HPProactiveInsights = [ordered]@{
        'apiScheme'            = $ApiScheme
        'apiHost'              = $ApiHost
        'apiBasePath'          = $ApiBasePath

        'client_id'            = $client_id
        'client_secret'        = $client_secret
        'redirect_uri'         = $redirect_uri
        'scope'                = $scope
        'state'                = $state

        'auth_code_uri'        = $auth_code_uri
        'auth_code'            = ''

        'access_token_uri'     = $access_token_uri
        'access_token'         = ''
        'access_token_expires' = ''
        'refresh_token'        = ''
    }

    $Global:HPProactiveInsights | ConvertTo-Json | Out-File $ConfigFile -Encoding ascii -Force
    
    Write-Verbose -Verbose "HP Proactive Insights API settings saved to $ConfigFile"

    Return $Global:HPProactiveInsights
}
function Initialize-HPProactiveInsights {
    [CmdletBinding()]
    param ()

    $ConfigFile = Get-HPProactiveInsightsConfig

    # Do we have a config file?
    if (Test-HPProactiveInsightsConfig) {
        try {
            $Global:HPProactiveInsights = Get-Content -Path $ConfigFile -ErrorAction Stop | ConvertFrom-Json
        }
        catch {
            Write-Warning 'HP Proactive Insights: Error reading the configuration file.'
            Write-Warning 'Run New-HPProactiveInsightsConfig'
            throw $_.Exception
        }
        
        Write-Verbose -Verbose "HP Proactive Insights: API settings imported from $ConfigFile"
        Write-Verbose -Verbose 'HP Proactive Insights: API settings are loaded in the Global Variable $Global:HPProactiveInsights'

        Return $Global:HPProactiveInsights

    }
    else {
        Write-Warning 'HP Proactive Insights: Configuration file does not exist.'
        Write-Warning 'Run New-HPProactiveInsightsConfig'
        Break
    }
}
function Update-HPProactiveInsightsToken {
    [CmdletBinding()]
    param ()

    $ConfigFile = Get-HPProactiveInsightsConfig

    $null = Initialize-HPProactiveInsights

    # Is the Access Token still valid?  Yes, let's try to refresh it to get more time
    if ($Global:HPProactiveInsights.access_token_expires -lt (Get-Date)) {
        $Body = @{
            'grant_type' = 'refresh_token'
            'refresh_token' = $Global:HPProactiveInsights.refresh_token
            'client_id' = $Global:HPProactiveInsights.client_id
            'client_secret' = $Global:HPProactiveInsights.client_secret
        }

        try {
            $Global:AccessToken = Invoke-RestMethod -Method Post -Body $Body -Uri $Global:HPProactiveInsights.access_token_uri -Headers @{'Content-Type' = 'application/x-www-form-urlencoded' } -ErrorAction Stop
            $Global:HPProactiveInsights.access_token = $Global:AccessToken.access_token
            $Global:HPProactiveInsights.access_token_expires = (Get-Date).AddSeconds($Global:AccessToken.expires_in)
            $Global:HPProactiveInsights.refresh_token = $Global:AccessToken.refresh_token
            $Global:HPProactiveInsights | ConvertTo-Json | Out-File $ConfigFile -Encoding ascii -Force
            Write-Verbose -Verbose 'HP Proactive Insights: Access Token has been refreshed'
            return $Global:HPProactiveInsights
        }
        catch {
            Write-Warning 'HP Proactive Insights: Error getting access token.'
            Write-Warning 'Run Connect-HPProactiveInsights'
            throw $_.Exception
        }
    }
    else {
        Write-Warning 'HP Proactive Insights: Access Token could not be refreshed.'
        Write-Warning 'Run Connect-HPProactiveInsights'
        Break
    }
}
function Connect-HPProactiveInsights {
    [CmdletBinding()]
    param ()

    $ConfigFile = Get-HPProactiveInsightsConfig

    $null = Initialize-HPProactiveInsights

    $Url = $Global:HPProactiveInsights.auth_code_uri + '?response_type=code' + "&client_id=$($Global:HPProactiveInsights.client_id)" + "&redirect_uri=$($Global:HPProactiveInsights.redirect_uri)" + "&scope=$($Global:HPProactiveInsights.scope)" + "&state=$($Global:HPProactiveInsights.state)"
    Write-Verbose -Verbose $Url
    Start-Process "microsoft-edge:$($Url)"

    $Global:HPProactiveInsights.auth_code = Read-Host "`nEnter the auth code from your response url $($Global:HPProactiveInsights.redirect_uri)?state=$($Global:HPProactiveInsights.state)&code=********"

    if ($Global:HPProactiveInsights.auth_code) {
        $Global:HPProactiveInsights | ConvertTo-Json | Out-File $ConfigFile -Encoding ascii -Force
    }
    else {
        throw
    }

    $Body = @{
        'grant_type'    = 'authorization_code'
        'code'          = $Global:HPProactiveInsights.auth_code
        'redirect_uri'  = $Global:HPProactiveInsights.redirect_uri
        'client_id'     = $Global:HPProactiveInsights.client_id
        'client_secret' = $Global:HPProactiveInsights.client_secret
    }

    try {
        $Global:AccessToken = Invoke-RestMethod -Method Post -Body $Body -Uri $Global:HPProactiveInsights.access_token_uri -Headers @{'Content-Type' = 'application/x-www-form-urlencoded' } -ErrorAction Stop
        $Global:HPProactiveInsights.access_token = $Global:AccessToken.access_token
        $Global:HPProactiveInsights.access_token_expires = (Get-Date).AddSeconds($Global:AccessToken.expires_in)
        $Global:HPProactiveInsights.refresh_token = $Global:AccessToken.refresh_token
        $Global:HPProactiveInsights | ConvertTo-Json | Out-File $ConfigFile -Encoding ascii -Force
    }
    catch {
        Write-Warning 'Error getting access token. Try running Get-HPProactiveInsightsAuthCode first.'
        throw $_.Exception
    }

    return $Global:HPProactiveInsights
}