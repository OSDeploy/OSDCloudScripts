function Set-HPProactiveInsights {
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

    $SettingsFile = "$env:HOMEPATH\Documents\HPProactiveInsightsConfig.json"

    $Global:HPProactiveInsights = [ordered]@{
        "apiScheme" = $ApiScheme
        "apiHost" = $ApiHost
        "apiBasePath" = $ApiBasePath

        "client_id" = $client_id
        "client_secret" = $client_secret
        "redirect_uri" = $redirect_uri
        "scope" = $scope
        "state" = $state

        "auth_code_uri" = $auth_code_uri
        "auth_code" = ""

        "access_token_uri" = $access_token_uri
        "access_token" = ""
        "refresh_token" = ""
    }

    $Global:HPProactiveInsights | ConvertTo-Json | Out-File $SettingsFile -Encoding ascii -Force
    
    Write-Verbose -Verbose "HP Proactive Insights API settings saved to $SettingsFile"

    Return $Global:HPProactiveInsights
}

Set-HPProactiveInsights