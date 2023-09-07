function Set-HpProactiveInsights {
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

        [Alias('CallbackURL')]
        [System.String]$redirect_uri = 'https://127.0.0.1:5000/',
        
        [System.String]$scope = 'Read',
        [System.String]$State = 'DCEeFWf45A53sdfKef424'
    )

    $Global:HpProactiveInsights = [ordered]@{
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

    $Global:HpProactiveInsights | ConvertTo-Json | Out-File "$env:HOMEPATH\Documents\HpProactiveInsights.json" -Encoding ascii -Force
}

Set-HpProactiveInsights -client_id 'your_client_id' -client_secret 'your_client_secret'