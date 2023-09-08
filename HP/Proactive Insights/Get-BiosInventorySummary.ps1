$access_token = '1CJr9gcpiGaUdNFKikwxk0lef6D4'

$ApiBase = 'https://daas.api.hp.com'
$ApiPath = '/analytics/v1/reports/biosinventory/biosInventorySummary/type/grap'
$Uri = "$($ApiBase)$($ApiPath)"

$Method = 'Post'

$Headers = @{
    "Content-Type" = "application/json"
    "Authorization" = "Bearer $access_token"
}

Invoke-RestMethod -Method $Method -Headers $Headers -Uri $Uri