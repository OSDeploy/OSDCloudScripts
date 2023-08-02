# Test Connection URL
$URL = "http://www.msftconnecttest.com/redirects"

$Response = Invoke-WebRequest -Uri $URL -UseBasicParsing -DisableKeepAlive -TimeoutSec 1 -ErrorAction SilentlyContinue

$Response

Break
#ensure we get a response even if an error's returned
try {
    (Invoke-WebRequest -Uri $Url -ErrorAction Stop).BaseResponse
}
catch [System.Net.WebException] {
    $_.Exception.Message
    $_.Exception.Response
}
