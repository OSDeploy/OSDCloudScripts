function Test-AzuretUrl {
    Write-Host -ForegroundColor DarkGray '========================================================================='
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test Azure URLs" -ForegroundColor Cyan
    $Server = 'azure.net'
    $Port = 443
    $Message = "Test port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }

    $Uri = 'https://portal.manage.microsoft.com'
    $Message = "Test URL $Uri"
    try {
        $response = Invoke-WebRequest -Uri $Uri
    }
    catch {
        $response = $null
    }
    if ($response.StatusCode -eq 200) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }
}

Test-AzuretUrl