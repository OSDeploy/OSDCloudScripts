function Test-AutopilotUrl {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test Autopilot URLs" -ForegroundColor Cyan
    $Server = 'ztd.dds.microsoft.com'
    $Port = 443
    $Message = "Test port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }

    $Server = 'cs.dds.microsoft.com'
    $Port = 443
    $Message = "Test port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }

    $Server = 'login.live.com'
    $Port = 443
    $Message = "Test port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }
}

Test-AutopilotUrl