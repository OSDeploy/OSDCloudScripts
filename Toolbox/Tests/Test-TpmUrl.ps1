function Test-TpmUrl {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test TPM URLs" -ForegroundColor Cyan
    $Server = 'ekop.intel.com'
    $Port = 443
    $Message = "Test Intel port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }

    $Server = 'ekcert.spserv.microsoft.com'
    $Port = 443
    $Message = "Test Qualcomm port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }

    $Server = 'ftpm.amd.com'
    $Port = 443
    $Message = "Test AMD port $Port on $Server"
    $NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
    if ($NetConnection -eq $true) {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $Message"
    }
}

Test-TpmUrl