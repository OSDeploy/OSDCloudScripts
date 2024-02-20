function Test-Connectivity {

    Write-Host 'Starting Connectivity test to Microsoft, Intel, Qualcomm and AMD' -ForegroundColor Yellow
    write-host "`n"
	
    test-managemicrosoft

    $TPM_ZTD = (Test-NetConnection ztd.dds.microsoft.com -Port 443).TcpTestSucceeded
    If ($TPM_ZTD -eq 'True') {
        Write-Host -NoNewline -ForegroundColor Green 'ZTD.DDS.Microsoft.Com - Success'
        Write-Host @ErrorIcon
    }
    Else {
        Write-Host -NoNewline -ForegroundColor Red 'ZTD.DDS.Microsoft.com - Error'
        Write-Host @ErrorIcon
    }

    $TPM_Intel = (Test-NetConnection ekop.intel.com -Port 443).TcpTestSucceeded
    If ($TPM_Intel -eq 'True') {
        Write-Host -NoNewline -ForegroundColor Green 'TPM_Intel - Success '
        Write-Host @ErrorIcon  
    }
    else {
        Write-Host -NoNewline -ForegroundColor Red 'TPM_Intel - Error '
        Write-Host @ErrorIcon   
    }
    $TPM_Qualcomm = (Test-NetConnection ekcert.spserv.microsoft.com -Port 443).TcpTestSucceeded
    If ($TPM_Qualcomm -eq 'True') {
        Write-Host -NoNewline -ForegroundColor Green 'TPM_Qualcomm - Success '
        Write-Host @ErrorIcon
    }
    else {
        Write-Host -NoNewline -ForegroundColor Red 'TPM_Qualcomm - Error '
        Write-Host @ErrorIcon
    }
    $TPM_AMD = (Test-NetConnection ftpm.amd.com -Port 443).TcpTestSucceeded
    If ($TPM_AMD -eq 'True') {
        Write-Host -NoNewline -ForegroundColor Green 'TPM_AMD - Success '
        Write-Host @ErrorIcon
    }
    else {
        Write-Host -NoNewline -ForegroundColor Red 'TPM_AMD - Error '
        Write-Host @ErrorIcon
    }
    $TPM_Azure = (Test-NetConnection azure.net -Port 443).TcpTestSucceeded 
    If ($TPM_Azure -eq 'True') {
        Write-Host -NoNewline -ForegroundColor Green 'Azure - Success '
        Write-Host @ErrorIcon
    }
    else {
        Write-Host -NoNewline -ForegroundColor Red 'Azure - Error '
        Write-Host @ErrorIcon
    }
}

Test-Connectivity