function Test-TpmVersion {
    Write-Host -ForegroundColor DarkGray '========================================================================='
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test for TPM 2.0" -ForegroundColor Cyan

    $TPMversion = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Query 'Select SpecVersion from win32_tpm' | Select-Object SpecVersion
    $TPMversion
    if ($TPMversion.SpecVersion -like '*2.0*') {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) TPM version is 2.0 and does support attestation" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) TPM version is not 2.0 and does not support attestation"
    }
}

Test-TpmVersion