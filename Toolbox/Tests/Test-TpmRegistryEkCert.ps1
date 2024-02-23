#Requires -RunAsAdministrator

function Test-TpmRegistryEkCert {
    $RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates'
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test EKCert in the Registry" -ForegroundColor Cyan
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $RegistryPath" -ForegroundColor DarkGray

    if (Test-Path -Path $RegistryPath) {
        $EKCert = Get-ItemProperty -Path $RegistryPath
        $EKCert | Format-List
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) EKCert key was not found in the Registry"
    }
}

Test-TpmRegistryEkCert