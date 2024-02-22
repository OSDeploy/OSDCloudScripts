#Requires -RunAsAdministrator

$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*'
Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Registry Test: Windows EKCert" -ForegroundColor DarkGray
Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $RegistryPath" -ForegroundColor DarkGray

if (Test-Path -Path $RegistryPath) {
    $EKCert = Get-ItemProperty -Path $RegistryPath
    $EKCert | Format-List
}
else {
    Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) EKCert was not found in the Registry"
}