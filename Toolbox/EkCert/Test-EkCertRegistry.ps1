#Requires -RunAsAdministrator

# This script checks the registry for the presence of an EKCert, and if found, displays the certificate information.

if (Test-Path -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*) {
    Write-Host 'This system has an EKCert, so the issue may apply here.' -ForegroundColor yellow
    $EKCert = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*
    $EKCert | Format-List
}
else {
    Write-Warning 'No EKCert found in the Regsitry at HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*'
}