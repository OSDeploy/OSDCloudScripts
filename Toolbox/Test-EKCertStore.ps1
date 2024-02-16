#Requires -RunAsAdministrator
# Description: This script checks if the EKCertStore is populated with a certificate

if (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*" -ErrorAction SilentlyContinue) {
    Return $true
}
else {
    Return $false
}