#Requires -RunAsAdministrator

$RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices\*'
Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Registry Test: Windows Boot Configuration Log" -ForegroundColor DarkGray
Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $RegistryPath -Value WBCL" -ForegroundColor DarkGray

if (Test-Path -Path $RegistryPath) {
    $WBCL = (Get-ItemProperty -Path $RegistryPath).WBCL
    if ($null -ne $WBCL) {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) WBCL was not found in the Registry"
        Write-Warning "Measured boot logs are missing.  Reboot may be required."
    }
}
else {
    Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) WBCL was not found in the Registry"
    Write-Warning "Measured boot logs are missing.  Reboot may be required."
}
