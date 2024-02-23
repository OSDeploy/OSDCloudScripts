#Requires -RunAsAdministrator

function Test-TpmRegistryWBCL {
    $RegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices'
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test Windows Boot Configuration Log in the Registry" -ForegroundColor Cyan
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) $RegistryPath" -ForegroundColor DarkGray

    if (Test-Path -Path $RegistryPath) {
        $WBCL = Get-ItemProperty -Path $RegistryPath
        $WBCL | Format-List

        $WBCL = (Get-ItemProperty -Path $RegistryPath).WBCL
        if ($null -eq $WBCL) {
            Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) WBCL was not found in the Registry"
            Write-Warning 'Measured boot logs are missing.  Reboot may be required.'
        }
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) IntegrityServices key was not found in the Registry"
        Write-Warning 'Measured boot logs are missing.  A Reboot may be required.'
    }
}

Test-TpmRegistryWBCL