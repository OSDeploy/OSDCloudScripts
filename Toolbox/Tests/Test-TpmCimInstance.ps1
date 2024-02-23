#Requires -RunAsAdministrator

function Test-TpmCimInstance {
<#
IsActivated_InitialValue    : True
IsEnabled_InitialValue      : True
IsOwned_InitialValue        : True
ManufacturerId              : 1314145024
ManufacturerIdTxt           : NTC
ManufacturerVersion         : 7.2.3.1
ManufacturerVersionFull20   : 7.2.3.1
ManufacturerVersionInfo     : NPCT75x 
PhysicalPresenceVersionInfo : 1.3
SpecVersion                 : 2.0, 0, 1.59
PSComputerName              : 
#>
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test TPM CimInstance" -ForegroundColor Cyan
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM'" -ForegroundColor DarkGray
    $Win32Tpm = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' -ErrorAction SilentlyContinue
    if ($Win32Tpm) {
        $Win32Tpm
        if ($Win32Tpm.IsEnabled_InitialValue -ne $true) {
            Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) IsEnabled_InitialValue should be True for Autopilot to work properly"
        }

        if ($Win32Tpm.IsActivated_InitialValue -ne $true) {
            Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) IsActivated_InitialValue should be True"
        }
    
        if ($Win32Tpm.IsOwned_InitialValue -ne $true) {
            Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) IsOwned_InitialValue should be True"
        }
        if (!(Get-Tpm | Select-Object tpmowned).TpmOwned -eq $true) {
            Write-Warning 'Reason: TpmOwned is not owned!)'
        }

        $IsReady = $Win32Tpm | Invoke-CimMethod -MethodName 'IsReadyInformation'
        $IsReadyInformation = $IsReady.Information
        if ($IsReadyInformation -eq '0') {
            Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) IsReadyInformation $IsReadyInformation TPM is ready for attestation"
        }
        else {
            Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) IsReadyInformation $IsReadyInformation TPM is not ready for attestation"
        }
        if ($IsReadyInformation -eq '16777216') {
            Write-Warning 'The TPM has a Health Attestation related vulnerability'
        }
    }
    else {
        Write-Warning 'FAIL: Unable to get TPM information'
    }
}

Test-TpmCimInstance