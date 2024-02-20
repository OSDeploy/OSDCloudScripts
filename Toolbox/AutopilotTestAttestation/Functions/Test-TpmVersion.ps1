#Requires -RunAsAdministrator

function Test-TpmVersion {
    Write-host 'Checking if the device has a required TPM 2.0 version' -ForegroundColor Yellow
    $TPMversion = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Query 'Select SpecVersion from win32_tpm' | Select-Object specversion
    if ($TPMVersion.SpecVersion -like '*1.2*') {
        Write-host 'TPM Version is 1.2. Attestation is not going to work!!!!' -ForegroundColor red
    }
    elseif ($TPMVersion.SpecVersion -like '*1.15*') {
        Write-host "TPM Version is 1.15. You are probably running this script on a VM aren't you? Attestation doesn't work on a VM!" -ForegroundColor red
    }
    else {
        Write-host 'TPM Version is 2.0' -ForegroundColor green
    }
}

Test-TpmVersion