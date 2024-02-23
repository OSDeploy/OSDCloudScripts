# Start the Transcript
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Transcript-Start-TPMDiagnostics.log"
$null = Start-Transcript -Path (Join-Path "$env:Temp" $Transcript) -ErrorAction Ignore


#Test TPM firmware
$IfxManufacturerIdInt = 0x49465800 # 'IFX'
function IsInfineonFirmwareVersionAffected ($FirmwareVersion) {
    $FirmwareMajor = $FirmwareVersion[0]
    $FirmwareMinor = $FirmwareVersion[1]
    switch ($FirmwareMajor) {
        4 { return $FirmwareMinor -le 33 -or ($FirmwareMinor -ge 40 -and $FirmwareMinor -le 42) }
        5 { return $FirmwareMinor -le 61 }
        6 { return $FirmwareMinor -le 42 }
        7 { return $FirmwareMinor -le 61 }
        133 { return $FirmwareMinor -le 32 }
        default { return $False }
    }
}
function IsInfineonFirmwareVersionSusceptible ($FirmwareMajor) {
    switch ($FirmwareMajor) {
        4 { return $True }
        5 { return $True }
        6 { return $True }
        7 { return $True }
        133 { return $True }
        default { return $False }
    }
}
$Tpm = Get-Tpm
$ManufacturerIdInt = $Tpm.ManufacturerId
$FirmwareVersion = $Tpm.ManufacturerVersion -split '\.'
$FirmwareVersionAtLastProvision = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI' -Name 'FirmwareVersionAtLastProvision' -ErrorAction SilentlyContinue).FirmwareVersionAtLastProvision
if (!$Tpm) {
    Write-Host 'No TPM found on this system, so the issue does not apply here.'
}
else {
    if ($ManufacturerIdInt -ne $IfxManufacturerIdInt) {
        #Write-Host 'This non-Infineon TPM is not affected by the issue.' -ForegroundColor green
    }
    else {
        if ($FirmwareVersion.Length -lt 2) {
            Write-Error 'Could not get TPM firmware version from this TPM.'
        }
        else {
            if (IsInfineonFirmwareVersionSusceptible($FirmwareVersion[0])) {
                if (IsInfineonFirmwareVersionAffected($FirmwareVersion)) {
                    Write-Warning ('This Infineon firmware version {0}.{1} TPM is not safe. Please update your firmware.' -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1])
                }
                else {
                    Write-Host ('This Infineon firmware version {0}.{1} TPM is safe.' -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green

                    if (!$FirmwareVersionAtLastProvision) {
                        Write-Warning ('We cannot determine what the firmware version was when the TPM was last cleared. Please clear your TPM now that the firmware is safe.')
                    }
                    elseif ($FirmwareVersion -ne $FirmwareVersionAtLastProvision) {
                        Write-Host ('The firmware version when the TPM was last cleared was different from the current firmware version. Please clear your TPM now that the firmware is safe.') -ForegroundColor yellow
                    }
                }
            }
            else {
                Write-Host ('This Infineon firmware version {0}.{1} TPM is safe.' -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green
            }
        }
    }
}

$OOBERegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE'
$SetupDisplayedEula = "SetupDisplayedEula"


Stop-Transcript

Break

if ($IsReadyInformation -eq '262144') {
    Write-Warning "Ek Certificate seems to be missing, let's try to fix it!"
    Start-ScheduledTask -TaskPath '\Microsoft\Windows\TPM\' -TaskName 'Tpm-Maintenance' -erroraction 'silentlycontinue'
    Start-Sleep 5
    $taskinfo = Get-ScheduledTaskInfo -TaskName '\Microsoft\Windows\TPM\Tpm-Maintenance' -ErrorAction Ignore
    $tasklastruntime = $taskinfo.LastTaskResult  
    if ($tasklastruntime -ne 0) {
        Write-Warning 'Reason: TPM-Maintenance Task could not be run! Checking and Configuring the EULA Key!'
    }
    if ((!(Get-ItemProperty -Path $OOBERegPath -Name $SetupDisplayedEula -ErrorAction Ignore)) -or ((Get-ItemProperty -Path $OOBERegPath -Name $SetupDisplayedEula -ErrorAction Ignore).SetupDisplayedEula -ne 1)) {
        Write-Warning 'Reason: Registervalue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE\SetupDisplayedEula does not exist! EULA is not accepted!'
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE\' -Name 'SetupDisplayedEula' -Value '1' -PropertyType 'DWORD' –Force | Out-null
        Write-Host 'SetupDisplayedEula registry key configured, rerunning the TPM-Maintanence Task' -ForegroundColor Yellow
        Start-ScheduledTask -TaskPath '\Microsoft\Windows\TPM\' -TaskName 'Tpm-Maintenance' -erroraction 'silentlycontinue'  
    }
    Start-Sleep 5
    $taskinfo = Get-ScheduledTaskInfo -TaskName '\Microsoft\Windows\TPM\Tpm-Maintenance' -ErrorAction Ignore
    $tasklastruntime = $taskinfo.LastTaskResult  
    if ($tasklastruntime -ne 0) {
        Write-Warning 'TPM-Maintenance task could not be run succesfully despite the EULA key being set! Exiting now!'
    }
    if ($tasklastruntime -eq 0) {
        Write-Host 'EULA Key is set and TPM-Maintenance Task has been run without issues' -ForegroundColor Green
        Write-Host "Please note, this doesn't mean the TPM-Maintenance task did its job! Let's test it again" -ForegroundColor yellow
        Write-Host "`n"
    }
}

if (!(test-path -path HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*)) {
    Write-Warning 'Reason:EKCert seems still to be missing in HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\ - Launching TPM-Maintenance Task again!'
    Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue' 
    Start-Sleep -Seconds 5
    Write-Host "`n"
    Write-Host "Going hardcore! Trying to install that damn EkCert on our own!!" -ForegroundColor yellow

    rundll32 tpmcoreprovisioning.dll,TpmPrepForNgc
    rundll32 tpmcoreprovisioning.dll,TpmProvision
    rundll32 tpmcoreprovisioning.dll,TpmCertInstallNvEkCerts
    rundll32 tpmcoreprovisioning.dll,TpmCertGetEkCertFromWeb
    rundll32 tpmcoreprovisioning.dll,TpmRetrieveEkCertOrReschedule
    Start-Sleep 5
    rundll32 tpmcoreprovisioning.dll,TpmVerifyDeviceHealth
    rundll32 tpmcoreprovisioning.dll,TpmRetrieveHealthCertOrReschedule
    Start-Sleep 5
    rundll32 tpmcoreprovisioning.dll,TpmCertGetWindowsAik
    rundll32 tpmcoreprovisioning.dll,TpmCheckCreateWindowsAIK
    rundll32 tpmcoreprovisioning.dll,TpmEnrollWindowsAikCertificate 
}

$endorsementkey = get-tpmendorsementkeyinfo   
if ($endorsementkey.IsPresent -ne $true) {
    Write-Warning 'Endorsementkey still not present!!'
}
else {
    Write-Host "Endorsementkey reporting for duty!" -ForegroundColor green
    Write-Host "Checking if the Endorsementkey has its required certificates attached" -ForegroundColor yellow

    $manufacturercerts = (TpmEndorsementKeyInfo).ManufacturerCertificates 
    $additionalcerts = (Get-TpmEndorsementKeyInfo).AdditionalCertificates

    if (((!$additionalcerts) -and (!$manufacturercerts))) {
        Write-Host "`n"
        Write-Warning 'This is definitely not good! Additional and/or ManufacturerCerts are missing!'
    }
    else {
    Write-Host "We have found one of the required certificates" -ForegroundColor green
    $additionalcerts
    $manufacturercerts
    Write-Host "`n"
    }
}          

#geting AIK Test CertEnroll error
$IsReady = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'Isreadyinformation'
$IsReadyInformation = $IsReady.Information

if ($IsReadyInformation -eq "0") {
    Write-Host "Retrieving AIK Certificate....." -ForegroundColor Green

    $errorcert = 1
    for ($num = 1 ; $errorcert -ne -1 ; $num++) {
    Write-Host "Fetching test-AIK cert - attempt $num"
    $certcmd = (cmd.exe /c "certreq -q -enrollaik -config """)

    $startcert  = [array]::indexof($certcmd,"-----BEGIN CERTIFICATE-----")
    $endcert    = [array]::indexof($certcmd,"-----END CERTIFICATE-----")
    $errorcert  = [array]::indexof($certcmd,'{"Message":"Failed to parse SCEP request."}')

    Write-Host "Checking the Output to determine if the AIK CA Url is valid!" -ForegroundColor yellow

    $Cacapserror = $CERTCMD -like "*GetCACaps: Not Found*"
    if ($CaCapserror) {
        Write-Warning "AIK CA Url is not valid"
    }
    else {
        Write-Host "AIK CA Url seems valid" -ForegroundColor Green
    }

    $certlength = $endcert - $startcert
    if ($certlength -gt 1) {
        Write-Host "Found Test AIK Certificate" -ForegroundColor Green
        $cert = $certcmd[$startcert..$endcert]
        Write-Host "`n"
        Write-Host $cert -ForegroundColor DarkGreen
        Write-Host "`n"
        Write-Host "AIK Test AIK Enrollment succeeded" -ForegroundColor Green
    }
    else {
            Write-Warning 'AIK TEST Certificate could not be retrieved'
        if ($num -eq 10) {
            Write-Warning "Retried 10 times, killing process"
        }
    }
}

#fetching AIkCertEnrollError
Write-Host "Running another test, to determine if the TPM is capable for key attestation... just for fun!!" -ForegroundColor Yellow

$IsReadycapable = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'IsKeyAttestationCapable'
$IsReadycapable = $IsReadycapable.testresult

if ($IsReadycapable -ne 0) {
    Write-Warning "Reason: TPM doesn't seems capable for Attestation!"
    tpmtool getdeviceinformation 
}
else {
    Write-Host "We can almost start celebrating! Because the TPM is capable for attestation! "-ForegroundColor green
}

Write-Host "Launching the real AikCertEnroll task!" -ForegroundColor Yellow
Start-ScheduledTask -TaskPath "\Microsoft\Windows\CertificateServicesClient\" -TaskName "AikCertEnrollTask"
Start-Sleep -Seconds 5

$AIKError = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\AIKCertEnroll\"
if ((Get-ItemProperty -Path $AIKError -Name "ErrorCode" -ErrorAction Ignore).errorcode -ne 0) {
    Write-Warning "Reason: AIK Cert Enroll Failed!"
    tpmtool getdeviceinformation
}
else {
        Write-Host "`n"
        Write-Host "AIK Cert Enroll Task Succeeded, Looks like the device is 100% Ready for Attestation! You can start the Autopilot Pre-Provioning!"-ForegroundColor green
        $Form.ShowDialog()
    }
}
else {
    Write-Host "`n"
    Write-Warning 'TPM is still NOT suited for Autopilot Pre-Provisioning,  please re-run the test again'
}