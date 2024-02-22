# Start the Transcript
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Transcript-Start-TPMDiagnostics.log"
$null = Start-Transcript -Path (Join-Path "$env:Temp" $Transcript) -ErrorAction Ignore

#Test the connection to the Microsoft 365 admin center
$Uri = 'https://portal.manage.microsoft.com'

try {
    $response = Invoke-WebRequest -Uri $Uri
}
catch {
    $response = $null
}

if ($response.StatusCode -eq 200) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Test $Uri" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Test $Uri" -ForegroundColor Red
}

#Test URLs
$Server = 'ztd.dds.microsoft.com'
$Port = 443
$NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
if ($NetConnection -eq $true) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Test port $Port on $Server" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Test port $Port on $Server" -ForegroundColor Red
}

$Server = 'ekop.intel.com'
$Port = 443
$NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
if ($NetConnection -eq $true) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Test port $Port on $Server" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Test port $Port on $Server" -ForegroundColor Red
}

$Server = 'ftpm.amd.com'
$Port = 443
$NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
if ($NetConnection -eq $true) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Test port $Port on $Server" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Test port $Port on $Server" -ForegroundColor Red
}

$Server = 'azure.net'
$Port = 443
$NetConnection = (Test-NetConnection -ComputerName $Server -Port $Port).TcpTestSucceeded
if ($NetConnection -eq $true) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Test port $Port on $Server" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Test port $Port on $Server" -ForegroundColor Red
}

#Test Windows Time Service
$W32Time = Get-Service -Name w32time
if ($W32Time.Status -eq 'Running') {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Windows Time Service is $($W32Time.Status)" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Windows Time Service is $($W32Time.Status)" -ForegroundColor Red
}

#Windows License
$WindowsProductKey = (Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
$WindowsProductType = (Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKeyDescription
if ($WindowsProductKey) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: BIOS OA3 Windows ProductKey is $WindowsProductKey" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: BIOS OA3 Windows ProductKey is $WindowsProductKey" -ForegroundColor Red
}
if ($WindowsProductType) {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: BIOS OA3 Windows ProductKeyDescription is $WindowsProductType" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: BIOS OA3 Windows ProductKeyDescription is $WindowsProductType" -ForegroundColor Red
}

if ($WindowsProductType -like '*Professional*' -or $WindowsProductType -eq 'Windows 10 Pro' -or $WindowsProductType -like '*Enterprise*') {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: BIOS Windows license is valid for Microsoft 365" -ForegroundColor Green
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: BIOS Windows license is not valid for Microsoft 365" -ForegroundColor Red
    $WindowsProductType = Get-ComputerInfo | Select-Object WindowsProductName 
    $WindowsProductType = $WindowsProductType.WindowsProductName
    
    if ($WindowsProductType -like '*Professional*' -or $WindowsProductType -eq 'Windows 10 Pro' -or $WindowsProductType -like '*Enterprise*') {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: Software Windows license is valid for Microsoft 365" -ForegroundColor Green
    }
    else {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: Software Windows license is not valid for Microsoft 365" -ForegroundColor Red
    }
}
#TPM Version
$TPMversion = Get-WmiObject -Namespace 'root\cimv2\security\microsofttpm' -Query 'Select SpecVersion from win32_tpm' | Select-Object SpecVersion
if ($TPMVersion.SpecVersion -like '*1.2*') {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: TPM version is 1.2 and does not support attestation" -ForegroundColor Red
}
elseif ($TPMVersion.SpecVersion -like '*1.15*') {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) FAIL: TPM version is 1.15 and does not support attestation" -ForegroundColor Red
}
else {
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) PASS: TPM version is 2.0 and does support attestation" -ForegroundColor Green
}

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
                    Write-Host ('This Infineon firmware version {0}.{1} TPM is not safe. Please update your firmware.' -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor red
                }
                else {
                    Write-Host ('This Infineon firmware version {0}.{1} TPM is safe.' -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green

                    if (!$FirmwareVersionAtLastProvision) {
                        Write-Host ('We cannot determine what the firmware version was when the TPM was last cleared. Please clear your TPM now that the firmware is safe.') -ForegroundColor red
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



Stop-Transcript