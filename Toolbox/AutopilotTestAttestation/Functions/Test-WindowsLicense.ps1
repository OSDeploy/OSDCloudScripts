function Test-WindowsLicense {

    $WindowsProductKey = (Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKey
    $WindowsProductType = (Get-WmiObject -query 'select * from SoftwareLicensingService').OA3xOriginalProductKeyDescription

    Write-Host "[BIOS] Windows Product Key: $WindowsProductKey" -ForegroundColor Yellow
    Write-Host "[BIOS] Windows Product Type: $WindowsProductType" -ForegroundColor Yellow


    If ($WindowsProductType -like '*Professional*' -or $WindowsProductType -eq 'Windows 10 Pro' -or $WindowsProductType -like '*Enterprise*') {
        Write-Host 'BIOS Windows license is suited for MS365 enrollment' -ForegroundColor Green
    }
    else {
        Write-Host 'BIOS Windows license is not suited for MS365 enrollment' -ForegroundColor red
        $WindowsProductType = get-computerinfo | Select-Object WindowsProductName 
        $WindowsProductType = $WindowsProductType.WindowsProductName
    
        Write-Host "[SOFTWARE] Windows Product Key: $WindowsProductKey" -ForegroundColor Yellow
        Write-Host "[SOFTWARE] Windows Product Type: $WindowsProductType" -ForegroundColor Yellow
    
        If ($WindowsProductType -like '*Professional*' -or $WindowsProductType -eq 'Windows 10 Pro' -or $WindowsProductType -like '*Enterprise*') {
            Write-Host 'SOFTWARE Windows license is valid for MS365 enrollment' -ForegroundColor Green
        }
        else {
            Write-Host 'SOFTWARE Windows license is not valid for MS365 Enrollment' -ForegroundColor red
        }
    }
}