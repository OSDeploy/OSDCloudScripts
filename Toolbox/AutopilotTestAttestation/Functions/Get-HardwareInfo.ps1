function Get-HardwareInfo { 
    # Apparaat Info
    $SerialNoRaw = wmic bios get serialnumber
    $SerialNo = $SerialNoRaw[2]
    
    $ManufacturerRaw = wmic computersystem get manufacturer
    $Manufacturer = $ManufacturerRaw[2]
    
    $ModelNoRaw = wmic computersystem get model
    $ModelNo = $ModelNoRaw[2]
    
    Write-Host "Computer Serialnumber: `t $SerialNo" -ForegroundColor Yellow
    Write-Host "Computer Supplier: `t $Manufacturer" -ForegroundColor Yellow
    Write-Host "Computer Model: `t $ModelNo" -ForegroundColor Yellow
    write-host "`n"
}

Get-HardwareInfo