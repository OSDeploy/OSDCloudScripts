#Requires -RunAsAdministrator
<#
.DESCRIPTION
This is a script that will recreate the partition structure that came on an HP EliteBook 860 G10 factory image.
.LINK
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions-sample-scripts?preserve-view=true&view=windows-10#-createpartitions-uefitxt
#>
if ($env:SystemDrive -eq 'X:') {

    # Map to the Images
    net use Z: \\OSDHome\Data\Images\HP /user:OSDHome\OSDCloud

    # Set the ImageRoot and ImageDescription
    $ImageRoot = 'Z:\EliteBook830-5CG325677M'
    $ImageDescription = 'EliteBook830-5CG325677M'

    # Target Disk
    $DiskNumber = 0

    $ImageFile = Get-ChildItem -Path $ImageRoot *.wim -File | Select-Object -ExpandProperty FullName

    if (-not ($ImageFile)) {
        Write-Host -ForegroundColor Red "[!] Could not find a WIM file to restore"
        Break
    }

    if (-not (Test-Path "$ImageRoot\deploy.cmd")) {
        Write-Host -ForegroundColor Red "[!] Could not find deploy.cmd"
        Break
    }

    if (-not (Test-Path "$ImageRoot\ReCreatePartitions.txt")) {
        Write-Host -ForegroundColor Red "[!] Could not find ReCreatePartitions.txt"
        Break
    }

    # Enable High Performance Power Plan
    Write-Host -ForegroundColor Green "[+] powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    cmd.exe /c "$ImageRoot\deploy.cmd $DiskNumber $ImageFile"

    # Enable Balanced Power Plan
    Write-Host -ForegroundColor Green "[+] powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e"
    powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e
}
else {
    Write-Warning "This script must be run in WinPE"
}