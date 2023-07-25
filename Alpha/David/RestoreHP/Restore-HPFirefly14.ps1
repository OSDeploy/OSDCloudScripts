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
    $ImageRoot = 'Z:\Firefly14-5CG3281YVJ'
    $ImageDescription = 'Firefly14-5CG3281YVJ'

    # Target Disk
    $DiskNumber = 0

    $ImageFiles = Get-ChildItem -Path $ImageRoot -File
    $ImageFile = $ImageFiles | Where-Object {$_.Extension -eq '.wim'} | Select-Object -ExpandProperty FullName
    $DeployCommand = $ImageFiles | Where-Object {$_.Name -eq 'deploy.cmd'} | Select-Object -ExpandProperty FullName
    $DiskpartScript = $ImageFiles | Where-Object {$_.Name -eq 'ReCreatePartitions.txt'} | Select-Object -ExpandProperty FullName

    if (-not ($ImageFile)) {
        Write-Host -ForegroundColor Red "[!] Could not find a WIM file to restore"
        Break
    }

    if (-not ($DeployCommand)) {
        Write-Host -ForegroundColor Red "[!] Could not find deploy.cmd"
        Break
    }

    if (-not ($DiskpartScript)) {
        Write-Host -ForegroundColor Red "[!] Could not find ReCreatePartitions.txt"
        Break
    }

    # Enable High Performance Power Plan
    Write-Host -ForegroundColor Green "[+] powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    Copy-Item -Path $DeployCommand -Destination "$env:SystemDrive\deploy.cmd" -Force
    Copy-Item -Path $DiskpartScript -Destination "$env:SystemDrive\ReCreatePartitions.txt" -Force

    cmd.exe /c "$env:SystemDrive\deploy.cmd $DiskNumber $ImageFile"

    robocopy $ImageRoot W:\sources *.*

    # Enable Balanced Power Plan
    Write-Host -ForegroundColor Green "[+] powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e"
    powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e
}
else {
    Write-Warning "This script must be run in WinPE"
}