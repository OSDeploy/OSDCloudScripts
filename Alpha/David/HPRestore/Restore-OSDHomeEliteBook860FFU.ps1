#Requires -RunAsAdministrator
<#
.DESCRIPTION
This is a script that will recreate the partition structure that came on an HP EliteBook 860 G10 factory image.
.LINK
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions-sample-scripts?preserve-view=true&view=windows-10#-createpartitions-uefitxt
#>

# Map to the Images
net use Z: \\OSDHome\Data\Images\HP /user:OSDHome\OSDCloud

# Set the ImageRoot
$ImageRoot = 'Z:\EliteBook860-5CG3270RZK'

# Target Disk
$DiskNumber = 0

$DiskpartScript = @"
select disk $DiskNumber
clean
exit
"@

if ($env:SystemDrive -eq 'X:') {
    if (Test-Path "$ImageRoot\image.ffu") {
        $DiskpartScript | Out-File X:\CreatePartitions-UEFI.txt -Encoding ASCII
        Write-Host -ForegroundColor Yellow "[!] DiskPart /s X:\CreatePartitions-UEFI.txt"
        DiskPart /s X:\CreatePartitions-UEFI.txt

        Write-Host -ForegroundColor Green "[+] powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        # Apply FFU
        Write-Host -ForegroundColor Yellow "[!] DISM.exe /Apply-FFU /ImageFile=$ImageRoot\image.ffu /ApplyDrive=\\.\PhysicalDrive$DiskNumber"
        DISM.exe /Apply-FFU /ImageFile=$ImageRoot\image.ffu /ApplyDrive=\\.\PhysicalDrive$DiskNumber

        # Enable Balanced Power Plan
        Write-Host -ForegroundColor Green "[+] powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e"
        powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e
    }
}
else {
    Write-Warning "This script must be run in WinPE"
}