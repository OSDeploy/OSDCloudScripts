<#
.DESCRIPTION
This is a script that will recreate the partition structure that came on an HP EliteBook 860 G10 factory image.
.LINK
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions-sample-scripts?preserve-view=true&view=windows-10#-createpartitions-uefitxt
#>
$ImageRoot = 'E:\OSDCloud\OS\HP\EliteBook860-5CG3270RZK'

$DiskNumber = 0

#Partition 1
$EfiSize = 260
$EfiLabel = 'System'

#Partition 2 is MSR

#Partition 3 is the OS
$WindowsLabel = 'Windows'
$WindowsDriveLetter = 'C'

$ShrinkSize = 33750

#Partition 4
$Partition4Size = 982
$Partition4Label = 'Windows RE'

#Partition 5 FAT32
$Partition5Size = 1024
$Partition5Label = 'SR_AED'

#Partition 6 is the Recovery Image
$RecoveryImageSize = 31744
$RecoveryImageLabel = 'SR_IMAGE'


$DiskpartScript = @"
rem == CreatePartitions-UEFI.txt ==
rem == These commands are used with DiskPart to
rem    create four partitions
rem    for a UEFI/GPT-based PC.
rem    Adjust the partition sizes to fill the drive
rem    as necessary. ==
select disk $DiskNumber
clean
convert gpt
rem == 1. System partition =========================
create partition efi size=$EfiSize
rem    ** NOTE: For Advanced Format 4Kn drives,
rem               change this value to size = 260 ** 
format quick fs=fat32 label="$EfiLabel"
assign letter="S"
rem == 2. Microsoft Reserved (MSR) partition =======
create partition msr size=16
rem == 3. Windows partition ========================
rem ==    a. Create the Windows partition ==========
create partition primary 
rem ==    b. Create space for the recovery tools ===
rem       ** Update this size to match the size of
rem          the recovery tools (winre.wim)
rem          plus some free space.
shrink minimum=$ShrinkSize
rem ==    c. Prepare the Windows partition ========= 
format quick fs=ntfs label="$WindowsLabel"
assign letter="$WindowsDriveLetter"
rem === 4. Recovery partition ======================
create partition primary size=$Partition4Size
format quick fs=ntfs label="$Partition4Label"
assign letter="R"
set id="de94bba4-06d1-4d40-a16a-bfd50179d6ac"
gpt attributes=0x8000000000000001
rem === 5. FAT32 partition ======================
create partition primary size=$Partition5Size
format quick fs=fat32 label="$Partition5Label"
assign letter="T"
rem === 6. Recovery Image partition ======================
create partition primary
format quick fs=ntfs label="$RecoveryImageLabel"
assign letter="U"
list volume
exit
"@

if ($env:SystemDrive -eq 'X:') {
    $DiskpartScript | Out-File X:\CreatePartitions-UEFI.txt -Encoding ASCII
    DiskPart /s X:\CreatePartitions-UEFI.txt
}
else {
    Write-Warning "This script must be run in WinPE"
}