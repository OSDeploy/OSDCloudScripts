#Requires -RunAsAdministrator
<#
.DESCRIPTION
This is a script that will recreate the partition structure that came on an HP EliteBook 860 G10 factory image.
.LINK
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions-sample-scripts?preserve-view=true&view=windows-10#-createpartitions-uefitxt
#>

# Map to the Images
net use Z: \\OSDHome\Data\Images\HP /user:OSDHome\OSDCloud

# Set the ImageRoot and ImageDescription
$ImageRoot = 'Z:\EliteBook860-5CG3270RZK'
$ImageDescription = 'EliteBook860-5CG3270RZK'

# Target Disk
$DiskNumber = 0

#Partition 1
$EfiSize = 260
$EfiLabel = 'System'

#Partition 2 is MSR

#Partition 3 is the OS
$WindowsLabel = 'Windows'
$WindowsDriveLetter = 'W'

$ShrinkSize = 982

#Partition 4
$Partition4Size = 982
$Partition4Label = 'Windows RE'

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
list volume
exit
"@

$ReAgentXmlPath = 'W:\Windows\System32\Recovery\ReAgent.xml'

$ReAgentXml = @'
<?xml version='1.0' encoding='utf-8'?>

<WindowsRE version="2.0">
  <WinreBCD id="{00000000-0000-0000-0000-000000000000}"/>
  <WinreLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <ImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <PBRImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}" index="0"/>
  <PBRCustomImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}" index="0"/>
  <InstallState state="0"/>
  <OsInstallAvailable state="0"/>
  <CustomImageAvailable state="0"/>
  <IsAutoRepairOn state="0"/>
  <WinREStaged state="0"/>
  <OperationParam path=""/>
  <OperationPermanent state="0"/>
  <OsBuildVersion path=""/>
  <OemTool state="0"/>
  <IsServer state="0"/>
  <DownlevelWinreLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <IsWimBoot state="0"/>
  <NarratorScheduled state="0"/>
  <ScheduledOperation state="0"/>
</WindowsRE>
'@

if ($env:SystemDrive -eq 'X:') {
    $DiskpartScript | Out-File X:\CreatePartitions-UEFI.txt -Encoding ASCII
    DiskPart /s X:\CreatePartitions-UEFI.txt

    if (Test-Path "$ImageRoot\1-SYSTEM.wim") {
        
        # Enable High Performance Power Plan
        powercfg.exe -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

        Expand-WindowsImage -ApplyPath S:\ -ImagePath "$ImageRoot\1-SYSTEM.wim" -Index 1
        Expand-WindowsImage -ApplyPath W:\ -ImagePath "$ImageRoot\3-Windows.wim" -Index 1
        Expand-WindowsImage -ApplyPath R:\ -ImagePath "$ImageRoot\4-Windows RE Tools.wim" -Index 1

        # Cleanup System Partition
        Remove-Item -Path S:\EFI\Boot -Recurse -Force
        Remove-Item -Path S:\EFI\Microsoft -Recurse -Force

        # Move Recovery back to Windows
        Robocopy R:\Recovery\WindowsRE W:\Windows\System32\Recovery /E

        # Reset ReAgent.xml since Disk GUIDS have changed
        $ReAgentXml | Out-File -FilePath $ReAgentXmlPath -Encoding UTF8 -Force

        # Cleanup existing Recovery Partition but leave the tag
        Remove-Item -Path R:\Recovery -Force -Recurse

        # Set Boot Partition
        W:\Windows\System32\bcdboot.exe W:\Windows /v /p

        # Capture FFU
        DISM.exe /Capture-FFU /ImageFile=$ImageRoot\capture.ffu /CaptureDrive=\\.\PhysicalDrive0 /Name:disk0 /Description:"$ImageDescription"

        # Enable Balanced Power Plan
        powercfg.exe -SetActive 381b4222-f694-41f0-9685-ff5bb260df2e

        # Optimize FFU
        # DISM.exe /Optimize-FFU /ImageFile:"$ImageRoot\capture.ffu"
    }
}
else {
    Write-Warning "This script must be run in WinPE"
}