#Requires -RunAsAdministrator
#Requires -Modules @{ ModuleName="OSD"; ModuleVersion="23.5.26.1" }
<#
.SYNOPSIS
Creates a new disk layout for a Windows operating system.

.DESCRIPTION
The New-OSDisk.ps1 script creates a new disk layout for a Windows operating system. It clears all local disks and automatically creates the partition layout with a recovery partition based on the boot method. It prompts for confirmation before clearing the disks.

.PARAMETER PartitionStyle
Specifies the partition style for the disk. Valid values are MBR and GPT. The default value is GPT.

.PARAMETER NoRecoveryPartition
Indicates that the recovery partition should not be created. This parameter is only valid when the PartitionStyle parameter is set to GPT.

.EXAMPLE
New-OSDisk.ps1
Creates a new disk layout with a recovery partition based on the boot method.

.EXAMPLE
New-OSDisk.ps1 -PartitionStyle GPT -NoRecoveryPartition
Creates a new disk layout without a recovery partition using the GPT partition style.

.NOTES
This script requires administrative privileges to run.
It also requires the OSD module version 23.5.26.1 or later.
#>
[CmdletBinding()]
param()

# Make sure we are in WinPE
if ($env:SystemDrive -eq 'X:') {

    # Remove attached USB Drives
    if (Get-USBDisk) {
        do {
            Write-Warning "Remove all attached USB Drives New-OSDisk is complete"
            pause
        }
        while (Get-USBDisk)
    }

    # Clears all Local Disks
    # Automatically creates the Partition Layout with Recovery Partition based on the Boot Method
    # Will prompt for confirmation before clearing the disks
    New-OSDisk -Force -ErrorAction Stop
}

<#
Other options for New-OSDisk

New-OSDisk -PartitionStyle GPT -Force
    System = 260MB
    MSR = 16MB
    Windows = *
    Recovery = 990MB
=========================================================================
| SYSTEM | MSR |                    WINDOWS                  | RECOVERY |
=========================================================================

New-OSDisk -PartitionStyle GPT -Force -NoRecoveryPartition
    System = 260MB
    MSR = 16MB
    Windows = *
This layout is ideal for Generation 2 Virtual Machines
=========================================================================
| SYSTEM | MSR |                    WINDOWS                             |
=========================================================================

New-OSDisk -PartitionStyle MBR -Force
    System = 260MB
    Windows = *
    Recovery = 990MB
=========================================================================
| SYSTEM |                          WINDOWS                  | RECOVERY |
=========================================================================

New-OSDisk -PartitionStyle MBR -Force -NoRecoveryPartition
    System = 260MB
    Windows = *
This layout is ideal for Generation 1 Virtual Machines
=========================================================================
| SYSTEM |                          WINDOWS                             |
=========================================================================
#>