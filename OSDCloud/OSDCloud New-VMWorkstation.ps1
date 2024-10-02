#Requires -RunAsAdministrator
#Requires -Modules @{ ModuleName="vmxtoolkit"; ModuleVersion="4.5.3.1" }
#Requires -PSEdition Core
<#
.SYNOPSIS
Creates a new virtual machine in VMware Workstation for OSDCloud.

.DESCRIPTION
This script creates a new virtual machine in VMware Workstation for OSDCloud. It sets the configuration for the virtual machine, including the name, ISO file, memory, processor count, and disk size. It also sets the network adapter, processor, and snapshot for the virtual machine.

.PARAMETER None
This script does not have any parameters.

.EXAMPLE
OSDCloud New-VMWorkstation.ps1
Creates a new virtual machine in VMware Workstation for OSDCloud.
#>
[CmdletBinding()]
param()
#Set VMware Workstation Configuration
$vmName = "OSDCloud $(Get-Random)"
$vmIso = Join-Path $(Get-OSDCloudWorkspace) 'OSDCloud_NoPrompt.iso'
$vmMemory = 16364
$vmProcessorCount = 2
$DiskSize = 100GB

#Create VM
new-VMX -VMXName $vmName -Type windows9-64 -Firmware EFI | New-VMXScsiDisk -NewDiskSize $DiskSize -NewDiskname SCSI0_0 | Add-VMXScsiDisk -LUN 0 -Controller 0 `
 | Connect-VMXcdromImage -ISOfile $vmIso | Set-VMXmemory -VMXName OSDClouDemo -MemoryMB $vmMemory | out-null

 #Set VMX Configuration Settings Network, Processor, and Snapshot
 Set-VMXNetworkAdapter -VMXName $vmName -Adapter 0 -ConnectionType bridged -AdapterType e1000e   -config "$global:vmxdir\$VmName\$VmName.vmx" | out-null
 Set-VMXprocessor -VMXName $vmName -Processorcount $vmProcessorCount -config "$global:vmxdir\$VmName\$VmName.vmx" | out-null
 New-VMXSnapshot -VMXName $vmname -SnapshotName "New-VM" -config "$global:vmxdir\$VmName\$VmName.vmx" | out-null

Start-Sleep -Seconds 3

get-VMX -VMXName $vmName | Start-VMX 