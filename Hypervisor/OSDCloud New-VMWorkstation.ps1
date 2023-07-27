<#PSScriptInfo
.VERSION 23.7.27.2
.GUID 07e82d88-755f-4160-95c7-db11c8f0c633
.AUTHOR Jerome Bezet-Torres
.COMPANYNAME Jérôme Bezet-Torres
.COPYRIGHT (c) 2023 Jérôme Bezet-Torres. All rights reserved.
.TAGS OSD OSDCloud VMware
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.DESCRIPTION
This script will search the an OSDCloud Workspace for the latest ISO and create a VMware Workstation VM
#>
[CmdletBinding()]
param()
#Requires -Modules @{ ModuleName="vmxtoolkit"; ModuleVersion="4.5.3.1" }
#Requires -PSEdition Core



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