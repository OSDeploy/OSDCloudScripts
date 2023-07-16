#Requires -Modules @{ ModuleName="OSD"; ModuleVersion="23.5.26.1" }
#Requires -RunAsAdministrator
<#
.DESCRIPTION
Clears the Local Disk using the Clear-LocalDisk function in the OSD Module
#>
[CmdletBinding()]
param()

if ($env:SystemDrive -eq 'X:') {
    # Clears all Local Disks.  Prompts for Confirmation
    Clear-LocalDisk -Force -ErrorAction Stop
}