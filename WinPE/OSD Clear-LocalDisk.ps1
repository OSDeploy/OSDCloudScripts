#Requires -RunAsAdministrator
#Requires -Modules @{ ModuleName="OSD"; ModuleVersion="23.5.26.1" }
<#
.SYNOPSIS
Clears all local disks on the system.

.DESCRIPTION
This script clears all local disks on the system. It prompts for confirmation before proceeding.
#>
[CmdletBinding()]
param()

if ($env:SystemDrive -eq 'X:') {
    Clear-LocalDisk -Force -ErrorAction Stop
}