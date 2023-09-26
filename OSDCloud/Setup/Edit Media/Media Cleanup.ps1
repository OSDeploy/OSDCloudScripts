#Requires -Modules @{ ModuleName="OSD"; ModuleVersion="23.5.26.1" }
#Requires -RunAsAdministrator
<#
.DESCRIPTION
If you're not a fan of all the extra files in the Media folder, this script will remove them.
.LINK
https://www.osdcloud.com
#>
[CmdletBinding()]
param()

$KeepTheseDirs = @('boot','efi','en-us','osdcloud','sources','fonts','resources')

Get-ChildItem "$(Get-OSDCloudWorkspace)\Media" | `
Where-Object {$_.PSIsContainer} | `
Where-Object {$_.Name -notin $KeepTheseDirs} | `
Remove-Item -Recurse -Force

Get-ChildItem "$(Get-OSDCloudWorkspace)\Media\Boot" | `
Where-Object {$_.PSIsContainer} | `
Where-Object {$_.Name -notin $KeepTheseDirs} | `
Remove-Item -Recurse -Force

Get-ChildItem "$(Get-OSDCloudWorkspace)\Media\EFI\Microsoft\Boot" | `
Where-Object {$_.PSIsContainer} | `
Where-Object {$_.Name -notin $KeepTheseDirs} | `
Remove-Item -Recurse -Force

New-OSDCloudISO