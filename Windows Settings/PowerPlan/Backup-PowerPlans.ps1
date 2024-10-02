<#
.SYNOPSIS
This script exports the Power Plans registry key and opens it in Notepad.

.DESCRIPTION
The Backup-PowerPlans.ps1 script exports the Power Plans registry key to a temporary file and opens it in Notepad.
This can be useful for backing up your Power Plans settings or for troubleshooting Power Plans issues.
#>
reg export HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings "$env:Temp\PowerSettings.reg"
notepad "$env:Temp\PowerSettings.reg"