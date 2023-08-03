#Requires -Modules @{ ModuleName="OSD"; ModuleVersion="23.5.26.1" }
#Requires -PSEdition Desktop
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Adds Windows capabilities to the current operating system.

.DESCRIPTION
This script adds Windows capabilities to the current operating system. It checks if the specified capabilities are already installed and installs them if they are not.

.PARAMETER Category
Specifies the category of the Windows capabilities to install.

.EXAMPLE
Add-WindowsCapability -Category Rsat

This example installs the Remote Server Administration Tools (RSAT) on the current operating system.

.NOTES
Author: Your Name
Date: Today's Date
#>
$Result = Get-MyWindowsCapability -Category Rsat -Detail
foreach ($Item in $Result) {
    if ($Item.State -eq 'Installed') {
        Write-Host -ForegroundColor DarkGray "$($Item.DisplayName)"
    }
    else {
        Write-Host -ForegroundColor DarkCyan "$($Item.DisplayName)"
        $Item | Add-WindowsCapability -Online -ErrorAction Ignore | Out-Null
    }
}

# get last boot up time
$LastBootUpTime = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime

# schedule a reboot in task scheduler
$TaskName = 'Reboot'
$TaskAction = New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /t 0'
$TaskTrigger = New-ScheduledTaskTrigger -Once -At $LastBootUpTime
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -DontStopIfGoingOnInternet
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Task = New-ScheduledTask -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -Principal $TaskPrincipal
Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force | Out-Null

