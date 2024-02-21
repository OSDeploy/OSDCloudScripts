#Requires -RunAsAdministrator

<#
.SYNOPSIS
This script runs the mdmdiagnosticstool.exe with specific areas and generates a .cab file with the diagnostics report.

.DESCRIPTION
The script requires to be run as an administrator. It uses the mdmdiagnosticstool.exe to collect logs from the areas 'DeviceEnrollment;DeviceProvisioning;AutoPilot;TPM'. The logs are stored in a .cab file in the temp directory. The file name includes the current date, time, and computer name. After the .cab file is created, the temp directory is opened in the file explorer.

.PARAMETER None
This script does not take any parameters.

.EXAMPLE
.\New-MDMDiagnostics.ps1

This will run the script and generate a .cab file with the diagnostics report in the temp directory.

.LINK
https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs

.NOTES
Make sure to run this script as an administrator.
#>
mdmdiagnosticstool.exe -area 'DeviceEnrollment;DeviceProvisioning;AutoPilot;TPM' -cab "$env:temp\$env:ComputerName-$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-MDMDiagReport.cab"
explorer $env:temp