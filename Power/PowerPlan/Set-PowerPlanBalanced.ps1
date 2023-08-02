#Requires -RunAsAdministrator
<#
.SYNOPSIS
Sets the power plan to Balanced.

.DESCRIPTION
This script sets the power plan to Balanced using the Win32_PowerPlan WMI class.

.PARAMETER None
This script does not accept any parameters.

.EXAMPLE
Set-PowerPlanBalanced.ps1
Sets the power plan to Balanced.

.NOTES
File Name: Set-PowerPlanBalanced.ps1
Author   : David Segura
#>
$PowerPlan = Get-CimInstance -Namespace "root\cimv2\power" -ClassName Win32_PowerPlan | Where-Object {$_.ElementName -eq 'Balanced'}
Invoke-CimMethod -InputObject $PowerPlan -MethodName Activate | Out-Null