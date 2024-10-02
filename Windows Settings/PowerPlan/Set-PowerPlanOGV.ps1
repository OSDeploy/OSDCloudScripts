#Requires -RunAsAdministrator
<#
.SYNOPSIS
    This script allows you to select and activate a power plan on your Windows device.

.DESCRIPTION
    The Set-PowerPlanOGV.ps1 script allows you to select a power plan from a list of available power plans on your Windows device.
    Once you have selected a power plan, the script activates it.

.PARAMETER None
    This script does not accept any parameters.

.EXAMPLE
    C:\PS> .\Set-PowerPlanOGV.ps1
    This example runs the Set-PowerPlanOGV.ps1 script, which displays a list of available power plans on your Windows device. You can select a power plan from the list, and the script will activate it.

.NOTES
    Author: Your Name
    Date: Today's Date
    Version: 1.0
#>
$ElementName = Get-CimInstance -Namespace "root\cimv2\power" -ClassName Win32_PowerPlan | Select-Object -ExpandProperty ElementName | Out-GridView -Title "Select a power plan" -OutputMode Single
$PowerPlan = Get-CimInstance -Namespace "root\cimv2\power" -ClassName Win32_PowerPlan | Where-Object {$_.ElementName -eq $ElementName}
Invoke-CimMethod -InputObject $PowerPlan -MethodName Activate | Out-Null