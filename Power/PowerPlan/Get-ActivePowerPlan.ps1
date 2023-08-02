#Requires -RunAsAdministrator
Get-CimInstance -Namespace "root\cimv2\power" -ClassName Win32_PowerPlan | Where-Object {$_.IsActive -eq $true}