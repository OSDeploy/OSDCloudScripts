#Requires -RunAsAdministrator
#https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs

mdmdiagnosticstool.exe -area 'DeviceEnrollment;DeviceProvisioning;AutoPilot;TPM' -cab "$env:temp\MDMDiagReport-$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-$env:ComputerName.cab"
explorer $env:temp