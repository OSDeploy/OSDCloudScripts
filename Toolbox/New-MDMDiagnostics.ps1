#Requires -RunAsAdministrator
#https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs

mdmdiagnosticstool.exe -area "DeviceEnrollment;DeviceProvisioning;AutoPilot;TPM" -cab $env:TEMP\MDMDiagReport-$env:ComputerName.cab
