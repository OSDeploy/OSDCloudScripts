#Requires -RunAsAdministrator
Get-WmiObject -Class Win32_InstalledStoreProgram | Select-Object -Property *