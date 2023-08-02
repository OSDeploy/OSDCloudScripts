Get-WmiObject -Class Win32_Battery | Select-Object -Property *
Get-WmiObject -Class Win32_CurrentProbe | Select-Object -Property *
Get-WmiObject -Class Win32_PortableBattery | Select-Object -Property *
Get-WmiObject -Class Win32_PowerManagementEvent	 | Select-Object -Property *
Get-WmiObject -Class Win32_VoltageProbe | Select-Object -Property *