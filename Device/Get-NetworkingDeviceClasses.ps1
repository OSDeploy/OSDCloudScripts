Get-WmiObject -Class Win32_NetworkAdapter | Select-Object -Property *
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Select-Object -Property *
Get-WmiObject -Class Win32_NetworkAdapterSetting | Select-Object -Property *