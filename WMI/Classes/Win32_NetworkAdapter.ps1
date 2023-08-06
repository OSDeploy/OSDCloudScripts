Get-WmiObject -Class Win32_NetworkAdapter | Select-Object -Property * | OGV


Get-WmiObject -Class Win32_NetworkAdapter | Select-Object -Property * | Where-Object GUID