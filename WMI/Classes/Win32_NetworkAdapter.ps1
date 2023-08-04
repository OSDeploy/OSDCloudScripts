Get-WmiObject -Class Win32_NetworkAdapter | Select-Object -Property * | Where-Object GUID


Get-WmiObject -Class Win32_NetworkAdapter | Select-Object -Property * | Where-Object GUID