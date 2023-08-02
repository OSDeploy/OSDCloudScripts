Get-WmiObject -Class Win32_DesktopMonitor | Select-Object -Property *
Get-WmiObject -Class Win32_DisplayControllerConfiguration | Select-Object -Property *
Get-WmiObject -Class Win32_VideoController | Select-Object -Property *
Get-WmiObject -Class Win32_VideoSettings | Select-Object -Property *