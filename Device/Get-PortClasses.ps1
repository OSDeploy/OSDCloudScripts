Get-WmiObject -Class Win32_ParallelPort | Select-Object -Property *
Get-WmiObject -Class Win32_PortConnector | Select-Object -Property *
Get-WmiObject -Class Win32_PortResource | Select-Object -Property *
Get-WmiObject -Class Win32_SerialPort | Select-Object -Property *
Get-WmiObject -Class Win32_SerialPortConfiguration | Select-Object -Property *
Get-WmiObject -Class Win32_SerialPortSetting | Select-Object -Property *