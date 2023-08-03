$ClassName = 'Win32_PerfFormattedData_Counters_FileSystemDiskActivity'

Get-CimInstance -ClassName $ClassName | Select-Object -Property *