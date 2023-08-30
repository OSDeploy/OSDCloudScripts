﻿$Events = Get-WinEvent -LogName 'Microsoft-Windows-WLAN-AutoConfig/Operational'
$Events | Where-Object {$_.ID -in @(8000,8001,8002,8003)} | Select-Object -Property TimeCreated,ID,ProviderName,LevelDisplayName,OpcodeDisplayName,Message,Properties | OGV