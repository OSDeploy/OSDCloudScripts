Get-WmiObject -Class Win32_PortableBattery | Select-Object -Property *

<#
if ($BatteryRunTime -eq [Math]::Round([Math]::Pow(2,32) / 60))
{
    $BatteryRunTimeText = ""
}
else
{
    $BatteryRunTimeText = "(" + $BatteryRunTime + " minutes runtime)"
}
#>