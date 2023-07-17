<#
.DESCRIPTION
Creates a new Battery Report using Powercfg.exe
.LINK
https://support.microsoft.com/en-us/windows/caring-for-your-battery-in-windows-2db3e37f-5e7d-488e-9086-ed15320519e4
#>
powercfg.exe /batteryreport /output "$env:TEMP\BatteryReport.html"
Invoke-Item "$env:TEMP\BatteryReport.html"