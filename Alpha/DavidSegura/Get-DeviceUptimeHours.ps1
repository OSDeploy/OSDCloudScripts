function Get-DeviceUptimeHours {
    [CmdletBinding()]
    param()

    # WMI LastBootUpTime is not a restart measure, but when the system was last restarted or hibernated
    # i.e. a device can hibernate every night for a month and never restart, but this appears to be a restart
    [datetime]$LastBootUpTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $WmiUptime = (Get-Date) - $LastBootUpTime

    # The proper measure is to use the Event Log to find the last full startup
    [datetime]$LastFullStartup = (Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| Where-Object {$_.Id -eq 27 -and $_.Message -match '0x1'})[0].TimeCreated
    $EventUptime = (Get-Date) - $LastFullStartup

    Write-Host "Device was last hibernated $($WmiUptime.Hours) hours ago according to WMI LastBootUpTime"
    Write-Host "Device last full startup was $($EventUptime.Hours) hours ago according to the event log"
}
Get-DeviceUptimeHours