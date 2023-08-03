function Get-DeviceUptime {
    <#
    .SYNOPSIS
        This script retrieves the uptime of the device.

    .DESCRIPTION
        This script uses WMI to retrieve the LastBootUpTime of the device and calculates the uptime based on the current time.

    .PARAMETER None
        This script does not accept any parameters.

    .EXAMPLE
        PS C:\> Get-DeviceUptime
        Returns the uptime of the device.

    .NOTES
        Version 1.0
    #>
    [CmdletBinding()]
    param()

    try {
        $LastBootUpTime = Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty LastBootUpTime -ErrorAction SilentlyContinue
        $LastBootUpTime = [Management.ManagementDateTimeConverter]::ToDateTime($LastBootUpTime)
        return [datetime]::Now - $LastBootUpTime
    }
    catch {
        <#Do this if a terminating exception happens#>
    }
    finally {
        <#Do this after the try block regardless of whether an exception occurred or not#>
    }
}

[Math]::Round($((Get-DeviceUptime).TotalHours), 2)