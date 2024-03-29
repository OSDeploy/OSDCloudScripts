function Get-AutopilotEvents {
    [CmdletBinding()]
    param ()
    Get-WinEvent -MaxEvents 100 -LogName 'Microsoft-Windows-ModernDeployment-Diagnostics-Provider/AutoPilot' | Sort-Object TimeCreated | Select-Object TimeCreated, Id, Message | Format-Table
}

Get-AutopilotEvents