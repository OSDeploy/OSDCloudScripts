function Get-LastFullStartup {
    [CmdletBinding()]
    param()
    [datetime](Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| Where-Object {$_.Id -eq 27 -and $_.Message -match '0x1'})[0].TimeCreated
}
Get-LastFullStartup