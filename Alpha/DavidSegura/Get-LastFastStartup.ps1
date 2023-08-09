function Get-LastFastStartup {
    [CmdletBinding()]
    param()
    [datetime](Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| Where-Object {$_.Id -eq 27 -and $_.Message -match '0x0'})[0].TimeCreated
}
Get-LastFastStartup