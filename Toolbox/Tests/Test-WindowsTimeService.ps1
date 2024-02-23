#Requires -RunAsAdministrator

function Test-WindowsTimeService {
    Write-Host -ForegroundColor DarkGray '========================================================================='
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Test Windows Time Service" -ForegroundColor Cyan
    Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Get-Service -Name W32time" -ForegroundColor DarkGray
    $W32Time = Get-Service -Name W32time
    if ($W32Time.Status -eq 'Running') {
        Write-Host "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Windows Time Service is $($W32Time.Status)" -ForegroundColor DarkGray
    }
    else {
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) Windows Time Service is $($W32Time.Status)"
        Write-Warning "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) To sync Windows Time, enter the following commands in an elevated PowerShell window"
        Write-Host 'Stop-Service W32Time' -ForegroundColor DarkGray
        Write-Host "cmd /c 'w32tm /unregister'" -ForegroundColor DarkGray
        Write-Host "cmd /c 'w32tm /register'" -ForegroundColor DarkGray
        Write-Host 'Start-Service W32Time' -ForegroundColor DarkGray
        Write-Host "cmd /c 'w32tm /resync'" -ForegroundColor DarkGray
        Write-Host "cmd /c 'w32tm /config /update /manualpeerlist:0.pool.ntp.org;1.pool.ntp.org;2.pool.ntp.org;3.pool.ntp.org;0x8 /syncfromflags:MANUAL /reliable:yes'" -ForegroundColor DarkGray
    }
}

Test-WindowsTimeService