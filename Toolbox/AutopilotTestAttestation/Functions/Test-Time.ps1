#Requires -RunAsAdministrator
function Test-Time {
    Write-Host 'Making sure the time service is running and configuring the time sync servers' -ForegroundColor Yellow
    If (((Get-Service W32Time).Status -ne 'Running') -or ((Get-Service W32Time).Status -eq 'Running')) {
        stop-service W32Time 
        cmd /c 'w32tm /unregister' | out-null
        cmd /c 'w32tm /register' | out-null
        start-service W32Time | out-null
        cmd /c 'w32tm /resync' | out-null
        cmd /c 'w32tm /config /update /manualpeerlist:0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org,0x8 /syncfromflags:MANUAL /reliable:yes' | out-null
    }
}

Test-Time