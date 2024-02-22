Stop-Service W32Time 
cmd /c "w32tm /unregister" | out-null
cmd /c "w32tm /register" | out-null
Start-Service W32Time
cmd /c "w32tm /resync"| out-null
cmd /c "w32tm /config /update /manualpeerlist:0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org,0x8 /syncfromflags:MANUAL /reliable:yes" | out-null