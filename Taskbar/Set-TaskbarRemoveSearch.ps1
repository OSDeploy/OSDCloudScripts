$RegKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"
if (-not(Test-Path $RegKey )) {
    $reg = New-Item $RegKey -Force | Out-Null
    try { $reg.Handle.Close() } catch {}
}
$reg = New-ItemProperty $RegKey -Name "SearchboxTaskbarMode"  -Value "0" -PropertyType Dword -Force
try { $reg.Handle.Close() } catch {}