# Default StartMenu pins layout 0=Default, 1=More Pins, 2=More Recommendations (requires Windows 11 22H2)

$reg = New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value "1" -PropertyType Dword -Force
try { $reg.Handle.Close() } catch {}
