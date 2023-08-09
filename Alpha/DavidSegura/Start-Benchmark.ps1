# write comment based help for this script

$time = Measure-Command {powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c; New-OSDCloudTemplate -Name HighPerformance}
$totalSeconds = $time.TotalSeconds
Write-Host -ForegroundColor Green "HighPerformance took $totalSeconds seconds"

$time = Measure-Command {powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e; New-OSDCloudTemplate -Name Balanced}
$totalSeconds = $time.TotalSeconds
Write-Host -ForegroundColor Green "Balanced took $totalSeconds seconds"

$time = Measure-Command {powercfg /setactive a1841308-3541-4fab-bc81-f71556f20b4a; New-OSDCloudTemplate -Name PowerSaver}
$totalSeconds = $time.TotalSeconds
Write-Host -ForegroundColor Green "PowerSaver took $totalSeconds seconds"

powercfg /setactive fb5220ff-7e1a-47aa-9a42-50ffbf45c673