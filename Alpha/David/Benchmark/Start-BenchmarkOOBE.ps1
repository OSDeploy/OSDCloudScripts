if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    Write-Host 'WinGet is already installed.'
}
else {
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe -Verbose
    }
    catch {
        Write-Error 'WinGet could not be installed.'
    }
}


$id = 'PrimateLabs.Geekbench.6'
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements
}
else {
    Write-Error -Message 'WinGet is not installed.'
}

# Open Geekbench
& 'C:\Program Files (x86)\Geekbench 6\Geekbench 6.exe'

# Always start with this first since it's the most intensive
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
Write-Host -ForegroundColor Green "1/4 HighPerformance Power Plan is enabled"

Pause

powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e
Write-Host -ForegroundColor Green "2/4 Balanced Power Plan is enabled"

Pause

powercfg /setactive a1841308-3541-4fab-bc81-f71556f20b4a
Write-Host -ForegroundColor Green "3/4 PowerSaver Power Plan is enabled"

Pause

powercfg /setactive fb5220ff-7e1a-47aa-9a42-50ffbf45c673
Write-Host -ForegroundColor Green "4/4 HP Optimized (Modern Standby) Power Plan is enabled"