#Requires -RunAsAdministrator
[CmdletBinding()]
param()

#region WinGet
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    Write-Host -ForegroundColor Green "[+] WinGet"
}
else {
    try {
        Write-Host -ForegroundColor Yellow "[-] Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
    }
    catch {
        Write-Error '[!] WinGet could not be installed'
        Break
    }
}
#endregion

#region Hardware Specific Installs
# Dell Display Manager
$id = 'Dell.DisplayManager'
if (Get-PnpDevice -PresentOnly -Class 'Monitor' | Where-Object {$_.InstanceID -match 'DISPLAY\\DEL'}) {
    Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --accept-source-agreements --accept-package-agreements"
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements

    $id = 'Microsoft.DotNet.DesktopRuntime.5'
    Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --accept-source-agreements --accept-package-agreements"
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements
}

# HP Display Center
$id = '9NT6FQ9KQF90'
if (Get-PnpDevice -PresentOnly -Class 'Monitor' | Where-Object {$_.InstanceID -match 'DISPLAY\\HP'}) {
    Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --accept-source-agreements --accept-package-agreements"
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements
}
#endregion