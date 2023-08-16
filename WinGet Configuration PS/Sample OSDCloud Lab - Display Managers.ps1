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

#region WinGet Packages - Display Managers
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    $WinGetPackages = @(
        'Dell.DisplayManager'
        '9NT6FQ9KQF90' # HP Display Center
    )
    
    foreach ($id in $WinGetPackages) {
        $WinGetList = winget list --id $id --exact --accept-source-agreements
        if ($WinGetList -match 'No installed package found') {
            Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --accept-source-agreements --accept-package-agreements"
            winget install --id $id --exact --accept-source-agreements --accept-package-agreements
        }
        else {
            Write-Host -ForegroundColor Green "[+] WinGet $id is installed"
        }
    }
}
#endregion