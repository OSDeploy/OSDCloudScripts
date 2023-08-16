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

#region WinGet Packages for OSD
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    $WinGetPackages = @(
        'Microsoft.DeploymentToolkit'
        '9NBLGGH4TX22' #Windows Configuration Designer
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

#region Windows ADK
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    $id = 'Microsoft.WindowsADK'
    $WinGetList = winget list --id $id --exact
    if ($WinGetList -match 'No installed package found') {
        Write-Host -ForegroundColor Yellow "[-] winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements"
        winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements
    }
    else {
        Write-Host -ForegroundColor Green "[+] WinGet $id is installed"
    }
    
    $id = 'Microsoft.ADKPEAddon'
    $WinGetList = winget list --id $id --exact
    if ($WinGetList -match 'No installed package found') {
        Write-Host -ForegroundColor Yellow "[-] winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements"
        winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements
    }
    else {
        Write-Host -ForegroundColor Green "[+] WinGet $id is installed"
    }

    if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
        New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
    }
}
#endregion