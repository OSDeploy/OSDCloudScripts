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

#region WinGet Packages
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    $WinGetPackages = @(
        '7zip.7zip'
        'Git.Git'
        'GitHub.GitHubDesktop'
        'Google.Chrome'
        'Logitech.OptionsPlus'
        'Microsoft.DotNet.DesktopRuntime.6'
        'Microsoft.DotNet.SDK.7'
        #'Microsoft.DeploymentToolkit'
        'Microsoft.Office'
        'Microsoft.OneDrive'
        'Microsoft.Teams'
        'Microsoft.PowerShell'
        'Microsoft.PowerToys'
        'Microsoft.VCRedist.2015+.x86'
        'Microsoft.VCRedist.2015+.x64'
        #'Microsoft.WinDbg'
        'Microsoft.WindowsAdminCenter'
        #'9NBLGGH4TX22' #Windows Configuration Designer
        'Notepad++.Notepad++'
        'PrimateLabs.Geekbench.6'
        'TechSmith.Snagit.2023'
        #'Zoom.Zoom'
        #'Zoom.ZoomOutlookPlugin'
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

#region VSCode
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    $id = 'Microsoft.VisualStudioCode'
    $WinGetList = winget list --id $id --exact
    if ($WinGetList -match 'No installed package found') {
        Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --override /SILENT /mergetasks=!runcode,addcontextmenufiles,addcontextmenufolders"
        winget install --id $id --exact --accept-source-agreements --accept-package-agreements --override '/SILENT /mergetasks="!runcode,addcontextmenufiles,addcontextmenufolders"'
    }
    else {
        Write-Host -ForegroundColor Green "[+] WinGet $id is installed"
    }
}
#endregion

#region WinGet Upgrade all Apps
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    winget upgrade 
    Start-Sleep -Seconds 2
    winget upgrade --all --silent
}
#endregion