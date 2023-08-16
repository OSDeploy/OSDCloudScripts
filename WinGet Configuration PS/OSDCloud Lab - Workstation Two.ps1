#Requires -RunAsAdministrator
[CmdletBinding()]
param()

#region Hyper-V
$FeatureName = 'Microsoft-Hyper-V-All'
$WindowsOptionalFeature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
if ($WindowsOptionalFeature.State -eq 'Enabled') {
    Write-Host -ForegroundColor Green "[+] Windows Optional Feature $FeatureName is installed"
}
elseif ($WindowsOptionalFeature.State -eq 'Disabled') {
    Write-Host -ForegroundColor Yellow "[-] Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart"
    Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -Confirm:$true
}
else {
    Write-Host -ForegroundColor Red "[!] Hyper-V is not compatible with this version of Windows"
}
#endregion

#region Windows Sandbox
$FeatureName = 'Containers-DisposableClientVM'
$WindowsOptionalFeature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
if ($WindowsOptionalFeature.State -eq 'Enabled') {
    Write-Host -ForegroundColor Green "[+] Windows Optional Feature $FeatureName is installed"
}
elseif ($WindowsOptionalFeature.State -eq 'Disabled') {
    Write-Host -ForegroundColor Yellow "[-] Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart"
    Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart
}
else {
    Write-Host -ForegroundColor Red "[!] $FeatureName is not compatible with this version of Windows"
}
#endregion

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

#region WinGet Packages - Detected Display Managers
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
        'Microsoft.DeploymentToolkit'
        'Microsoft.Office'
        'Microsoft.OneDrive'
        'Microsoft.Teams'
        'Microsoft.PowerShell'
        'Microsoft.PowerToys'
        'Microsoft.VCRedist.2015+.x86'
        'Microsoft.VCRedist.2015+.x64'
        'Microsoft.WinDbg'
        'Microsoft.WindowsAdminCenter'
        '9NBLGGH4TX22' #Windows Configuration Designer
        'Notepad++.Notepad++'
        'PrimateLabs.Geekbench.6'
        'TechSmith.Snagit.2023'
        'Zoom.Zoom'
        'Zoom.ZoomOutlookPlugin'
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

#region WinGet Upgrade all Apps
if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    winget upgrade 
    Start-Sleep -Seconds 2
    winget upgrade --all --silent
}
#endregion