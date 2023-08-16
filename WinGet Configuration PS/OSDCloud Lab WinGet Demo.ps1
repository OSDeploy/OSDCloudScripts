#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [System.String]$AddHyperV = $true,
    [System.String]$AddSandbox = $true,
    [System.String]$HardwareApps = $true,
    [System.String]$InstallOSD = $true,
    [System.String]$InstallVSCode = $true,
    [System.String]$WinGetUpgrade = $true
)

$WinGetPackages = @(
    '7zip.7zip'
    'Google.Chrome'
    'Logitech.OptionsPlus'
    'Microsoft.DotNet.DesktopRuntime.6'
    'Microsoft.DotNet.SDK.7'
    'Microsoft.Office'
    'Microsoft.OneDrive'
    'Microsoft.Teams'
    'Microsoft.PowerShell'
    'Microsoft.PowerToys'
    'Microsoft.VCRedist.2015+.x86'
    'Microsoft.VCRedist.2015+.x64'
    'Microsoft.WinDbg'
    'Microsoft.WindowsAdminCenter'
    'Notepad++.Notepad++'
    'PrimateLabs.Geekbench.6'
    'TechSmith.Snagit.2023'
    'Zoom.Zoom'
    'Zoom.ZoomOutlookPlugin'
)

#region Hyper-V
if ($AddHyperV -eq $true) {
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
}
#endregion

#region Windows Sandbox
if ($AddSandbox -eq $true) {
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
}
#endregion

#region Install WinGet
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

#region WinGetPackages
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
#endregion

#region HardwareApps
if ($HardwareApps -eq $true) {
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
}
#endregion

#region InstallOSD
if ($InstallOSD -eq $true) {
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
            Write-Host -ForegroundColor Green "[+] $id"
        }
    }

    $id = 'Microsoft.WindowsADK'
    $WinGetList = winget list --id $id --exact
    if ($WinGetList -match 'No installed package found') {
        Write-Host -ForegroundColor Yellow "[-] winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements"
        winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements
    }
    else {
        Write-Host -ForegroundColor Green "[+] $id"
    }
    
    $id = 'Microsoft.ADKPEAddon'
    $WinGetList = winget list --id $id --exact
    if ($WinGetList -match 'No installed package found') {
        Write-Host -ForegroundColor Yellow "[-] winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements"
        winget install --id $id --version 10.1.22621.1 --exact --accept-source-agreements --accept-package-agreements
    }
    else {
        Write-Host -ForegroundColor Green "[+] $id"
    }

    if (-not (Test-Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs')) {
        New-Item -Path 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment\x86\WinPE_OCs' -ItemType Directory -Force
    }
}
#endregion

#region InstallVSCode
if ($InstallVSCode -eq $true) {
    $WinGetPackages = @(
        'Git.Git'
        'GitHub.GitHubDesktop'
    )
    
    foreach ($id in $WinGetPackages) {
        $WinGetList = winget list --id $id --exact --accept-source-agreements
        if ($WinGetList -match 'No installed package found') {
            Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --accept-source-agreements --accept-package-agreements"
            winget install --id $id --exact --accept-source-agreements --accept-package-agreements
        }
        else {
            Write-Host -ForegroundColor Green "[+] $id"
        }
    }

    $id = 'Microsoft.VisualStudioCode'
    $WinGetList = winget list --id $id --exact
    if ($WinGetList -match 'No installed package found') {
        Write-Host -ForegroundColor Yellow "[-] winget install --id $id --exact --override /SILENT /mergetasks=!runcode,addcontextmenufiles,addcontextmenufolders"
        winget install --id $id --exact --accept-source-agreements --accept-package-agreements --override '/SILENT /mergetasks="!runcode,addcontextmenufiles,addcontextmenufolders"'
    }
    else {
        Write-Host -ForegroundColor Green "[+] $id"
    }
}
#endregion

#region WinGetUpgrade
if ($WinGetUpgrade -eq $true) {
    winget upgrade 
    Start-Sleep -Seconds 5
    Write-Host -ForegroundColor Yellow "[-] winget upgrade --all --silent"
    winget upgrade --all --silent
}
#endregion