#Requires -RunAsAdministrator
[CmdletBinding()]
param()

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