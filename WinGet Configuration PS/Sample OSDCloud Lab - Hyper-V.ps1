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