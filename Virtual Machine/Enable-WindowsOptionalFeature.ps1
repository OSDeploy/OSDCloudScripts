#Requires -RunAsAdministrator
<#
.SYNOPSIS
Enables the Microsoft Hyper-V feature on a Windows machine.

.DESCRIPTION
This script checks if the Microsoft Hyper-V feature is installed on a Windows machine. If it is not installed, the script enables the feature.

.PARAMETER FeatureName
Specifies the name of the Windows feature to enable. The default value is 'Microsoft-Hyper-V-All'.

.EXAMPLE
Enable-WindowsOptionalFeature.ps1 -FeatureName 'Microsoft-Hyper-V-All'
This example enables the Microsoft Hyper-V feature on the local machine.

.LINK
https://learn.microsoft.com/fr-fr/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v

.NOTES
This script requires administrative privileges to run.
#>
$FeatureName = 'Microsoft-Hyper-V-All'
$WindowsOptionalFeature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
if ($WindowsOptionalFeature.State -eq 'Enabled') {
    Write-Host -ForegroundColor Green "[+] Windows Optional Feature $FeatureName is installed"
}
elseif ($WindowsOptionalFeature.State -eq 'Disabled') {
    Write-Host -ForegroundColor Yellow "[-] Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart"
    Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart
}
else {
    Write-Host -ForegroundColor Red "[!] $FeatureName is not compatible with this version of Windows"
}