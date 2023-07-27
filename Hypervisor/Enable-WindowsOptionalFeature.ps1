<#PSScriptInfo
.VERSION 23.6.1.2
.GUID c3f0cde1-d1af-4832-9135-aa3f99466f6c
.AUTHOR David Segura
.COMPANYNAME David Segura
.COPYRIGHT (c) 2023 David Segura. All rights reserved.
.TAGS WinGet
.LICENSEURI 
.PROJECTURI
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
#Requires -RunAsAdministrator
<#
.DESCRIPTION
This script will enable the Windows Optional Feature Microsoft-Hyper-V-All
.LINK
https://learn.microsoft.com/fr-fr/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v
#>
#Requires -RunAsAdministrator

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