<#PSScriptInfo
.VERSION 23.6.1.2
.GUID 30302c37-3650-4e8d-9588-47ea942db3ba
.AUTHOR David Segura
.COMPANYNAME David Segura
.COPYRIGHT (c) 2023 David Segura. All rights reserved.
.TAGS WinGet
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/PwshHub
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
#Requires -RunAsAdministrator
<#
.DESCRIPTION
Install Package using WinGet
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$id = 'wingetcreate'
)

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Install
    winget install $id
}
else {
    Write-Error -Message 'WinGet is not installed.'
}