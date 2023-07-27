<#PSScriptInfo
.VERSION 23.7.27.5
.GUID eb4da66f-1ac7-426d-b2c0-790b8db6caff
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
<#
.DESCRIPTION
Install PowerShell 7 
.LINK
    https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.3
#>


Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"