<#PSScriptInfo
.VERSION 23.7.27.5
.GUID 3119fc78-1038-4785-8a59-5730423f3732
.AUTHOR Bezet-Torres Jérôme
.COMPANYNAME Bezet-Torres Jérôme
.COPYRIGHT (c) 2023 Bezet-Torres Jérôme. All rights reserved.
.TAGS DEV PARAM
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/OSDCloudScripts
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.DESCRIPTION
Installs WinGet by adding the Microsoft.DesktopAppInstaller Appx Package
.LINK
https://learn.microsoft.com/en-us/windows/package-manager/winget/#install-winget
#>

net use Z: http://live.sysinternals.com/tools

