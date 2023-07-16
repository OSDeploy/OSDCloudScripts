<#PSScriptInfo
.VERSION 23.7.16.1
.GUID c7c5121e-21b1-4594-82fa-035911a32584
.AUTHOR Bezet-Torres Jérôme
.COMPANYNAME Bezet-Torres Jérôme
.COPYRIGHT (c) 2023 Bezet-Torres Jérôme. All rights reserved.
.TAGS DEV PARAM
.LICENSEURI 
.PROJECTURI https://github.com/OSDeploy/PwshHub
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
#Requires -Modules AzureRM.Netcore
#Requires -Modules @{ ModuleName="AzureRM.Netcore"; ModuleVersion="0.12.0" }
#Requires -Modules @{ ModuleName="AzureRM.Netcore"; MaximumVersion="0.12.0" }
#Requires -Modules @{ ModuleName="OSD"; ModuleVersion="23.5.26.1" }
#Requires -PSEdition Core
#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -Assembly path\to\foo.dll
#Requires -Assembly "System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35"
<#
.DESCRIPTION
Some Defaults
#>
[CmdletBinding()]
param(

  [Parameter(Mandatory=$true, 
  ValueFromPipeline=$true,
  ValueFromPipelineByPropertyName=$true, 
  ValueFromRemainingArguments=$false, 
  Position=0)]
[ValidateNotNull()]
[ValidateNotNullOrEmpty()]
[ValidateCount(0,5)]
[ValidateSet("sun", "moon", "earth")]
[Alias("p1")] 
$Testvar,

[Parameter()]
[AllowNull()]
[AllowEmptyCollection()]
[AllowEmptyString()]
[ValidateScript({$true})]
[ValidateRange(0,5)]
[int]
$Testvar2



)

Write-host -Object "Hello World $Testvar and $Testvar2"
