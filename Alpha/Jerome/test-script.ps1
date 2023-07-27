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
#Requires -PSEdition Desktop
#Requires -RunAsAdministrator
#Requires -Version 5.1
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
[Alias("p1")] 
$Testvar,

[Parameter()]
[AllowNull()]
[ValidateSet('Startup', 'Shutdown', 'LogOn', 'LogOff')]
[String]$Testvar2



)

Write-host -Object "Hello World $Testvar and $Testvar2"
