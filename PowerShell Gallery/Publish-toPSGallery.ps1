<#
.SYNOPSIS
Publish a module to the PowerShell Gallery
.DESCRIPTION
Publish a module to the PowerShell Gallery.
You will need to add your NuGet API key to the $NuGetApiKey parameter.
.LINK
https://www.powershellgallery.com/account/apikeys
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$NuGetApiKey = '',
    [Parameter(Mandatory = $true)]
    [string]$ModuleName = ''
)
# Import the module first
Import-Module $ModuleName -Force -Verbose

# Publish the module
Publish-Module -Name $ModuleName -NuGetApiKey $NuGetApiKey