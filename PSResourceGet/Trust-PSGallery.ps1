<#
.SYNOPSIS
Trusts the PowerShell Gallery repository.
.DESCRIPTION
Microsoft.PowerShell.PSResourceGet is a continuation of the PowerShellGet 3.0 project.
The first preview release of this module under the new name is now available on the PowerShell Gallery.
This release contains the module rename, and reintroduces support for Azure Artifacts, GitHub packages, and Artifactory and contains a number of bug fixes.
.LINK
https://devblogs.microsoft.com/powershell/psresourceget-preview-is-now-available/
#>
[CmdletBinding()]
param()

if (Get-Command Set-PSResourceRepository -ErrorAction SilentlyContinue) {
    if ((Get-PSResourceRepository -Name PSGallery).Trusted -eq $false) {
        Set-PSResourceRepository -Name PSGallery -Trusted
    }
}

# Microsoft.PowerShell.PSResourceGet is not installed
else {
    Write-Warning "Set-PSResourceRepository is not installed.  Use the following command"
    Write-Host "Install-Module -Name Microsoft.PowerShell.PSResourceGet -AllowPrerelease -Verbose"
}