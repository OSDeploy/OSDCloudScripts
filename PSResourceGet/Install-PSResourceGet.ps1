<#
.SYNOPSIS
Installs the latest version of the PSResourceGet module.
.DESCRIPTION
Microsoft.PowerShell.PSResourceGet is a continuation of the PowerShellGet 3.0 project.
The first preview release of this module under the new name is now available on the PowerShell Gallery.
This release contains the module rename, and reintroduces support for Azure Artifacts, GitHub packages, and Artifactory and contains a number of bug fixes.
.LINK
https://devblogs.microsoft.com/powershell/psresourceget-preview-is-now-available/
#>
[CmdletBinding()]
param()

# To install from PowerShellGet 3.0 previews
if (Get-Module -Name Microsoft.PowerShell.PSResourceGet -ListAvailable) {
    Install-PSResource Microsoft.PowerShell.PSResourceGet -Prerelease -Verbose
}

# To install from PowerShellGet 2.2.5
else {
    Install-Module -Name Microsoft.PowerShell.PSResourceGet -AllowPrerelease -Verbose
}