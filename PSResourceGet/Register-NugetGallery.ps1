<#
.SYNOPSIS
Registers the NuGet Gallery as a repository.
.DESCRIPTION
Microsoft.PowerShell.PSResourceGet is a continuation of the PowerShellGet 3.0 project.
The first preview release of this module under the new name is now available on the PowerShell Gallery.
This release contains the module rename, and reintroduces support for Azure Artifacts, GitHub packages, and Artifactory and contains a number of bug fixes.
.LINK
https://devblogs.microsoft.com/powershell/psresourceget-preview-is-now-available/
#>
[CmdletBinding()]
param()

Register-PSResourceRepository -Name "NuGetGallery" -Uri "https://api.nuget.org/v3/index.json"