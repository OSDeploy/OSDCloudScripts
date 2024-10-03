<#
.SYNOPSIS
Sets the PowerShell Gallery as a trusted repository.
.LINK
https://learn.microsoft.com/en-us/powershell/module/powershellget/set-psrepository?view=powershellget-2.x
#>
[CmdletBinding()]
param()

if ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq 'Untrusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -Verbose
}
Get-PSRepository -Name PSGallery