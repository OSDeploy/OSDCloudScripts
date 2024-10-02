#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install Intel Graphics Command Center from Microsoft Store using WinGet
.DESCRIPTION
Install Intel Graphics Command Center from Microsoft Store using WinGet
.LINK
https://www.intel.com/content/www/us/en/support/articles/000055840/graphics.html
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$id = '9PLFNLNT3G5G'
)

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    winget install --id $id --exact --accept-source-agreements --accept-package-agreements
}
else {
    Write-Error -Message 'WinGet is not installed.'
}