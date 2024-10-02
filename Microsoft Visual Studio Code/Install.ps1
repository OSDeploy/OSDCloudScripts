#Requires -RunAsAdministrator
<#
.DESCRIPTION
Install Microsoft Visual Studio Code
.LINK
https://code.visualstudio.com/
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # Show all available versions
    winget show --id Microsoft.VisualStudioCode --versions

    # Microsoft Visual Studio Code
    winget install --id Microsoft.VisualStudioCode --scope machine --override '/SILENT /mergetasks="!runcode,addcontextmenufiles,addcontextmenufolders"' --accept-source-agreements --accept-package-agreements
}
else {
    Write-Error -Message 'WinGet is not installed.'
}