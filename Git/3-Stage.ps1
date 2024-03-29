<#
.SYNOPSIS
    Clone a repository from GitHub
.DESCRIPTION
    Clone the OSDCloud Scripts repository from GitHub using PowerShell
    Requires Git for Windows
.NOTES
    Author: David Segura
    Modified: 2023-07-28
#>
# Set the location for the Git repository
Set-Location -Path C:\Temp\OSDCloudScripts
git add -A