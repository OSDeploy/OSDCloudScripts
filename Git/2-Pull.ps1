<#
.SYNOPSIS
    Pull changes from a Git repository
.DESCRIPTION
    Pull changes from a Git repository
    Requires Git for Windows
.NOTES
    Author: David Segura
    Modified: 2023-07-28
#>
# Set the location for the Git repository
Set-Location -Path C:\Temp\OSDCloudScripts

# Sync any changes from the remote repository
git pull