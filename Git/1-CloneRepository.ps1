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
$Source = "https://github.com/OSDeploy/OSDCloudScripts.git"
$Destination = "C:\Temp\OSDCloudScripts"

git clone $Source "$Destination"