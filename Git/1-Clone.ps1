<#
.SYNOPSIS
Clone a repository from GitHub
.DESCRIPTION
Clone the OSDCloud Scripts repository from GitHub using PowerShell
Requires Git to be installed on the machine
#>
# Set the location for the Git repository
Set-Location -Path C:\Temp\OSDCloudScripts

# Clone the repository
git clone https://github.com/OSDeploy/OSDCloudScripts.git