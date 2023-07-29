#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Clone a repository from GitHub
.DESCRIPTION
    Clone a repository from GitHub using PowerShell
.NOTES
    Author: David Segura
    Modified: 2023-07-28
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$Owner = 'OSDeploy',
    [ValidateNotNullOrEmpty()]
    [string]$Repository = 'OSDCloudScripts',
    [ValidateNotNullOrEmpty()]
    [string]$Path = 'C:\Temp'
)

# Make sure the Git is installed
if (-NOT (Get-Command 'git.exe' -ErrorAction SilentlyContinue)) {
    Write-Warning "Git is not installed. Please install Git from https://git-scm.com/downloads"
    Break
}

# Make sure the Path exists, if not create it
if (-NOT (Test-Path $Path)) {
    try {
        New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Warning "Unable to create the Path: $Path"
        Break
    }
}

# Make sure we can get to the URL

