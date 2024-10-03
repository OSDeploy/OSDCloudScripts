#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install the OSD PowerShell Module in the AllUsers scope
#>
$params = @{
    Name        = 'OSD'
    Scope       = 'AllUsers'
    ErrorAction = 'SilentlyContinue'
    Force       = $true
    Verbose     = $true
}
Install-Module @params