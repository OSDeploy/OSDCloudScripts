<#
.SYNOPSIS
Install the OSD PowerShell Module in the CurrentUser scope
#>
$params = @{
    Name        = 'OSD'
    Scope       = 'CurrentUser'
    ErrorAction = 'SilentlyContinue'
    Force       = $true
    Verbose     = $true
}
Install-Module @params