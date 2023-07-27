<#PSScriptInfo
.VERSION 23.7.27.2
.GUID 8f3378bf-87a1-469e-b77a-e1b3823a79c1
.AUTHOR Damien Van Robaeys
.COMPANYNAME Damien Van Robaeys
.COPYRIGHT (c) 2023 Damien Van Robaeys. All rights reserved.
.TAGS WinGet
.LICENSEURI 
.PROJECTURI 
.ICONURI 
.EXTERNALMODULEDEPENDENCIES 
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.DESCRIPTION
This script will convert the OneDrive SyncDiagnostics.log file to a PowerShell object
.LINK
https://www.systanddeploy.com/2022/07/converting-onedrive-syncdiagnostics-log.html
#>
# 
if (Test-Path "$env:USERPROFILE\AppData\Local\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log") {
    $SyncDiagnosticsLog = "$env:USERPROFILE\AppData\Local\Microsoft\OneDrive\logs\Business1\SyncDiagnostics.log"
}
elseif (Test-Path "$env:USERPROFILE\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncDiagnostics.log") {
    $SyncDiagnosticsLog = "$env:USERPROFILE\AppData\Local\Microsoft\OneDrive\logs\Personal\SyncDiagnostics.log"
}
else {
    Write-Warning "SyncDiagnostics.log was not found"
}

if ($SyncDiagnosticsLog) {
    Write-Host "Working"
    $SyncDiag_Content = Get-Content -Path $SyncDiagnosticsLog
    $OneDrive_SyncDiag = New-Object PSObject ; $SyncDiag_Content | `
    Where-Object {(($_ -match '=') -or ($_ -match ':') -and ($_ -notlike "*==*"))} | `
    ForEach-Object {
        if ($_ -like "*=*") {
            $Item = ($_.Trim() -split '= ').trim()
        }
        elseif ($_ -like "*:*") {
            $Item = ($_.Trim() -split ': ').trim()
        }
        $OneDrive_SyncDiag | Add-Member -MemberType NoteProperty -Name $($Item[0]) -Value $Item[1] -EA SilentlyContinue
    }
}
$OneDrive_SyncDiag