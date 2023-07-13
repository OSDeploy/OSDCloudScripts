# https://www.systanddeploy.com/2022/07/converting-onedrive-syncdiagnostics-log.html

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