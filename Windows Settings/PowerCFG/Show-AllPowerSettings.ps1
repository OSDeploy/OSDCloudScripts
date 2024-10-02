$PowerSettings = "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings"
$querylist =  reg query $PowerSettings
foreach ($regfolder in $querylist) {
$querylist2 = reg query $regfolder
    foreach($2ndfolder in $querylist2){
    $active2 = $2ndfolder -replace "HKEY_LOCAL_MACHINE" , "HKLM:"
    Get-ItemProperty -Path $active2
    Set-ItemProperty -Path "$active2" -Name "Attributes" -Value '2'
    }
    $active = $regfolder -replace "HKEY_LOCAL_MACHINE" , "HKLM:"
    Get-ItemProperty -Path $active
    Set-ItemProperty -Path "$active" -Name "Attributes" -Value '2'
}