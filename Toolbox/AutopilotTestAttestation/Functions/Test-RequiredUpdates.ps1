function Test-RequiredUpdates {

    [datetime]$dtToday = [datetime]::NOW
    $strCurrentMonth = $dtToday.Month.ToString()
    $strCurrentYear = $dtToday.Year.ToString()
    [datetime]$dtMonth = $strCurrentMonth + '/1/' + $strCurrentYear

    while ($dtMonth.DayofWeek -ne 'Tuesday') { 
        $dtMonth = $dtMonth.AddDays(1) 
    }

    $strPatchTuesday = $dtMonth.AddDays(7)
    $intOffSet = 1

    if ([datetime]::NOW -lt $strPatchTuesday -or [datetime]::NOW -ge $strPatchTuesday.AddDays($intOffSet)) {
        $objUpdateSession = New-Object -ComObject Microsoft.Update.Session
        $objUpdateSearcher = $objUpdateSession.CreateupdateSearcher()
        $arrAvailableUpdates = @($objUpdateSearcher.Search('IsAssigned=1 and IsHidden=0 and IsInstalled=0').Updates)
        $strAvailableCumulativeUpdates = $arrAvailableUpdates | Where-Object { (($_.title -like '*Windows 10*') -or ($_.title -like '*Windows 11*')) -and ($_.title -notlike '*.Net Framework*') -and ($_.title -notlike '*2022-04*') }

        if ($strAvailableCumulativeUpdates -eq $null) {
            write-host 'Nice work, the device is up to date!' -ForegroundColor green
            write-host "`n"
        }
        else {
            $missingupdate = $strAvailableCumulativeUpdates.Title
            write-host "`n"
            write-host "Device is not up to date because it's missing this update: $missingupdate. Please make sure the device is up to date before performing Autopilot Pre-Provisioning" -ForegroundColor red
            write-host "`n"
            write-host 'Do you want to check for updates? Yes or No?' -ForegroundColor Yellow
            $check4updates = read-host
            If (($check4updates -eq 'Y') -or ($check4updates -eq 'y') ) {
                cmd /c 'C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate'
            }
            else {
                write-host 'Skipping Windows Update.' -ForegroundColor Green
            }

        }
    }
    else {
        write-host 'Device seems up to date'? -ForegroundColor green
    }
}

Test-RequiredUpdates