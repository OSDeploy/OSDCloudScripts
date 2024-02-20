function Test-ManageMicrosoft {

    $web = Invoke-WebRequest https://portal.manage.microsoft.com
    $web.tostring() -split "[`r`n]" | select-string 'Copyright (C) Microsoft Corporation. All rights reserved'
    $webclient = new-object System.Net.WebClient 
    $webclient.Headers.Add('user-agent', 'PowerShell Script')
    $webpage = 'https://portal.manage.microsoft.com'
    $output = ''
    $output = $webclient.DownloadString($webpage)

    if ($output -like '*Copyright (C) Microsoft Corporation. All rights reserved*') {
        write-host 'Great news as it looks like there are no OOBEAADV10 errors :) ' -ForegroundColor green
    }
    else {
        write-host 'Great scott, this doesnt look good. It looks like there are some OOBEAADV10 errors going on ' -ForegroundColor red
        write-host 'Please visit https://call4cloud.nl/2022/07/oobeaadv10-return-of-the-502-error/ to read more about this error' -ForegroundColor red
    }
}

Test-ManageMicrosoft