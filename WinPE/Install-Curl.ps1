<#
.SYNOPSIS
Installs the Curl utility in a Windows Preinstallation Environment (WinPE).

.DESCRIPTION
The osdcloud-WinpeInstallCurl function installs the Curl utility in a Windows Preinstallation Environment (WinPE). This function downloads the latest version of Curl from the official website and installs it in the WinPE environment.

.PARAMETER None
This function does not accept any parameters.

.EXAMPLE
osdcloud-WinpeInstallCurl
Installs the Curl utility in the current WinPE environment.

.NOTES
This function requires an active internet connection to download the latest version of Curl from the official website.
#>
function osdcloud-WinpeInstallCurl {
    [CmdletBinding()]
    param ()
    if (-not (Get-Command 'curl.exe' -ErrorAction SilentlyContinue)) {
        Write-Host -ForegroundColor Yellow "[-] Install Curl 8.1.2 for Windows"
        #$Uri = 'https://curl.se/windows/dl-7.81.0/curl-7.81.0-win64-mingw.zip'
        #$Uri = 'https://curl.se/windows/dl-7.88.1_2/curl-7.88.1_2-win64-mingw.zip'
        #$Uri = 'https://curl.se/windows/dl-8.1.2_2/curl-8.1.2_2-win64-mingw.zip'
        $Uri = 'https://curl.se/windows/dl-8.2.1_3/curl-8.2.1_3-win64-mingw.zip'
        Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile "$env:TEMP\curl.zip"
    
        $null = New-Item -Path "$env:TEMP\Curl" -ItemType Directory -Force
        Expand-Archive -Path "$env:TEMP\curl.zip" -DestinationPath "$env:TEMP\curl"
    
        Get-ChildItem "$env:TEMP\curl" -Include 'curl.exe' -Recurse | foreach {Copy-Item $_ -Destination "$env:SystemRoot\System32\curl.exe"}
    }
    if (Get-Command 'curl.exe' -ErrorAction SilentlyContinue) {
        $GetItemCurl = Get-Item -Path "$env:SystemRoot\System32\curl.exe" -ErrorAction SilentlyContinue
        Write-Host -ForegroundColor Green "[+] Curl $($GetItemCurl.VersionInfo.FileVersion)"
    }
}
osdcloud-WinpeInstallCurl