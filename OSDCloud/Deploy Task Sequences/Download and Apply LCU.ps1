Start-OSDCloudGUI

$WsusXml = Get-WSUSXML -Catalog "Windows 11" -UpdateArch x64 -UpdateBuild 22H2 -UpdateOS "Windows 11"

foreach ($Update in $WsusXml) {
    $DownloadPath = 'C:\OSDCloud\Updates'
    $DownloadFullPath = Join-Path $DownloadPath $(Split-Path $Update.OriginUri -Leaf)
    #=================================================
    #	Download
    #=================================================
    $SourceUrl = $Update.OriginUri
    $SourceUrl = [Uri]::EscapeUriString($SourceUrl)

    if (!(Test-Path $DownloadPath)) {New-Item -Path "$DownloadPath" -ItemType Directory -Force | Out-Null}
    if (!(Test-Path $DownloadFullPath)) {
        Write-Host "$DownloadFullPath"
        Write-Host "$($Update.OriginUri)" -ForegroundColor Gray
        if (Get-Command 'curl.exe' -ErrorAction SilentlyContinue) {
            Write-Verbose "cURL: $SourceUrl"
            if ($host.name -match 'ConsoleHost') {
                Invoke-Expression "& curl.exe --insecure --location --output `"$DownloadFullPath`" --url `"$SourceUrl`""
            }
            else {
                #PowerShell ISE will display a NativeCommandError, so progress will not be displayed
                $Quiet = Invoke-Expression "& curl.exe --insecure --location --output `"$DownloadFullPath`" --url `"$SourceUrl`" 2>&1"
            }
        }
        else {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls1
            $WebClient = New-Object System.Net.WebClient
            $WebClient.DownloadFile("$SourceUrl", "$DownloadFullPath")
            $WebClient.Dispose()
        }
    }
}
$Updates = Get-ChildItem -Path $DownloadPath -File
foreach ($Item in $Updates) {
    dism /Image:C:\ /Add-Package /PackagePath:$($Item.FullName) /ScratchDir:C:\Windows\Temp
}