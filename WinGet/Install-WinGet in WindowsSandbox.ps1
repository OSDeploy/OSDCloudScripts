#WPNinjaS
#requires -RunAsAdministrator

<#
Install winget on Windows Sandbox
Windows Sandbox provides a lightweight desktop environment to safely run applications in isolation. Software installed inside the Windows Sandbox environment remains "sandboxed" and runs separately from the host machine. Windows Sandbox does not include winget, nor the Microsoft Store app, so you will need to download the latest winget package from the winget releases page on GitHub.

To install the stable release of winget on Windows Sandbox, follow these steps from a Windows PowerShell command prompt:
$progressPreference = 'silentlyContinue'
$latestWingetMsixBundleUri = $(Invoke-RestMethod https://api.github.com/repos/microsoft/winget-cli/releases/latest).assets.browser_download_url | Where-Object {$_.EndsWith(".msixbundle")}
Write-Host -ForegroundColor Cyan "Latest winget release: $latestWingetMsixBundleUri"
$latestWingetMsixBundle = $latestWingetMsixBundleUri.Split("/")[-1]
Write-Host -ForegroundColor Cyan "Downloading $latestWingetMsixBundle"
Invoke-WebRequest -Uri $latestWingetMsixBundleUri -OutFile "./$latestWingetMsixBundle"
Write-Host -ForegroundColor Cyan "Downloading Microsoft.VCLibs.x64.14.00.Desktop.appx"
Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx -Verbose
Add-AppxPackage $latestWingetMsixBundle -Verbose
#>

$progressPreference = 'silentlyContinue'
Write-Host -ForegroundColor Cyan 'Downloading WinGet and its dependencies...'
Invoke-WebRequest -Uri https://aka.ms/getwinget -OutFile Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle
Invoke-WebRequest -Uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile Microsoft.VCLibs.x64.14.00.Desktop.appx
Invoke-WebRequest -Uri https://github.com/microsoft/microsoft-ui-xaml/releases/download/v2.7.3/Microsoft.UI.Xaml.2.7.x64.appx -OutFile Microsoft.UI.Xaml.2.7.x64.appx
Add-AppxPackage Microsoft.VCLibs.x64.14.00.Desktop.appx
Add-AppxPackage Microsoft.UI.Xaml.2.7.x64.appx
Add-AppxPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle

winget --info
<#
If you would like a preview or different version of the Package Manager, go to https://github.com/microsoft/winget-cli/releases. Copy the URL of the version you would prefer and update the above Uri.

For more information on Windows Sandbox, including how to install a sandbox and what to expect from it's usage, see the Windows Sandbox docs.
#>