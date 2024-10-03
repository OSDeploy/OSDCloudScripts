# https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-overview

# Windows 10
# dism /online /Enable-Feature /FeatureName:"Containers-DisposableClientVM" -All

# Windows 11
$FeatureName = 'Containers-DisposableClientVM'

$params = @{
    Online      = $true
    FeatureName = $FeatureName
    ErrorAction = 'SilentlyContinue'
}
$WindowsOptionalFeature = Get-WindowsOptionalFeature @params

if ($WindowsOptionalFeature.State -eq 'Enabled') {
    Write-Host -ForegroundColor Green "[+] Windows Optional Feature $FeatureName is installed"
}
elseif ($WindowsOptionalFeature.State -eq 'Disabled') {
    Write-Host -ForegroundColor Yellow "[-] Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart"
    $params = @{
        Online      = $true
        FeatureName = $FeatureName
        All         = $true
        NoRestart   = $true
        ErrorAction = 'SilentlyContinue'
    }
    Enable-WindowsOptionalFeature @params
}
else {
    Write-Host -ForegroundColor Red "[!] $FeatureName is not compatible with this version of Windows"
}

#If you're using a virtual machine, run the following PowerShell command to enable nested virtualization:
#Set-VMProcessor -VMName <VMName> -ExposeVirtualizationExtensions $true