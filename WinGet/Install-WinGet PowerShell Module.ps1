#Requires -RunAsAdministrator
#WPNinjaS
<#
.SYNOPSIS
Installs Microsoft.WinGet.Client PowerShell Module

.NOTES
NuGet provider is required to continue
PowerShellGet requires NuGet provider version '2.8.5.201' or newer to interact with NuGet-based repositories. The NuGet provider must be available
in 'C:\Program Files\PackageManagement\ProviderAssemblies' or 'C:\Users\WDAGUtilityAccount\AppData\Local\PackageManagement\ProviderAssemblies'. You
 can also install the NuGet provider by running 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force'. Do you want PowerShellGet
to install and import the NuGet provider now?
[Y] Yes  [N] No  [S] Suspend  [?] Help (default is "Y"): Y

Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the
Set-PSRepository cmdlet. Are you sure you want to install the modules from 'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): Y
PS C:\> Get-Command -Module Microsoft.WinGet.Client

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Add-WinGetSource                                   0.2.1      Microsoft.WinGet.Client
Function        Disable-WinGetSetting                              0.2.1      Microsoft.WinGet.Client
Function        Enable-WinGetSetting                               0.2.1      Microsoft.WinGet.Client
Function        Get-WinGetSettings                                 0.2.1      Microsoft.WinGet.Client
Function        Remove-WinGetSource                                0.2.1      Microsoft.WinGet.Client
Function        Reset-WinGetSource                                 0.2.1      Microsoft.WinGet.Client
Cmdlet          Assert-WinGetPackageManager                        0.2.1      Microsoft.WinGet.Client
Cmdlet          Find-WinGetPackage                                 0.2.1      Microsoft.WinGet.Client
Cmdlet          Get-WinGetPackage                                  0.2.1      Microsoft.WinGet.Client
Cmdlet          Get-WinGetSource                                   0.2.1      Microsoft.WinGet.Client
Cmdlet          Get-WinGetUserSettings                             0.2.1      Microsoft.WinGet.Client
Cmdlet          Get-WinGetVersion                                  0.2.1      Microsoft.WinGet.Client
Cmdlet          Install-WinGetPackage                              0.2.1      Microsoft.WinGet.Client
Cmdlet          Repair-WinGetPackageManager                        0.2.1      Microsoft.WinGet.Client
Cmdlet          Set-WinGetUserSettings                             0.2.1      Microsoft.WinGet.Client
Cmdlet          Test-WinGetUserSettings                            0.2.1      Microsoft.WinGet.Client
Cmdlet          Uninstall-WinGetPackage                            0.2.1      Microsoft.WinGet.Client
Cmdlet          Update-WinGetPackage                               0.2.1      Microsoft.WinGet.Client
#>
Install-Module Microsoft.WinGet.Client -Force -Verbose