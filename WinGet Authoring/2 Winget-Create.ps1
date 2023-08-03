<#
.SYNOPSIS
This script creates a WinGet package and submits it to the WinGet repository.

.DESCRIPTION
The script uses the wingetcreate.exe tool to create a WinGet package for the HP.HPCMSL application.
The package version is set to 1.6.9 and the download URL is set to https://hpia.hpcloud.hp.com/downloads/cmsl/hp-cmsl-1.6.9.exe.
The package is then submitted to the WinGet repository using a personal access token.


This example creates a WinGet package and submits it to the WinGet repository using the specified personal access token.

.NOTES
This script requires the wingetcreate.exe tool to be installed on the system. This can be installed using the following command
winget install wingetcreate
#>

$token = 'xxxxxxxxxxxxxxxxx'
$id = 'HP.HPCMSL'
$version = '1.6.9'
$urls = 'https://hpia.hpcloud.hp.com/downloads/cmsl/hp-cmsl-1.6.9.exe'

wingetcreate.exe update --submit --token $token --urls $urls --version $version $id

<#
Retrieving latest manifest for HP.HPCMSL
Downloading and parsing: https://hpia.hpcloud.hp.com/downloads/cmsl/hp-cmsl-1.6.9.exe...
Generating a preview of your manifests...
Version manifest preview:
# Created using wingetcreate 1.2.8.0
# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.4.0.schema.json

PackageIdentifier: HP.HPCMSL
PackageVersion: 1.6.9
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.4.0


Installer manifest preview:
# Created using wingetcreate 1.2.8.0
# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.4.0.schema.json

PackageIdentifier: HP.HPCMSL
PackageVersion: 1.6.9
MinimumOSVersion: 10.0.0.0
Scope: machine
InstallModes:
- interactive
- silent
- silentWithProgress
Installers:
- Architecture: x86
  InstallerType: inno
  InstallerUrl: https://hpia.hpcloud.hp.com/downloads/cmsl/hp-cmsl-1.6.9.exe
  InstallerSha256: 80909320C2A51597CCCCC0AA4E0D0FBD93889B49E043CA56499CC64C4D0BD11D
  ProductCode: '{5A1AECCB-E0CE-4D2C-833C-29CCEA959448}_is1'
ManifestType: installer
ManifestVersion: 1.4.0

Default locale manifest preview:
# Created using wingetcreate 1.2.8.0
# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.4.0.schema.json

PackageIdentifier: HP.HPCMSL
PackageVersion: 1.6.9
PackageLocale: en-US
Publisher: HP Development Company, L.P.
PackageName: HP Client Management Script Library
License: Proprietary
ShortDescription: HP Client Management Script Library is a collection of powershell functions for managing HP BIOS, and streamlining the download and organization of Softpaq downloads.
ManifestType: defaultLocale
ManifestVersion: 1.4.0


Manifest saved to C:\manifests\h\HP\HPCMSL\1.6.9

Manifest validation succeeded: True

Submitting pull request for manifest...

Pull request can be found here: https://github.com/microsoft/winget-pkgs/pull/114760

PS C:\>

#>