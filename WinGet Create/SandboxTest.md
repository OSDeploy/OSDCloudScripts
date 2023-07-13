Using SandboxTest.ps1
The sandbox test script is designed to allow you to test manifests locally without having to install the application to your Windows installation directly. To do this, it makes use of the Windows Sandbox.

First, create a fork of this repository and then clone it to your computer. Once the repository has finished cloning, you will need to open a PowerShell terminal since the SandboxTest script is designed to be run from the command line. In the PowerShell terminal which you just opened, navigate to the folder the repository was cloned into and then into the Tools folder. You can do this by using cd <drive>\<path-to-parent>\winget-pkgs\Tools. Once you are here, you should be ready to run the script.

Usage
To test a manifest, simply call the script with the full path to the manifest as an argument. This will validate the manifest, open Windows Sandbox, and attempt to install the package defined in the manifest.

.\SandboxTest.ps1 <path-to-manifest> [<options>]
The following optional arguments are supported:

Argument	Description
-Script	Post-installation script to run in the Sandbox
-MapFolder	The folder to map in Sandbox. Default is the current directory
-WinGetVersion	Specify version of WinGet to use in Sandbox
-Prerelease	Allow preview release versions of WinGet
-EnableExperimentalFeatures	Enable WinGet experimental features
-SkipManifestValidation	Skip winget validate -m <manifest> if you have already validated the manifest
Examples
Test manifest on the latest stable release of WinGet

.\SandboxTest.ps1 <path-to-manifest>
Test manifest on the latest preview release of WinGet

.\SandboxTest.ps1 <path-to-manifest> -Prerelease
Test manifest on a specified version of WinGet

.\SandboxTest.ps1 <path-to-manifest> -WinGetVersion 1.4.2011 -Prerelease -Script {Write-Host 'The script has finished'}
Install a package from the repository in Sandbox

.\SandboxTest.ps1 -WinGetVersion 1.5 -Script {winget install <PackageIdentifier> --accept-source-agreements}
System Requirements
In order to use the SandboxTest script, you must have Windows Sandbox enabled. The Windows Sandbox has the following system requirements -

Windows 10 Pro, Enterprise or Education build 18305 or Windows 11 (Windows Sandbox is currently not supported on Windows Home edition)
AMD64 architecture
Virtualization capabilities enabled in BIOS
At least 4 GB of RAM
At least 1 GB of free disk space
At least two CPU cores
To enable the sandbox, open PowerShell and run the command Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online. Once the command completes, restart your computer to finish the installation.

References to SandboxTest.ps1
The SandboxTest script has been integrated as part of the toolset here in the winget-pkgs repository. The YamlCreate Script uses SandboxTest to test the creation of new manifests when they are created. The PRTest Script also uses SandboxTest as a dependency to test manifests which have been submitted to the repository in PRs.