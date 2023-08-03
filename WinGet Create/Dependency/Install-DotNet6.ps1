<#
https://github.com/microsoft/winget-create
Using the standalone exe:
The latest version of the standalone exe can be found at https://aka.ms/wingetcreate/latest, and the latest preview version can be found at https://aka.ms/wingetcreate/preview, both of these require .NET Runtime 6.0 to be installed on the build machine.
To install this on your build machine in your pipeline, you can include the following dotnet task:
Or you can utilize a PowerShell task and run the following script.

Note: Make sure your build machine has the Microsoft Visual C++ Redistributable for Visual Studio already installed.
Without this, the standalone WingetCreate exe will fail to execute and likely show a "DllNotFoundException" error.

https://learn.microsoft.com/en-US/cpp/windows/latest-supported-vc-redist?view=msvc-170
#>

Invoke-WebRequest https://dot.net/v1/dotnet-install.ps1 -OutFile dotnet-install.ps1
.\dotnet-install.ps1 -Runtime dotnet -Architecture x64 -Version 6.0.13 -InstallDir $env:ProgramFiles\dotnet