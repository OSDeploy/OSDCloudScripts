<#
.DESCRIPTION
The validate command of the winget tool validates a manifest for submitting software to the Microsoft Community Package Manifest Repository on GitHub.
The manifest must be a YAML file that follows the specification.

.LINK
https://learn.microsoft.com/en-us/windows/package-manager/winget/validate

.NOTES
Usage
winget validate [--manifest] \<path>

Arguments
-q,--query	        The query used to search for an application.
-?, --help	        Gets additional help on this command.

Options
--manifest	        the path to the manifest to be validated.
--verbose-logs	    Used to override the logging setting and create a verbose log.
-?, --help	        get additional help on this command
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # In PowerShell, you will need to escape the quotes, so this command becomes:
    winget validate --manifest C:\Temp\MyApp.yaml
}