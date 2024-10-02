<#
.DESCRIPTION
The show command of the winget tool displays details for the specified application, including details on the source of the application as well as the metadata associated with the application.
The show command only shows metadata that was submitted with the application.
If the submitted application excludes some metadata, then the data will not be displayed.

.LINK
https://learn.microsoft.com/en-us/windows/package-manager/winget/show

.NOTES
Usage
winget show [[-q] \<query>] [\<options>]

Arguments
-q,--query	        The query used to search for an application.
-?, --help	        Gets additional help on this command.

Options
-m,--manifest	            The path to the manifest of the application to install.
--id	                    Filter results by ID.
--name	                    Filter results by name.
--moniker	                Filter results by application moniker.
-v,--version	            Use the specified version. The default is the latest version.
-s,--source	                Find the application using the specified source.
-e,--exact	                Find the application using exact match.
--versions	                Show available versions of the application.
--header	                Optional Windows-Package-Manager REST source HTTP header.
--accept-source-agreements  Used to accept the source license agreement, and avoid the prompt.
--verbose-logs	            Used to override the logging setting and create a verbose log.
#>
[CmdletBinding()]
param()

if (Get-Command 'WinGet' -ErrorAction SilentlyContinue) {
    # In PowerShell, you will need to escape the quotes, so this command becomes:
    winget search -q `"HPCMSL`"
}