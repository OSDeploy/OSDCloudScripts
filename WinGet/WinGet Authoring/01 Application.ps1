<#
.SYNOPSIS
This script demonstrates the first steps to authoring a package for WinGet.

.DESCRIPTION
Before you invest the time to generate and submit a manifest, you should check to see if the package already exists.
Start out with winget search <package>.
If that doesn't yield anything, try a quick search using the search box in the top left corner of GitHub for the package "In this repository".
If you still don't find anything, finally check to see if there is already a PR for the package by putting the package in the filters box, and be sure to remove the "is:pr is:open" filters.

.EXAMPLE
PS C:\> winget search HP.HPCMSL
Name                                Id        Version Source
-------------------------------------------------------------
HP Client Management Script Library HP.HPCMSL 1.6.8   winget

.NOTES
# HP Client Management Script Library Reference
# https://www.hp.com/us-en/solutions/client-management-solutions/download.html

# Latest Release 1.6.10
# https://hpia.hpcloud.hp.com/downloads/cmsl/hp-cmsl-1.6.10.exe
#>
winget search HP.HPCMSL