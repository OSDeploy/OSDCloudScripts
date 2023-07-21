<#
.SYNOPSIS
Sets the location of a Windows RE boot image.

.DESCRIPTION
Sets the location of a Windows RE boot image.
Supports both online and offline operations.

/setreimage syntax
/setreimage /path <path_to_Windows_RE_image> [/target <path_to_offline_image>]

/setreimage usage
/path supports UNC paths to locations on the local disk. For example:
Reagentc /setreimage /path S:\Recovery\WindowsRE

/target Specifies the location of the Windows image when you apply the setting offline. For example:
Reagentc /setreimage /path T:\Recovery\WindowsRE /target W:\Windows
    
.LINK
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/reagentc-command-line-options?view=windows-11    

.NOTES
    Author: David Segura
    Modified: 2023-07-20
#>
Reagentc /setreimage /path R:\Recovery\WindowsRE