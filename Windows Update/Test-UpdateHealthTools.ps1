#Requires -RunAsAdministrator
<#
.SYNOPSIS
Update Health Tools test for KB4023057.

.DESCRIPTION
Tests if the Update Health Tools are installed by testing if 'KB4023057 - Update for Windows 10 Update Service components' is installed.
    
.LINK
https://learn.microsoft.com/en-us/mem/intune/protect/windows-10-expedite-updates

.NOTES
    Author: David Segura
    Modified: 2023-07-21
#>
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$historyCount = $Searcher.GetTotalHistoryCount()
$list = $Searcher.QueryHistory(0, $historyCount) | Select-Object -Property "Title"
foreach ($update in $list)
{
   if ($update.Title.Contains("4023057"))
   {
      return 1
   }
}
return 0