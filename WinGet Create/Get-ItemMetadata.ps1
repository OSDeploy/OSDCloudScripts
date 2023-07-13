Function Get-ItemMetadata {
    Param
    (
      [Parameter(Mandatory = $true)]
      [string] $FilePath
    )
    try {
      $MetaDataObject = [ordered] @{}
      $FileInformation = (Get-Item $FilePath)
      $ShellApplication = New-Object -ComObject Shell.Application
      $ShellFolder = $ShellApplication.Namespace($FileInformation.Directory.FullName)
      $ShellFile = $ShellFolder.ParseName($FileInformation.Name)
      $MetaDataProperties = [ordered] @{}
      0..400 | ForEach-Object -Process {
        $DataValue = $ShellFolder.GetDetailsOf($null, $_)
        $PropertyValue = (Get-Culture).TextInfo.ToTitleCase($DataValue.Trim()).Replace(' ', '')
        if ($PropertyValue -ne '') {
          $MetaDataProperties["$_"] = $PropertyValue
        }
      }
      foreach ($Key in $MetaDataProperties.Keys) {
        $Property = $MetaDataProperties[$Key]
        $Value = $ShellFolder.GetDetailsOf($ShellFile, [int] $Key)
        if ($Property -in 'Attributes', 'Folder', 'Type', 'SpaceFree', 'TotalSize', 'SpaceUsed') {
          continue
        }
        If (($null -ne $Value) -and ($Value -ne '')) {
          $MetaDataObject["$Property"] = $Value
        }
      }
      [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ShellFile)
      [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ShellFolder)
      [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ShellApplication)
      [System.GC]::Collect()
      [System.GC]::WaitForPendingFinalizers()
      return $MetaDataObject
    } catch {
      Write-Error -Message $_.ToString()
      break
    }
}
<#
Name                           hp-cmsl-1.6.9.exe
Size                           5.75 MB
ItemType                       Application
DateModified                   7/3/2023 12:52 AM
DateCreated                    7/3/2023 12:52 AM
DateAccessed                   7/3/2023 12:52 AM
PerceivedType                  Application
Owner                          OSDCode\david
Kind                           Program
Rating                         Unrated
Copyright                      Copyright 2018-2022 HP Development Company, L.P.
Company                        HP Development Company, L.P.
FileDescription                HP Client Management Script Library Installer
Computer                       OSDCode (this PC)
FileExtension                  .exe
Filename                       hp-cmsl-1.6.9.exe
FileVersion                    1.6.9.169
Shared                         No
FolderName                     HPCMSL
FileLocation                   C:\Temp\WinGet\HPCMSL
Path                           C:\Temp\WinGet\HPCMSL\hp-cmsl-1.6.9.exe
Language                       Language Neutral
LinkStatus                     Unresolved
SharingStatus                  Not shared
ProductName                    HP Client Management Script Library
ProductVersion                 1.6.9
#>
Get-ItemMetadata -FilePath 'C:\Temp\WinGet\HPCMSL\hp-cmsl-1.6.9.exe'
<#
Name                           hp-cmsl-1.6.10.exe
Size                           5.75 MB
ItemType                       Application
DateModified                   7/3/2023 12:51 AM
DateCreated                    7/3/2023 12:51 AM
DateAccessed                   7/3/2023 12:51 AM
PerceivedType                  Application
Owner                          OSDCode\david
Kind                           Program
Rating                         Unrated
Copyright                      Copyright 2018-2023 HP Development Company, L.P.
Company                        HP Development Company, L.P.
FileDescription                HP Client Management Script Library Installer
Computer                       OSDCode (this PC)
FileExtension                  .exe
Filename                       hp-cmsl-1.6.10.exe
FileVersion                    1.6.10.295
Shared                         No
FolderName                     HPCMSL
FileLocation                   C:\Temp\WinGet\HPCMSL
Path                           C:\Temp\WinGet\HPCMSL\hp-cmsl-1.6.10.exe
Language                       Language Neutral
LinkStatus                     Unresolved
SharingStatus                  Not shared
ProductName                    HP Client Management Script Library
ProductVersion                 1.6.10
#>
Get-ItemMetadata -FilePath 'C:\Temp\WinGet\HPCMSL\hp-cmsl-1.6.10.exe'