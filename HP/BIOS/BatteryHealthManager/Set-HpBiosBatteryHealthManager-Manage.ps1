#Requires -RunAsAdministrator
<#
.LINK
https://h20195.www2.hp.com/v2/GetDocument.aspx?docname=4AA7-8536ENW
#>
[CmdletBinding()]
param (
    [ValidateSet('Let HP manage my battery charging', 'Maximize my battery health')]
    [string]$Value = 'Let HP manage my battery charging'
)

$Namespace = 'root\HP\InstrumentedBIOS'
$Class = 'HP_BIOSSetting'
$ClassInterface = 'HP_BIOSSettingInterface'
$Name = 'Battery Health Manager'

try {
    $WmiObject = Get-WmiObject -Namespace $Namespace -Class $ClassInterface -ErrorAction Stop
    $WmiObject.SetBIOSSetting($Name, $Value)
}
catch {
    Write-Error -Message "Failed to set $Name to $Value"
}