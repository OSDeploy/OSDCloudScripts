<#
.SYNOPSIS
This script allows you to select a CIM class from the 'root\cimv2' namespace and displays all the properties of the instances of the selected class.
.DESCRIPTION
This script allows you to select a CIM class from the 'root\cimv2' namespace and displays all the properties of the instances of the selected class.
#>
$CimClassName = Get-CimClass -Namespace 'root\cimv2' | Sort-Object -Property CimClassName | `
Select-Object -ExpandProperty CimClassName | Out-GridView -PassThru -Title 'Select a CIM Class'

foreach ($CimClass in $CimClassName) {
    Write-Host "Get-CimInstance -ClassName $CimClass" -ForegroundColor Cyan
    Get-CimInstance -ClassName $CimClass | Select-Object -Property *
}