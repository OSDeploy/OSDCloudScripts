function Get-CimMethod {
    [CmdletBinding()]
    param (
        [string]$ClassName = 'Win32_Desktop',
        [string]$MethodName
    )

    if ($MethodName) {
        $class = Get-CimClass -ClassName $ClassName
        $class.CimClassMethods[$MethodName].Parameters
    }
    else {
        Get-CimClass -ClassName $ClassName | Select-Object -ExpandProperty CimClassMethods
    }
}

Get-CimMethod -ClassName Win32_Desktop