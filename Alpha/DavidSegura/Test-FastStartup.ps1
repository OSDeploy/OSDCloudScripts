function Test-FastStartup {
    [CmdletBinding()]
    param()
    return (((Get-ItemProperty 'HKLM:\SYSTEM\ControlSet001\Control\Session Manager\Power' -ErrorAction SilentlyContinue).HiberbootEnabled) -eq 1)
}
Test-FastStartup