#Requires -RunAsAdministrator
<#
.SYNOPSIS
Enables Microsoft Update via a predefined GUID with the Windows Update Agent.

.DESCRIPTION
This script registers Microsoft Update via a predefined GUID with the Windows Update Agent.
It uses the ServiceManager COM object to query and add the service registration.
If the service is already registered, it will not be added again.

.PARAMETER None
This script does not accept any parameters.

.EXAMPLE
Enable-MicrosoftUpdate.ps1
This example runs the script to enable Microsoft Update.

.NOTES
This script requires administrative privileges to run.
It also requires the ServiceManager COM object to be installed on the system.
The GUID used in this script is the default GUID for Microsoft Update.
If you need to use a different GUID, you can modify the script accordingly.

.LINK
https://docs.microsoft.com/en-us/windows/win32/wua_sdk/opt-in-to-microsoft-update
#>
$serviceManager = (New-Object -ComObject Microsoft.Update.ServiceManager)
$isRegistered = $serviceManager.QueryServiceRegistration('7971f918-a847-4430-9279-4a52d1efe18d').Service.IsRegisteredWithAu

if (!$isRegistered) {
    Write-Verbose -Verbose "Opting into Microsoft Update as the Autmatic Update Service"
    # 7 is the combination of asfAllowPendingRegistration, asfAllowOnlineRegistration, asfRegisterServiceWithAU
    # AU means Automatic Updates
    $null = $serviceManager.AddService2('7971f918-a847-4430-9279-4a52d1efe18d', 7, '')
}
else {
    Write-Verbose -Verbose "Microsoft Update is already registered for Automatic Updates"
}

$isRegistered = $serviceManager.QueryServiceRegistration('7971f918-a847-4430-9279-4a52d1efe18d').Service.IsRegisteredWithAu

# Return if it was successful, which is the opposite of Pending.
return $isRegistered