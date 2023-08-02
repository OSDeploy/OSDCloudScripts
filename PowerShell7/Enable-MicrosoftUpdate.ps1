# This registers Microsoft Update via a predifened GUID with the Windows Update Agent.
# https://docs.microsoft.com/en-us/windows/win32/wua_sdk/opt-in-to-microsoft-update

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