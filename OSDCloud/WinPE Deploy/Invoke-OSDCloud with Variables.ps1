#Requires -RunAsAdministrator

$Global:MyOSDCloud = @{
    ImageFileUrl    = 'http://b1.download.windowsupdate.com/c/upgr/2022/09/22621.382.220806-0833.ni_release_svc_refresh_clientconsumer_ret_x64fre_de-de_4b92f7c5f5d5236fe4ba5b3de8f38f847a152db8.esd'
    OSImageIndex    = 9
    restartComputer = $false
}

Invoke-OSDCloud