#Requires -RunAsAdministrator
if ((Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online).State -eq 'Enabled') {
    Set-OSDCloudVMSettings -MemoryStartupGB 10 -ProcessorCount 2 -SwitchName 'Default Switch'
}