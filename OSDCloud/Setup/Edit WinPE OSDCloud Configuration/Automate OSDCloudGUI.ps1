#Requires -RunAsAdministrator

$Automate = @'
{
    "BrandName":  "Workplace Ninja 2023",
    "BrandColor":  "RED",
    "OSActivation":  "Retail",
    "OSEdition":  "Pro",
    "OSLanguage":  "de-de",
    "OSImageIndex":  9,
    "OSName":  "Windows 11 22H2 x64",
    "OSReleaseID":  "22H2",
    "OSVersion":  "Windows 11",
    "OSActivationValues":  [
                                "Retail",
                                "Volume"
                            ],
    "OSEditionValues":  [
                            "Home",
                            "Education",
                            "Enterprise",
                            "Pro"
                        ],
    "OSLanguageValues":  [
                                "de-de",
                                "en-us"
                            ],
    "OSNameValues":  [
                            "Windows 11 22H2 x64",
                            "Windows 10 22H2 x64"
                        ],
    "OSReleaseIDValues":  [
                                "22H2"
                            ],
    "OSVersionValues":  [
                            "Windows 11",
                            "Windows 10"
                        ],
    "ClearDiskConfirm":  false,
    "restartComputer":  false,
    "updateDiskDrivers":  false,
    "updateFirmware":  false,
    "updateNetworkDrivers":  false,
    "updateSCSIDrivers":  false
}
'@

$AutomateISO = "$(Get-OSDCloudWorkspace)\Media\OSDCloud\Automate"
if (!(Test-Path $AutomateISO)) {
    New-Item -Path $AutomateISO -ItemType Directory -Force
}
$Automate | Out-File -FilePath "$AutomateISO\Start-OSDCloudGUI.json" -Force


$AutomateUSB = "$(Get-OSDCloudWorkspace)\Media\Automate"
if (!(Test-Path $AutomateUSB)) {
    New-Item -Path $AutomateUSB -ItemType Directory -Force
}
$Automate | Out-File -FilePath "$AutomateUSB\Start-OSDCloudGUI.json" -Force

# Run Edit-OSDCloudWinPE to rebuild