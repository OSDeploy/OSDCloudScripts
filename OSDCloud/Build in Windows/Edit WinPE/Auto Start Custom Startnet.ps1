#Requires -RunAsAdministrator

$Startnet = @'
start PowerShell -NoL -C Start-OSDCloudGUI -OSBuild 20H2 -OSEdition Pro -OSLanguage de-de -OSLicense Retail
'@

Edit-OSDCloudWinPE -Startnet $Startnet