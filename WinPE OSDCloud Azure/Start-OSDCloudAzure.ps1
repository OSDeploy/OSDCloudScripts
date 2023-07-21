#Requires -RunAsAdministrator
<#
.SYNOPSIS

.DESCRIPTION
This is a good script to see how OSDCloudAzure starts
#>
[CmdletBinding()]
param()

if ($env:SystemDrive -eq 'X:') {
    if ($Force) {
        $Force = $false
        $Global:AzOSDCloudBlobImage = $null
    }

    $Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Start-OSDCloudAzure.log"
    $null = Start-Transcript -Path (Join-Path "$env:SystemRoot\Temp" $Transcript) -ErrorAction Ignore
    Invoke-Expression -Command (Invoke-RestMethod -Uri functions.osdcloud.com)
    osdcloud-StartWinPE -OSDCloud -Azure
    Connect-OSDCloudAzure
    Get-OSDCloudAzureResources
    $null = Stop-Transcript -ErrorAction Ignore

    if ($Global:AzOSDCloudBlobImage) {
        Write-Host -ForegroundColor DarkGray '========================================================================='
        Write-Host -ForegroundColor Green 'Start-OSDCloudAzure'
        & "$((Get-Module -Name OSD -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).ModuleBase)\Projects\OSDCloudAzure\MainWindow.ps1"
        Start-Sleep -Seconds 2

        if ($Global:StartOSDCloud.AzOSDCloudImage) {
            Write-Host -ForegroundColor DarkGray '========================================================================='
            Write-Host -ForegroundColor Green "Invoke-OSDCloud ... Starting in 5 seconds..."
            Start-Sleep -Seconds 5
            Invoke-OSDCloud
        }
        else {
            Write-Warning "Unable to get a Windows Image from OSDCloudAzure to handoff to Invoke-OSDCloud"
        }
    }
    else {
        Write-Warning 'Unable to find resources to OSDCloudAzure'
    }
}
else {
    Write-Warning "OSDCloudAzure must be run from WinPE"
}