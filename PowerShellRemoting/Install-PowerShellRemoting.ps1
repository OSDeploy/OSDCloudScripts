# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#####################################################################################################
#
# Registers the WinRM endpoint for this instance of PowerShell.
#
# If the parameters '-PowerShellHome' were specified, it means that the script will be registering
# an instance of PowerShell from another instance of PowerShell.
#
# If no parameter is specified, it means that this instance of PowerShell is registering itself.
#
# Assumptions:
#     1. The CoreCLR and the PowerShell assemblies are side-by-side in $PSHOME
#     2. Plugins are registered by version number. Only one plugin can be automatically registered
#        per PowerShell version. However, multiple endpoints may be manually registered for a given
#        plugin.
#
#####################################################################################################
[CmdletBinding(DefaultParameterSetName = "NotByPath")]
param
(
    [parameter(Mandatory = $true, ParameterSetName = "ByPath")]
    [switch]$Force,
    [string]
    $PowerShellHome
)

Set-StrictMode -Version 3.0

if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Error "WinRM registration requires Administrator rights. To run this cmdlet, start PowerShell with the `"Run as administrator`" option."
    return
}
function Register-WinRmPlugin
{
    param
    (
        #
        # Expected Example:
        # %windir%\\system32\\PowerShell\\6.0.0\\pwrshplugin.dll
        #
        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $pluginAbsolutePath,

        #
        # Expected Example: powershell.6.0.0-beta.3
        #
        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $pluginEndpointName
    )

    $regKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Plugin\$pluginEndpointName"

    $pluginArchitecture = "64"
    if ($env:PROCESSOR_ARCHITECTURE -match "x86" -or $env:PROCESSOR_ARCHITECTURE -eq "ARM")
    {
        $pluginArchitecture = "32"
    }
    $regKeyValueFormatString = @"
<PlugInConfiguration xmlns="http://schemas.microsoft.com/wbem/wsman/1/config/PluginConfiguration" Name="{0}" Filename="{1}"
    SDKVersion="2" XmlRenderingType="text" Enabled="True" OutputBufferingMode="Block" ProcessIdleTimeoutSec="0" Architecture="{2}"
    UseSharedProcess="false" RunAsUser="" RunAsPassword="" AutoRestart="false">
    <InitializationParameters>
        <Param Name="PSVersion" Value="7.0"/>
    </InitializationParameters>
    <Resources>
        <Resource ResourceUri="http://schemas.microsoft.com/powershell/{0}" SupportsOptions="true" ExactMatch="true">
            <Security Uri="http://schemas.microsoft.com/powershell/{0}" ExactMatch="true"
            Sddl="O:NSG:BAD:P(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"/>
            <Capability Type="Shell"/>
        </Resource>
    </Resources>
    <Quotas IdleTimeoutms="7200000" MaxConcurrentUsers="5" MaxProcessesPerShell="15" MaxMemoryPerShellMB="1024" MaxShellsPerUser="25"
    MaxConcurrentCommandsPerShell="1000" MaxShells="25" MaxIdleTimeoutms="43200000"/>
</PlugInConfiguration>
"@
    $valueString = $regKeyValueFormatString -f $pluginEndpointName, $pluginAbsolutePath, $pluginArchitecture

    New-Item $regKey -Force > $null
    New-ItemProperty -Path $regKey -Name ConfigXML -Value $valueString > $null
}

function New-PluginConfigFile
{
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
    param
    (
        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $pluginFile,

        [string]
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $targetPsHomeDir
    )

    # This always overwrites the file with a new version of it if the
    # script is invoked multiple times.
    Set-Content -Path $pluginFile -Value "PSHOMEDIR=$targetPsHomeDir" -ErrorAction Stop
    Add-Content -Path $pluginFile -Value "CORECLRDIR=$targetPsHomeDir" -ErrorAction Stop

    Write-Verbose "Created Plugin Config File: $pluginFile" -Verbose
}

function Install-PluginEndpoint {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact="Medium")]
    param (
        [Parameter()] [bool] $Force,
        [switch]
        $VersionIndependent
    )

    ######################
    #                    #
    # Install the plugin #
    #                    #
    ######################

    if (-not [String]::IsNullOrEmpty($PowerShellHome))
    {
        $targetPsHome = $PowerShellHome
        $targetPsVersion = & "$targetPsHome\pwsh" -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
    }
    else
    {
        ## Get the PSHome and PSVersion using the current powershell instance
        $targetPsHome = $PSHOME
        $targetPsVersion = $PSVersionTable.PSVersion.ToString()
    }
    Write-Verbose "PowerShellHome: $targetPsHome" -Verbose

    # For default, not tied to the specific version endpoint, we apply
    # only first number in the PSVersion string to the endpoint name.
    # Example name: 'PowerShell.6'.
    if ($VersionIndependent) {
        $dotPos = $targetPsVersion.IndexOf(".")
        if ($dotPos -ne -1) {
            $targetPsVersion = $targetPsVersion.Substring(0, $dotPos)
        }
    }

    Write-Verbose "Using PowerShell Version: $targetPsVersion" -Verbose

    $pluginEndpointName = "PowerShell.$targetPsVersion"

    $endPoint = Get-PSSessionConfiguration $pluginEndpointName -Force:$Force -ErrorAction silentlycontinue 2>&1

    # If endpoint exists and -Force parameter was not used, the endpoint would not be overwritten.
    if ($endpoint -and !$Force)
    {
        Write-Error -Category ResourceExists -ErrorId "PSSessionConfigurationExists" -Message "Endpoint $pluginEndpointName already exists."
        return
    }

    if (!$PSCmdlet.ShouldProcess($pluginEndpointName)) {
        return
    }

    if ($PSVersionTable.PSVersion -lt "6.0")
    {
        # This script is primarily used from Windows PowerShell for Win10 IoT and NanoServer to setup PSCore6 remoting endpoint
        # so it's ok to hardcode to 'C:\Windows' for those systems
        $pluginBasePath = Join-Path "C:\Windows\System32\PowerShell" $targetPsVersion
    }
    else
    {
        $pluginBasePath = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Windows) + "\System32\PowerShell") $targetPsVersion
    }

    $resolvedPluginAbsolutePath = ""
    if (! (Test-Path $pluginBasePath))
    {
        Write-Verbose "Creating $pluginBasePath"
        $resolvedPluginAbsolutePath = New-Item -Type Directory -Path $pluginBasePath
    }
    else
    {
        $resolvedPluginAbsolutePath = Resolve-Path $pluginBasePath
    }

    $pluginPath = Join-Path $resolvedPluginAbsolutePath "pwrshplugin.dll"

    # This is forced to ensure the file is placed correctly
    Copy-Item $targetPsHome\pwrshplugin.dll $resolvedPluginAbsolutePath -Force -Verbose -ErrorAction Stop

    $pluginFile = Join-Path $resolvedPluginAbsolutePath "RemotePowerShellConfig.txt"
    New-PluginConfigFile $pluginFile (Resolve-Path $targetPsHome)

    # Register the plugin
    Register-WinRmPlugin $pluginPath $pluginEndpointName

    ####################################################################
    #                                                                  #
    # Validations to confirm that everything was registered correctly. #
    #                                                                  #
    ####################################################################

    if (! (Test-Path $pluginFile))
    {
        throw "WinRM Plugin configuration file not created. Expected = $pluginFile"
    }

    if (! (Test-Path $resolvedPluginAbsolutePath\pwrshplugin.dll))
    {
        throw "WinRM Plugin DLL missing. Expected = $resolvedPluginAbsolutePath\pwrshplugin.dll"
    }

    try
    {
        Write-Host "`nGet-PSSessionConfiguration $pluginEndpointName" -ForegroundColor "green"
        Get-PSSessionConfiguration $pluginEndpointName -ErrorAction Stop
    }
    catch [Microsoft.PowerShell.Commands.WriteErrorException]
    {
        throw "No remoting session configuration matches the name $pluginEndpointName."
    }
}

Install-PluginEndpoint -Force $Force
Install-PluginEndpoint -Force $Force -VersionIndependent

Write-Host "Restarting WinRM to ensure that the plugin configuration change takes effect.`nThis is required for WinRM running on Windows SKUs prior to Windows 10." -ForegroundColor Magenta
Restart-Service winrm


# SIG # Begin signature block
# MIInlgYJKoZIhvcNAQcCoIInhzCCJ4MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAmMBO/z6uvMDNL
# ywsEntW1l8ui09V7mB9QxyD4sH3/L6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGXYwghlyAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIASzAbkapgzkIHyjEtglU6vA
# HP0o6aqvz8pdcZCJCVXCMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAUNPFNW3CX2JC39N1Yl5lkm3gWhvquEbzc5FSXyBhRabPkd69IVWgOhYC
# otYoRq3JNtcadlEeYluRkwaKC+GPZO17qukJgFyZBBJKNDY+35K24nPuYp6TCbYC
# cjjLYAMMKH2PMaeMKq9rmDE8e+sdYO3uTrtucKt3BSww5HFP/aQ5dZMIJPCji9TU
# fQJXW15vTvVCVjGrEP20HHEXWq27oLyKIrqEXZyRSCy+l7T8lFc20YEr/wEcQWpw
# rA2MsRIJGN5GEF37o4za5s6a18VmpwvzKxbSn/x5pgFiK6KZgQ/BVvz+O4ZrZpRR
# uErJRkmQdnYDmaiS/yM+EMmqncoTsqGCFwAwghb8BgorBgEEAYI3AwMBMYIW7DCC
# FugGCSqGSIb3DQEHAqCCFtkwghbVAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCArw1T1lX92vVEwNvSxjTzZ0eKoD303r041tNXLzCE7VAIGZIt2pYcS
# GBMyMDIzMDcxMzAwMzQxNy4wMTNaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1l
# cmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4QTgyLUUz
# NEYtOUREQTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCC
# EVcwggcMMIIE9KADAgECAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIyMTEwNDE5MDEy
# OFoXDTI0MDIwMjE5MDEyOFowgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjhBODItRTM0Ri05RERBMSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtfEJvPKOSFn3petp9wco29/UoJmDDyHpmmpRruRVWBF3
# 7By0nvrszScOV/K+LvHWWWC4S9cme4P63EmNhxTN/k2CgPnIt/sDepyACSkya4uk
# qc1sT2I+0Uod0xjy9K2+jLH8UNb9vM3yH/vCYnaJSUqgtqZUly82pgYSB6tDeZIY
# cQoOhTI+M1HhRxmxt8RaAKZnDnXgLdkhnIYDJrRkQBpIgahtExtTuOkmVp2y8YCo
# FPaUhUD2JT6hPiDD7qD7A77PLpFzD2QFmNezT8aHHhKsVBuJMLPXZO1k14j0/k68
# DZGts1YBtGegXNkyvkXSgCCxt3Q8WF8laBXbDnhHaDLBhCOBaZQ8jqcFUx8ZJSXQ
# 8sbvEnmWFZmgM93B9P/JTFTF6qBVFMDd/V0PBbRQC2TctZH4bfv+jyWvZOeFz5yl
# tPLRxUqBjv4KHIaJgBhU2ntMw4H0hpm4B7s6LLxkTsjLsajjCJI8PiKi/mPKYERd
# mRyvFL8/YA/PdqkIwWWg2Tj5tyutGFtfVR+6GbcCVhijjy7l7otxa/wYVSX66Lo0
# alaThjc+uojVwH4psL+A1qvbWDB9swoKla20eZubw7fzCpFe6qs++G01sst1SaA0
# GGmzuQCd04Ue1eH3DFRDZPsN+aWvA455Qmd9ZJLGXuqnBo4BXwVxdWZNj6+b4P8C
# AwEAAaOCATYwggEyMB0GA1UdDgQWBBRGsYh76V41aUCRXE9WvD++sIfGajAfBgNV
# HSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBU
# aW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwG
# CCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRz
# L01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNV
# HRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IC
# AQARdu3dCkcLLPfaJ3rR1M7D9jWHvneffkmXvFIJtqxHGWM1oqAh+bqxpI7HZz2M
# eNhh1Co+E9AabOgj94Sp1seXxdWISJ9lRGaAAWzA873aTB3/SjwuGqbqQuAvUzBF
# CO40UJ9anpavkpq/0nDqLb7XI5H+nsmjFyu8yqX1PMmnb4s1fbc/F30ijaASzqJ+
# p5rrgYWwDoMihM5bF0Y0riXihwE7eTShak/EwcxRmG3h+OT+Ox8KOLuLqwFFl1si
# TeQCp+YSt4J1tWXapqGJDlCbYr3Rz8+ryTS8CoZAU0vSHCOQcq12Th81p7QlHZv9
# cTRDhZg2TVyg8Gx3X6mkpNOXb56QUohI3Sn39WQJwjDn74J0aVYMai8mY6/WOurK
# MKEuSNhCiei0TK68vOY7sH0XEBWnRSbVefeStDo94UIUVTwd2HmBEfY8kfryp3Rl
# A9A4FvfUvDHMaF9BtvU/pK6d1CdKG29V0WN3uVzfYETJoRpjLYFGq0MvK6QVMmuN
# xk3bCRfj1acSWee14UGjglxWwvyOfNJe3pxcNFOd8Hhyp9d4AlQGVLNotaFvopgP
# LeJwUT3dl5VaAAhMwvIFmqwsffQy93morrprcnv74r5g3ejC39NYpFEoy+qmzLW1
# jFa1aXE2Xb/KZw2yawqldSp0Hu4VEkjGxFNc+AztIUWwmTCCB3EwggVZoAMCAQIC
# EzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBS
# b290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoX
# DTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9DtWC
# 0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VG
# Iwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP
# 2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXcag/P
# XfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJj361
# VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjklqwB
# Sru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37ZyL9t9
# X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M269e
# wvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDw
# wvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr
# 9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode2o+e
# FnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEAATAj
# BgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+n
# FV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEBMEEw
# PwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9j
# cy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt4Swf
# ZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsPMeTC
# j/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++Kctu
# 2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9QKC/
# GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2wh3D
# YXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbO
# xnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5zbcqO
# Cb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nxt67I
# 6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0
# zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+ANuOaM
# mdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNT
# TY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLOMIICNwIBATCB+KGB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046OEE4Mi1FMzRGLTlEREExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAMp1N1VLhPMvWXEoZfmF4apZlnRUoIGD
# MIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEF
# BQACBQDoWYw7MCIYDzIwMjMwNzEzMDQzMTU1WhgPMjAyMzA3MTQwNDMxNTVaMHcw
# PQYKKwYBBAGEWQoEATEvMC0wCgIFAOhZjDsCAQAwCgIBAAICA9UCAf8wBwIBAAIC
# EdswCgIFAOha3bsCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAK
# MAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAwIeTZ7dOv
# 6xebGJJofU2bbUZed0Lcuo9b8fhtVxtVYi6h/Qro37jxeEnUO0xJsvvt8LsAbOqo
# YNObKHGprivkOzDoqhKEC6cIbZtBcbOxSxnILOeNXr9yHJJ0OpDAN/RGHttdWizu
# jvsDiPte6Zi/ZH3ns+GDm9alx1cInURQ4zGCBA0wggQJAgEBMIGTMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABwvp9hw5UU0ckAAEAAAHCMA0GCWCG
# SAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZI
# hvcNAQkEMSIEIDXxdkhEGR/Exz9FbdCK+mXgt1VuIBjNIHEnHovrQifFMIH6Bgsq
# hkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgypNgW8fpsMV57r0F5beUuiEVOVe4Bdma
# O+e28mGDUBYwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAIT
# MwAAAcL6fYcOVFNHJAABAAABwjAiBCAWdCpufEhEtRG1xrKnCLIWPhB6TlkGVVHs
# a552X1LEiDANBgkqhkiG9w0BAQsFAASCAgB6EEgAlZTLGN0xq5xDbGzCpcHniNr5
# LH0oCC9tn7FhpAbSVLCepSI0a5GBVR5iETwiWRuzl9QOvnZJDCIzSOI7nRQBrXcZ
# wI0CRO1DOTJZVRZ9b7CD2X4AUElfPszp02oDF1YpcX+ePlcR3IxDZxlHmKRHRrJX
# i1vXTKTyEUEJ8DVhmxpwYoylGz1F+UjeguXovil5pkbmCTTXROZw5h9ut4eBvn7w
# 7qNgWaR+m1qU5cfLeCX9MsZmBr9r6Yu9EtipRmDIAQxfecyxoRty7lhKdmLup85x
# WbDYnVvie3o1MqEQx5DmtXxNhYUvAKxaB/DOnhhqlviDx/bULj+lR0qV63l/iPVJ
# RVyh++QD2p+iyJgAjElvxa5+7uEn68t6XmI+tb2iMAWviw/QUzu+CiqGGM7KPRF0
# 1fQKexO0WPfqcEU30wWffckKqUgZGdS8/NVbBxlcTYY2ErJtFKAaTLUBP63FxKfp
# BFZdn2la7tmOzPvMpKZ7JO3NqXxgdVoqRanomGPzmh427y8v5j82GBXabOSok67G
# B/IrPSDxEnOd/+uLwus32xZvEPcB+BA7FPHLYQi64qe6u4CtVXjoMzmB5t8xRXda
# 0aUJGU13SXxFCftHYPqdd1VU+FZEa3b4yCf2UEnnGGMd9T9Nqm+wgwaXm777+w3p
# QwLfNiIhSTLeow==
# SIG # End signature block
