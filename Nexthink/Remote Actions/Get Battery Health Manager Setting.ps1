Add-Type -Path $env:NEXTHINK\RemoteActions\nxtremoteactions.dll

<#
.SYNOPSIS
  Get the value of a BIOS setting.

.DESCRIPTION
  This function retrieves the value of a BIOS setting. Whereas the Get-HPBIOSSetting retrieves all setting fields, Get-HPBIOSSettingValue retrieves only the setting's value.

.NOTES
  Requires HP BIOS.

.PARAMETER name
  The name of the setting to retrieve

.PARAMETER ComputerName
  Alias -Target. Execute the command on specified target computer. If not specified, the command is executed on the local computer.

.PARAMETER CimSession
  A pre-established CIM Session (as created by [New-CIMSession](https://docs.microsoft.com/en-us/powershell/module/cimcmdlets/new-cimsessionoption?view=powershell-5.1) cmdlet). Use this to pass a preconfigured session object to optimize remote connections or specify the connection protocol (Wsman or DCOM). If not specified, the function will create its own one-time use CIM Session object, and default to DCOM protocol.

.EXAMPLE
  Get-HPBIOSSettingValue -Name 'Asset Tracking Number'
#>

<#
.SYNOPSIS
  This is a private function for internal use only

.DESCRIPTION
  This is a private function for internal use only

.EXAMPLE

.NOTES
  - This is a private function for internal use only
#>
function newCimSession () {
    [CmdletBinding()]
    param
    (
      [Parameter(Position = 0)] $SkipTestConnection = $true,
      [Parameter(Position = 1)] $Protocol = 'DCOM',
      [Parameter(Position = 2)] $target = '.',
      [Parameter(Position = 3)] $SessionName = 'CMSLCimSession'
    )
  
    Write-Verbose "Creating new CimSession (Protocol= $Protocol, Computer=$Target)"
    $opts = New-CimSessionOption -Protocol $Protocol
  
    $params = @{
      Name = $SessionName
      SkipTestConnection = $SkipTestConnection
      SessionOption = $opts
    }
    if ($Target -and ($Target -ne ".")) {
      $params.Add("ComputerName",$target)
    }
    New-CimSession @params
  
  }
  

function getFormattedBiosSettingValue {
    [CmdletBinding()]
    param($obj)
    switch ($obj.CimClass.CimClassName) {
      { $_ -eq 'HPBIOS_BIOSString' } {
        $result = $obj.Value
  
      }
      { $_ -eq 'HPBIOS_BIOSInteger' } {
        $result = $obj.Value
      }
      { $_ -eq 'HPBIOS_BIOSEnumeration' } {
        $result = $obj.CurrentValue
      }
      { $_ -eq 'HPBIOS_BIOSPassword' } {
        throw [System.InvalidOperationException]"Password values cannot be retrieved, it will always result in an empty string"
      }
      { $_ -eq 'HPBIOS_BIOSOrderedList' } {
        $result = $obj.Value
      }
    }
    return $result
  }

  function getNamespace {
    [CmdletBinding()]
    param()
    [string]$c = [environment]::GetEnvironmentVariable("HP_BIOS_NAMESPACE","User")
    if (-not $c) {
      return "root\HP\InstrumentedBIOS"
    }
    Write-Verbose ("Default BIOS namespace is overwritten via HP_BIOS_NAMESPACE Variable, to $c. This should only happen during development.")
    return $c
  }
  

  function Get-HPBIOSSetting {
    [CmdletBinding(DefaultParameterSetName = 'NewSession',HelpUri = "https://developers.hp.com/hp-client-management/doc/Get-HPBIOSSetting")]
    param(
      [Parameter(ParameterSetName = 'NewSession',Position = 0,Mandatory = $true)]
      [Parameter(ParameterSetName = 'ReuseSession',Position = 0,Mandatory = $true)]
      $Name,
      [Parameter(ParameterSetName = 'NewSession',Position = 1,Mandatory = $false)]
      [Parameter(ParameterSetName = 'ReuseSession',Position = 1,Mandatory = $false)]
      [ValidateSet('XML','JSON','BCU','CSV')]
      $Format,
      [Parameter(ParameterSetName = 'NewSession',Position = 2,Mandatory = $false)]
      [Alias('Target')]
      [string]$ComputerName = ".",
      [Parameter(ParameterSetName = 'ReuseSession',Position = 3,Mandatory = $true)]
      [CimSession]$CimSession
    )
  
    $ns = getNamespace
    Write-Verbose "Reading HP BIOS Setting '$Name' from $ns on '$ComputerName'"
    $result = $null
  
    $params = @{
      Class = "HP_BIOSSetting"
      Namespace = $ns
      Filter = "Name='$name'"
    }
  
    if ($PSCmdlet.ParameterSetName -eq 'NewSession') {
      $params.CimSession = newCimSession -Target $ComputerName
    }
    if ($PSCmdlet.ParameterSetName -eq 'ReuseSession') {
      $params.CimSession = $CimSession
    }
  
    try {
      $result = Get-CimInstance @params -ErrorAction stop
    } catch [Microsoft.Management.Infrastructure.CimException]
    {
      if ($_.Exception.Message.trim() -eq "Access denied")
      {
        throw [System.UnauthorizedAccessException]"Access denied: Please ensure you have the rights to perform this operation."
      }
      throw [System.NotSupportedException]"$($_.Exception.Message): Please ensure this is a supported HP device."
    }
  
  
    if (-not $result) {
      $Err = "Setting not found: '" + $name + "'"
      throw [System.Management.Automation.ItemNotFoundException]$Err
    }
    Add-Member -InputObject $result -Force -NotePropertyName "Class" -NotePropertyValue $result.CimClass.CimClassName | Out-Null
    Write-Verbose "Retrieved HP BIOS Setting '$name' ok."
  
    switch ($format) {
      { $_ -eq 'CSV' } { return convertSettingToCSV ($result) }
      { $_ -eq 'XML' } { return convertSettingToXML ($result) }
      { $_ -eq 'BCU' } { return convertSettingToBCU ($result) }
      { $_ -eq 'JSON' } { return convertSettingToJSON ($result) }
      default { return $result }
    }
  }
  
function Get-HPBIOSSettingValue {
    [CmdletBinding(DefaultParameterSetName = 'NewSession',HelpUri = "https://developers.hp.com/hp-client-management/doc/Get-HPBIOSSettingValue")]
    param(
      [Parameter(ParameterSetName = 'NewSession',Position = 0,Mandatory = $true)]
      [Parameter(ParameterSetName = 'ReuseSession',Position = 0,Mandatory = $true)]
      [string]$Name,
      [Parameter(ParameterSetName = 'NewSession',Position = 1,Mandatory = $false)]
      [Alias('Target')]
      [string]$ComputerName = ".",
      [Parameter(ParameterSetName = 'ReuseSession',Position = 2,Mandatory = $false)]
      [CimSession]$CimSession
    )
    $params = @{
      Name = $Name
    }
    if ($PSCmdlet.ParameterSetName -eq 'NewSession') { $params.CimSession = newCimSession -Target $ComputerName }
    if ($PSCmdlet.ParameterSetName -eq 'ReuseSession') { $params.CimSession = $CimSession }
  
    $obj = Get-HPBIOSSetting @params
    if ($obj) {
      getFormattedBiosSettingValue $obj
    }
  
  
  }

$resultofBHM = Get-HPBIOSSettingValue "Battery Health Manager"
# Write-Host $resultofBHM
[NXT]::WriteOutputString("BHM", $resultofBHM)
    
# SIG # Begin signature block
# MIIbmwYJKoZIhvcNAQcCoIIbjDCCG4gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNVWvZtCoQhSZBo9GGZwImApT
# VqygghYRMIIDBjCCAe6gAwIBAgIQWiA0ao8Fgq1MjKfm+ShLCjANBgkqhkiG9w0B
# AQsFADAbMRkwFwYDVQQDDBBBVEEgQXV0aGVudGljb2RlMB4XDTIyMTEwMTE1NTIy
# MloXDTIzMTEwMTE2MTIyMlowGzEZMBcGA1UEAwwQQVRBIEF1dGhlbnRpY29kZTCC
# ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALStUY/UzZYzUn95evAg+9Ac
# sl2XEa79vTB431iYs1b7edZNuFx5PQQovDXjF3NMJqPl6H34GkZMXMj5pCdau8eW
# V+1lINCee/8m3VJz+2Xfh/BzWFaWit5rDkJsdZg9gLNKmN9S0ih+jsGpzK1L8/mD
# arl8yYlpit8bhg8U5y0+4qj1hlU2cW8zWjnEZ7yZtO0kD1AkiqOU1ZagZk/hecsN
# 6vQEafyZDb8Oyp/Sb8KxUnnMKe/uqm9dEdvUtDmnWLKHTOmapmhS91ZhaJhjo9Ky
# scUD1BlpMPUcX2nFmhEg7SvRCZlmkS0PE8TUNUopD3EkITKhKXgjz/+wPP743P0C
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBTT7IAJ7JHON4OesvO8UA+YDmvNozANBgkqhkiG9w0BAQsFAAOCAQEA
# kkeJ52upbpPYVjL/ks/HrimwtxyzvtUKL1z5kdBo+xywVaiGJ6xMLogATT7pYILP
# rwax8ZoULA2+rPilEOPsTNWBI/3TGCh0lgMtATOOS/nK3+DZKoB8koWzblyAk71l
# 8tXBIUcfYBvD9+EJsvHmO0dFlYHYVF6A5DJIFHbF4IyR2AvqzcuMm0xgghgCKItV
# KddXrBBVdo8q5VCe5IJ8sySCiNcv9qAE+ZqTkZ5ntXootUVao7WZtuMf9FLU1awL
# uL1e/605CuoVIXVRxWmYi+ESFiYE5sgJMnnWpyo4SY49+nT72bfJh5gGaEDMZo9a
# s1TKxhfit5VN8Lw78xyMIjCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFow
# DQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIz
# NTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2je
# u+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bG
# l20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBE
# EC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/N
# rDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A
# 2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8
# IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfB
# aYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaa
# RBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZi
# fvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXe
# eqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g
# /KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1Ud
# IAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22
# Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih
# 9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYD
# E3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c
# 2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88n
# q2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5
# lDCCBq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAw
# YjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQ
# d3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290
# IEc0MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMC
# VVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBU
# cnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJ
# KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh
# 1tKD0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+Feo
# An39Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1
# decfBmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxnd
# X7RUCyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6
# Th+xtVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPj
# Q2OAe3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlREr
# WHRAKKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JM
# q++bPf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh
# 3pP+OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8j
# u2TjY+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnS
# DmuZDNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1Ud
# DgQWBBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# dwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy
# dC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9E
# aWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOC
# AgEAfVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp
# /GnBzx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40B
# IiXOlWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2d
# fNBwCnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibB
# t94q6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7
# T6NJuXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZA
# myEhQNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdB
# eHo46Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnK
# cPA3v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/
# pNHzV9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yY
# lvZVVCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggbAMIIEqKADAgEC
# AhAMTWlyS5T6PCpKPSkHgD1aMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1
# c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcNMjIwOTIx
# MDAwMDAwWhcNMzMxMTIxMjM1OTU5WjBGMQswCQYDVQQGEwJVUzERMA8GA1UEChMI
# RGlnaUNlcnQxJDAiBgNVBAMTG0RpZ2lDZXJ0IFRpbWVzdGFtcCAyMDIyIC0gMjCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAM/spSY6xqnya7uNwQ2a26Ho
# FIV0MxomrNAcVR4eNm28klUMYfSdCXc9FZYIL2tkpP0GgxbXkZI4HDEClvtysZc6
# Va8z7GGK6aYo25BjXL2JU+A6LYyHQq4mpOS7eHi5ehbhVsbAumRTuyoW51BIu4hp
# DIjG8b7gL307scpTjUCDHufLckkoHkyAHoVW54Xt8mG8qjoHffarbuVm3eJc9S/t
# jdRNlYRo44DLannR0hCRRinrPibytIzNTLlmyLuqUDgN5YyUXRlav/V7QG5vFqia
# nJVHhoV5PgxeZowaCiS+nKrSnLb3T254xCg/oxwPUAY3ugjZNaa1Htp4WB056PhM
# kRCWfk3h3cKtpX74LRsf7CtGGKMZ9jn39cFPcS6JAxGiS7uYv/pP5Hs27wZE5FX/
# NurlfDHn88JSxOYWe1p+pSVz28BqmSEtY+VZ9U0vkB8nt9KrFOU4ZodRCGv7U0M5
# 0GT6Vs/g9ArmFG1keLuY/ZTDcyHzL8IuINeBrNPxB9ThvdldS24xlCmL5kGkZZTA
# WOXlLimQprdhZPrZIGwYUWC6poEPCSVT8b876asHDmoHOWIZydaFfxPZjXnPYsXs
# 4Xu5zGcTB5rBeO3GiMiwbjJ5xwtZg43G7vUsfHuOy2SJ8bHEuOdTXl9V0n0ZKVkD
# Tvpd6kVzHIR+187i1Dp3AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFGKK3tBh/I8xFO2XC809KpQU31KcMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAFWqKhrzRvN4Vzcw/HXjT9aFI/H8+ZU5myXm93KKmMN31GT8Ffs2wklR
# LHiIY1UJRjkA/GnUypsp+6M/wMkAmxMdsJiJ3HjyzXyFzVOdr2LiYWajFCpFh0qY
# QitQ/Bu1nggwCfrkLdcJiXn5CeaIzn0buGqim8FTYAnoo7id160fHLjsmEHw9g6A
# ++T/350Qp+sAul9Kjxo6UrTqvwlJFTU2WZoPVNKyG39+XgmtdlSKdG3K0gVnK3br
# /5iyJpU4GYhEFOUKWaJr5yI+RCHSPxzAm+18SLLYkgyRTzxmlK9dAlPrnuKe5NMf
# hgFknADC6Vp0dQ094XmIvxwBl8kZI4DXNlpflhaxYwzGRkA7zl011Fk+Q5oYrsPJ
# y8P7mxNfarXH4PMFw1nfJ2Ir3kHJU7n/NBBn9iYymHv+XEKUgZSCnawKi8ZLFUrT
# mJBFYDOA4CPe+AOk9kVH5c64A0JH6EE2cXet/aLol3ROLtoeHYxayB6a1cLwxiKo
# T5u92ByaUcQvmvZfpyeXupYuhVfAYOd4Vn9q78KVmksRAsiCnMkaBXy6cbVOepls
# 9Oie1FqYyJ+/jbsYXEP10Cro4mLueATbvdH7WwqocH7wl4R44wgDXUcsY6glOJcB
# 0j862uXl9uab3H4szP8XTE0AotjWAQ64i+7m4HJViSwnGWH2dwGMMYIE9DCCBPAC
# AQEwLzAbMRkwFwYDVQQDDBBBVEEgQXV0aGVudGljb2RlAhBaIDRqjwWCrUyMp+b5
# KEsKMAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMCMGCSqGSIb3DQEJBDEWBBRg4ohf566c+C7cyQemaSFlA8sjeTANBgkqhkiG
# 9w0BAQEFAASCAQAqQbANcJzeLWygpl6gnoddQB2ougK6rAjAG8KRZl8L3+cDqVHt
# GbgQu22lhA8lNSEaB6jPnrjww+xdjIrx5hUp22vt/7ZsHcoDWvoikIcMgKB4qYPe
# doDqZhkp+WCjS8YtwiyURc5dA0UzlZV3FiLWxMHK9i6zltw7Hb5V2Gu7E5zhXDVT
# TQy1q/2xjM3f0z0ykxXM2wcrYEk870T4ag87kiR9TBUVs8H1bCQyiNBgTL7z4yze
# oAnWCdFnt0/qudjEX6Qz6qQZEytYuKWrwo1WAjLYfWkFgzhycJosAuxW2n9rcBe1
# ULMHyUguEl5HxbQ2ukG/ZC8ovyX8s2E2mXUkoYIDIDCCAxwGCSqGSIb3DQEJBjGC
# Aw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIy
# MTEwMTIxMDEzNFowLwYJKoZIhvcNAQkEMSIEIB90uS6w30layeifmdKrEyc3UyTu
# +HIRVxDrwnWkmNQPMA0GCSqGSIb3DQEBAQUABIICAEXdcjITUyW6GYQ0Ti7mZ9nV
# +qisOtBUuYrvvlMIoXwFVLS5wx+YWevf1kwMsvDvDToxm5juAXJacFwAF4goUP/2
# 33gYT0tlgnU5CTnqpN/Ga+ecDhuUKV6XM/iXgn+DLcEtI5pEcHz9jwavkF0NFoer
# Vby9unhxhzUXxa9VR0J/+a9JfBbP98j195KsBzRyB6giiMmlLO5qrdaFxvZAwyfC
# 4bL/jhVBp96NWVuxfBU99qKkMeTX/ned0lAd3J+awBztesiWnVuxMOULP8h4Lq25
# kN2iLTCtC1RUDuLSslPYV6akJFFtCqGxw6NoPzALeCSGZWD2o/50WUETEI0KIAU9
# Rkm+QMKt19NCT4JakKE1eIcGhWDFiKlbrbb3PX4oJ4+Z3fYBNujmXTBfUPar5nIa
# Zc9yNUX1wdkN7QaFhqeYH5R8Q8JmPivZYsEZ4I8Na5ldPrsR8BtEGBv0koDoVY5B
# ujE5qjTKiRKbIbIXcjN/JY2/jNX9INO3MSOS2M1BvBRTQprZlBFB00Gy6jpib3Uq
# eUQxkSfcQb6QRB6Jwnkrvj+ueIsyMihstDE6zEn80ToYkqk1P/xAAPOVsNBOARqG
# yMtN7+xVbt/o39QAM+kUQz7YB7bFJUCQIjoCVPlZfdZJ/gyjLnGVut6H6I3ftlht
# DS+qtZH2Y/GUsPIoMm66
# SIG # End signature block
