Add-Type -Path $env:NEXTHINK\RemoteActions\nxtremoteactions.dll

<#
.SYNOPSIS
Obtains the battery health manager setting using HP Client Management Library functions. HP Battery Health Manager is a BIOS-level setting available in most HP business notebooks. 
It is designed to help optimize battery life by mitigating the exposure of the notebook battery to key factors, such as high state-of-charge, that can accelerate battery swelling and chemical aging over time.


.DESCRIPTION
Returns the battery health manager setting enabled on the laptop: Let HP Maange My Battery Health or Maximize My Battery Health.

The Let HP Manage My Battery:
Dynamically changes how the system charges the battery based upon usage conditions and temperature over time.

Maximize My Battery Health:
Limits the maximum state-of-charge on the notebook battery to 80%, which has been proven to optimize battery health and helps mitigate battery swelling due to high state-of-charge.

.FUNCTIONALITY
On-demand

.OUTPUTS
ID BatteryHealthManager   

.RESTRICTIONS
BIOS update 01.17.01 changes the default setting in HP Battery Health Manager to the Maximize My Battery Health setting on select older HP business notebooks.

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
  
  function getBiosSettingInterface {
    [CmdletBinding(DefaultParameterSetName = 'nNwSession')]
    param(
      [Parameter(ParameterSetName = 'NewSession',Position = 0,Mandatory = $false)]
      [string]$Target = ".",
      [Parameter(ParameterSetName = 'ReuseSession',Position = 1,Mandatory = $true)]
      [CimSession]$CimSession
    )
    $defaultAction = $ErrorActionPreference
    $ns = getNamespace
    $ErrorActionPreference = "Stop";
  
    try {
      Write-Verbose "Getting BIOS interface from '$target' for namespace '$ns'"
      $params = @{
        Namespace = $ns
        Class = "HPBIOS_BIOSSettingInterface"
      }
  
      if ($CimSession) {
        $params.Add("CimSession",$CimSession)
      }
  
      if ($Target -and ($target -ne ".") -and -not $CimSession) {
        $params.Add("ComputerName",$Target)
      }
  
  
      $result = Get-CimInstance @params -ErrorAction stop
      if (-not $result) { throw [System.EntryPointNotFoundException]"Setting interface not found" }
    }
    catch {
      Write-Error "Method failed: $($_.Exception.Message)" -ErrorAction stop
    }
    finally {
      $ErrorActionPreference = $defaultAction
    }
    $result
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

function Set-HPPrivateBIOSSetting {
    [CmdletBinding()]
    param(
      $Setting,
      [string]$ComputerName = ".",
      [CimSession]$CimSession,
      [switch]$SkipPrecheck,
      [AllowEmptyString()]
      [string]$Password,
      $ErrorHandling,
      [Parameter(Mandatory = $false)]
      [ref]$actualSetFailCounter
    )
  
    $localCounterForSet = 0
  
    if ($CimSession -eq $null) {
      $CimSession = newCimSession -Target $ComputerName
    }
  
    $Name = $Setting.Name
    $Value = $Setting.Value
    if ($Setting.AuthString -and (Get-HPPrivateUseAuthString -SettingName $Name) -eq $true) {
      $authorization = $Setting.AuthString
      Write-Verbose "Using authorization string"
    }
    else {
      $authorization = "<utf-16/>" + $Password
      Write-Verbose "Using BIOS Setup password"
    }
  
    if ($SkipPrecheck.IsPresent) {
      Write-Verbose "Skipping pre-check"
  
      if ($Name -eq "Setup Password" -or $Name -eq "Power-On Password") {
        $type = 'HPBIOS_BIOSPassword'
      }
      else {
        $type = 'HPBIOS_Setting'
      }
    }
    else {
    }
  
    $c = getBiosSettingInterface -CimSession $CimSession
    switch ($type) {
      { $_ -eq 'HPBIOS_BIOSPassword' } {
        Write-Verbose "Setting Password setting '$Name' on '$ComputerName'"
        $Arguments = @{
          Name = $Name
          Value = "<utf-16/>" + [string]$Value
          Password = $authorization
        }
        $r = Invoke-CimMethod -InputObject $c -MethodName SetBiosSetting -Arguments $Arguments
      }
  
      default {
        Write-Verbose "Setting HP BIOS Setting '$Name' to value '$Value' on '$ComputerName'"
        $Arguments = @{
          Name = $Name
          Value = [string]$Value
          Password = $authorization;
        }
        $r = Invoke-CimMethod -InputObject $c -MethodName SetBiosSetting -Arguments $Arguments
      }
    }
  
    if ($r.Return -eq 0) {
      $message = "HP BIOS Setting $Name successfully set"
      if ($Name -ne "Setup Password" -and $Name -ne "Power-On Password") {
        $message += " to $Value"
      }
      Write-Host -ForegroundColor Green $message
    }
    if ($r.Return -ne 0) {
  
      $localCounterForSet++
  
      if ($r.Return -eq 5) {
        Write-Host -ForegroundColor Magenta "Operation failed. Please make sure that you are passing a valid value."
        Write-Host -ForegroundColor Magenta "Some variable names or values may be case sensitive."
      }
      $Err = "$(biosErrorCodesToString($r.Return))"
      if ($ErrorHandling -eq 1) {
        Write-Host -ForegroundColor Red "$($setting.Name) failed to set due to $Err"
        $actualSetFailCounter.Value = $localCounterForSet
      }
      throw $Err
    }
  }

  function biosErrorCodesToString ($code) {
    switch ($code) {
      0 { return "OK" }
      1 { return "Not Supported" }
      2 { return "Unspecified error" }
      3 { return "Operation timed out" }
      4 { return "Operation failed or setting name is invalid" }
      5 { return "Invalid parameter" }
      6 { return "Access denied or incorrect password" }
      7 { return "Bios user already exists" }
      8 { return "Bios user not present" }
      9 { return "Bios user name too long" }
      10 { return "Password policy not met" }
      11 { return "Invalid keyboard layout" }
      12 { return "Too many users" }
      32768 { return "Security or password policy not met" }
      default { return "Unknown error: $code" }
    }
  }
  
  function Get-HPPrivateUseAuthString {
    [CmdletBinding()]
    param(
      [string]$SettingName
    )
  
    if ((Get-HPPrivateIsSureAdminEnabled) -eq $true -or $SettingName -eq "Enhanced BIOS Authentication Mode") {
      return $true
    }
  
    return $false
  }
  
#>
  function Set-HPBIOSSettingValue {
    [CmdletBinding(DefaultParameterSetName = 'NewSession',HelpUri = "https://developers.hp.com/hp-client-management/doc/Set-HPBIOSSettingValue")]
    param(
      [Parameter(ParameterSetName = "NewSession",Position = 0,Mandatory = $false)]
      [Parameter(ParameterSetName = "ReuseSession",Position = 0,Mandatory = $false)]
      [AllowEmptyString()]
      [string]$Password,
  
      [Parameter(ParameterSetName = "NewSession",Position = 1,Mandatory = $false)]
      [Parameter(ParameterSetName = "ReuseSession",Position = 1,Mandatory = $false)]
      [string]$Name,
  
      [Parameter(ParameterSetName = "NewSession",Position = 2,Mandatory = $true)]
      [Parameter(ParameterSetName = "ReuseSession",Position = 2,Mandatory = $true)]
      [AllowEmptyString()]
      [string]$Value,
  
      [Parameter(ParameterSetName = "NewSession",Position = 3,Mandatory = $false)]
      [Parameter(ParameterSetName = "ReuseSession",Position = 3,Mandatory = $false)]
      [switch]$SkipPrecheck,
  
      [Parameter(ParameterSetName = 'NewSession',Position = 4,Mandatory = $false)]
      [Alias('Target')]
      $ComputerName = ".",
  
      [Parameter(ParameterSetName = 'ReuseSession',Position = 4,Mandatory = $true)]
      [CimSession]$CimSession
    )
  
  
    $params = @{
      Setting = $setting
      Password = $Password
      CimSession = $CimSession
      ComputerName = $ComputerName
      SkipPrecheck = $SkipPrecheck
    }
    Set-HPPrivateBIOSSetting @params
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

Set-HPBIOSSettingValue -Name "Battery Health Manager" -Value "Maximize My Battery Health"
# $resultofBHM = Get-HPBIOSSettingValue "Battery Health Manager" 

# Write-Host $resultofBHM
# [NXT]::WriteOutputString("BHM", $resultofBHM)
    
# SIG # Begin signature block
# MIIbmwYJKoZIhvcNAQcCoIIbjDCCG4gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxolUtUXGx8TKfRmFgZmO0HMc
# o+ugghYRMIIDBjCCAe6gAwIBAgIQWiA0ao8Fgq1MjKfm+ShLCjANBgkqhkiG9w0B
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
# AgEVMCMGCSqGSIb3DQEJBDEWBBTisaBq/oxcrRvcQSO5YrBozdH5bjANBgkqhkiG
# 9w0BAQEFAASCAQCGdBsS6+AuHIJkPID8dRZW3M3Djyown/KKgSnKlnJMhPARitBp
# IoqQww9j3jbJ3UywyjheqgyftJg0zgzfNeGPEWJX2FGrEk5DaGoUupGHAMpEhXlG
# TFEPATEwIAR85ylc1LH51derAnjZC7sByYjIrjdYvFqtzTKOElL0vFQT1VNfDe58
# c1v3mtCeIqaxJTws8e7ToalHa3c49gs2vA/lWjK8mVyGHi1ITzI2vO19zhftkJGX
# h2D6m863k2e80WYW/HASkPzOIkNSeawLK7S/CbwriSkLeC8idIPsUPB/vY27xV3l
# wgoH6b71uVK9PXkEQDW82BQhqppecxp7yf3DoYIDIDCCAxwGCSqGSIb3DQEJBjGC
# Aw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQQIQDE1pckuU+jwqSj0pB4A9WjANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIy
# MTEwMjE0MjgxMFowLwYJKoZIhvcNAQkEMSIEIA/Gf9i9Ekw9ZSeLfj4LJNmvNRep
# d0JHNYK6cOZQM4gWMA0GCSqGSIb3DQEBAQUABIICADTur5dcBlYWagcY7C+xXC7W
# KHesIj542nmvB2qT8KOwZY3UKd1TV+WrP9MghBpui+MQGm++JHhZrFH6jYpWfu76
# QKgjZ67wNjvTpQs37shRFhiUpeDzPc9xtNj2yDMUXuzZ3oNSduO8+JSZB5gj/ndQ
# ruj8ycuizEfyuY5AbQhhhbis1FLIScwuSCydGwfcM2kfBn3GRfpX3AojEd+fV4xe
# G9JVDpRtSnfxN9k/GVTPL3Egh5up3RBYHZdQl7ik270anOi2FCKrlgiVo+p90CFH
# JBt/gHkQp/2DAXY3cKJX8C45RyFhEf7tyGwKHHkVYIQVetQQUV4rPOee7nDLxisi
# tmGwaOOcy/vJ6RLLzRtkSuP4vu3N9yPVMLIIQ63B7gjRorbZ1esQb5qU2ezn+CAY
# sPsS+Hzxpblweu8K2PIEM9A49szzwnVvdgTltCcGA2bNyClLhOxb6RSAn/wXoAig
# auaWkDPMSwGWQqg64Ms9/3O9DO+UtMJduHP/z2NS0pycMOqCDdK+bnhWCyA2IHxX
# G8S1NGATvsomJKnzxICECmWe85o4/skYhjIWyMZJIFQOfknDKEsL/yvoyI7SQib/
# Gdw0ntRk2In+0F6ClPICafw6O6KxKwNsoiGAmydkzr9eUEVPR7+67ceVrP1m5vW8
# FMOzaD8t3oNnFjO2LB3P
# SIG # End signature block
