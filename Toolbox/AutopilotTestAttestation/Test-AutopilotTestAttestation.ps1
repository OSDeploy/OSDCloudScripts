<#PSScriptInfo
.VERSION 0.11
.GUID 715a6707-796c-445f-9e8a-8a0fffd778a5
.AUTHOR Rudy Ooms
.COMPANYNAME
.COPYRIGHT
.TAGS Windows, AutoPilot, Powershell
.LICENSEURI
.PROJECTURI https://www.github.com
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.RELEASENOTES
Version 0.1: Initial Release.
Version 0.2/4: Changed to WMI to fetch the error codes.
Version 0.5: Added some more checks and changed the AIK error code url
Version 0.6: removed the Exit's and added the Additional/ManufacturerCertificates certificate check
Version 0.7: Improved some texts and added some more explanation
Version 0.8: Removed the internet test and added a windows update check. Also changed the w32 time check
Version 0.9: Added the TPM version check
Version 0.10: Removed the tpmdiagnostics dependency and switched over to the tpmcoreprovisioning.dll file
Version 0.11: I was bored.. so I added a gif when your device is ready for attestation
Version 0.12: Excluded the "fake" 2022-04 update and added the oobeaadv10 check
.PRIVATEDATA
#>
<#
.DESCRIPTION
.SYNOPSIS
GUI to import Device to Autopilot. 
MIT LICENSE
Copyright (c) 2022 Rudy Ooms    
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:  
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.  
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
.DESCRIPTION
The goal of this script is to help with the troubleshooting of Attestation issues when enrolling your device with Autopilot for Pre-Provisioned deployments
.EXAMPLE
Blog post with examples and explanations @call4cloud.nl 
.LINK
Online version: https://call4cloud.nl/2022/08/the-last-tpm-attestation-script-from-your-lover/
#>
function Test-AutopilotAttestation {


############################################
# defining some functions		  #
############################################



function test-managemicrosoft {

$web = Invoke-WebRequest https://portal.manage.microsoft.com
$web.tostring() -split "[`r`n]" | select-string "Copyright (C) Microsoft Corporation. All rights reserved"
$webclient = new-object System.Net.WebClient 
$webclient.Headers.Add("user-agent", "PowerShell Script")
$webpage = "https://portal.manage.microsoft.com"
$output = ""
$output = $webclient.DownloadString($webpage)

if($output -like "*Copyright (C) Microsoft Corporation. All rights reserved*"){
	write-host "Great news as it looks like there are no OOBEAADV10 errors :) " -ForegroundColor green
}else{
	write-host "Great scott, this doesnt look good. It looks like there are some OOBEAADV10 errors going on " -ForegroundColor red
	write-host "Please visit https://call4cloud.nl/2022/07/oobeaadv10-return-of-the-502-error/ to read more about this error" -ForegroundColor red
	}
}


function test-connnectivity{

    Write-Host "Starting Connectivity test to Microsoft, Intel, Qualcomm and AMD" -ForegroundColor Yellow
    write-host "`n"
	
    test-managemicrosoft

    $TPM_ZTD = (Test-NetConnection ztd.dds.microsoft.com -Port 443).TcpTestSucceeded
    If ($TPM_ZTD -eq "True") {
        Write-Host -NoNewline -ForegroundColor Green "ZTD.DDS.Microsoft.Com - Success"
        Write-Host @ErrorIcon
    }
	Else {
        Write-Host -NoNewline -ForegroundColor Red "ZTD.DDS.Microsoft.com - Error"
        Write-Host @ErrorIcon
    }

    $TPM_Intel = (Test-NetConnection ekop.intel.com -Port 443).TcpTestSucceeded
    If($TPM_Intel -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "TPM_Intel - Success "
        Write-Host @ErrorIcon  
    } else {
        Write-Host -NoNewline -ForegroundColor Red "TPM_Intel - Error "
        Write-Host @ErrorIcon   
    }
    $TPM_Qualcomm = (Test-NetConnection ekcert.spserv.microsoft.com -Port 443).TcpTestSucceeded
    If($TPM_Qualcomm -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "TPM_Qualcomm - Success "
        Write-Host @ErrorIcon
    } else {
        Write-Host -NoNewline -ForegroundColor Red "TPM_Qualcomm - Error "
        Write-Host @ErrorIcon
    }
    $TPM_AMD = (Test-NetConnection ftpm.amd.com -Port 443).TcpTestSucceeded
    If($TPM_AMD -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "TPM_AMD - Success "
       Write-Host @ErrorIcon
    } else {
        Write-Host -NoNewline -ForegroundColor Red "TPM_AMD - Error "
     Write-Host @ErrorIcon
    }
    $TPM_Azure = (Test-NetConnection azure.net -Port 443).TcpTestSucceeded 
    If($TPM_Azure -eq "True"){
        Write-Host -NoNewline -ForegroundColor Green "Azure - Success "
      Write-Host @ErrorIcon
    } else {
        Write-Host -NoNewline -ForegroundColor Red "Azure - Error "
      Write-Host @ErrorIcon
    }
}


function test-time{
   Write-Host "Making sure the time service is running and configuring the time sync servers" -ForegroundColor Yellow
    If (((Get-Service W32Time).Status -ne "Running") -or ((Get-Service W32Time).Status -eq "Running")) {
    stop-service W32Time 
	cmd /c "w32tm /unregister" | out-null
    cmd /c "w32tm /register" | out-null
    start-service W32Time | out-null
    cmd /c "w32tm /resync"| out-null
    cmd /c "w32tm /config /update /manualpeerlist:0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org,0x8 /syncfromflags:MANUAL /reliable:yes" | out-null
    }
}

function get-hardwareinfo{ 
    # Apparaat Info
    $SerialNoRaw = wmic bios get serialnumber
    $SerialNo = $SerialNoRaw[2]
    
    $ManufacturerRaw = wmic computersystem get manufacturer
    $Manufacturer = $ManufacturerRaw[2]
    
    $ModelNoRaw = wmic computersystem get model
    $ModelNo = $ModelNoRaw[2]
    
    Write-Host "Computer Serialnumber: `t $SerialNo" -ForegroundColor Yellow
    Write-Host "Computer Supplier: `t $Manufacturer" -ForegroundColor Yellow
    Write-Host "Computer Model: `t $ModelNo" -ForegroundColor Yellow
    write-host "`n"
}


function test-windowslicense{

$WindowsProductKey =  (Get-WmiObject -query "select * from SoftwareLicensingService").OA3xOriginalProductKey
$WindowsProductType = (Get-WmiObject -query "select * from SoftwareLicensingService").OA3xOriginalProductKeyDescription

Write-Host "[BIOS] Windows Product Key: $WindowsProductKey" -ForegroundColor Yellow
Write-Host "[BIOS] Windows Product Type: $WindowsProductType" -ForegroundColor Yellow


If($WindowsProductType -like "*Professional*" -or $WindowsProductType -eq "Windows 10 Pro" -or $WindowsProductType -like "*Enterprise*"){
    Write-Host "BIOS Windows license is suited for MS365 enrollment" -ForegroundColor Green
}
else{
    Write-Host "BIOS Windows license is not suited for MS365 enrollment" -ForegroundColor red
    $WindowsProductType = get-computerinfo | select WindowsProductName 
    $WindowsProductType = $WindowsProductType.WindowsProductName
    
    Write-Host "[SOFTWARE] Windows Product Key: $WindowsProductKey" -ForegroundColor Yellow
    Write-Host "[SOFTWARE] Windows Product Type: $WindowsProductType" -ForegroundColor Yellow
    
    If($WindowsProductType -like "*Professional*" -or $WindowsProductType -eq "Windows 10 Pro" -or $WindowsProductType -like "*Enterprise*"){
        Write-Host "SOFTWARE Windows license is valid for MS365 enrollment" -ForegroundColor Green
    }
    else{
    Write-Host "SOFTWARE Windows license is not valid for MS365 Enrollment" -ForegroundColor red
    }
}
}


function test-requiredupdates{

[datetime]$dtToday = [datetime]::NOW
$strCurrentMonth = $dtToday.Month.ToString()
$strCurrentYear = $dtToday.Year.ToString()
[datetime]$dtMonth = $strCurrentMonth + '/1/' + $strCurrentYear

while ($dtMonth.DayofWeek -ne 'Tuesday') { 
      $dtMonth = $dtMonth.AddDays(1) 
}

$strPatchTuesday = $dtMonth.AddDays(7)
$intOffSet = 1

if ([datetime]::NOW -lt $strPatchTuesday -or [datetime]::NOW -ge $strPatchTuesday.AddDays($intOffSet)) {
    $objUpdateSession = New-Object -ComObject Microsoft.Update.Session
    $objUpdateSearcher = $objUpdateSession.CreateupdateSearcher()
    $arrAvailableUpdates = @($objUpdateSearcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0").Updates)
    $strAvailableCumulativeUpdates = $arrAvailableUpdates | Where-Object {(($_.title -like "*Windows 10*") -or ($_.title -like "*Windows 11*")) -and ($_.title -notlike "*.Net Framework*") -and ($_.title -notlike "*2022-04*")  }

    if ($strAvailableCumulativeUpdates -eq $null) {
       write-host "Nice work, the device is up to date!" -ForegroundColor green
       write-host "`n"
    }else {
        $missingupdate = $strAvailableCumulativeUpdates.Title
        write-host "`n"
        write-host "Device is not up to date because it's missing this update: $missingupdate. Please make sure the device is up to date before performing Autopilot Pre-Provisioning" -ForegroundColor red
	   	write-host "`n"
                 write-host "Do you want to check for updates? Yes or No?" -ForegroundColor Yellow
                $check4updates = read-host
                If(($check4updates -eq "Y") -or ($check4updates -eq "y") ){
                cmd /c "C:\Windows\System32\control.exe /name Microsoft.WindowsUpdate"
                }else{
                write-host "Skipping Windows Update." -ForegroundColor Green
                }

         }
}else {
    write-host "Device seems up to date"? -ForegroundColor green
}
}

function test-tpmversion{
Write-host "Checking if the device has a required TPM 2.0 version" -ForegroundColor Yellow
$TPMversion = Get-WmiObject -Namespace "root\cimv2\security\microsofttpm" -Query "Select SpecVersion from win32_tpm" | Select-Object specversion
if($TPMVersion.SpecVersion -like "*1.2*")
{
    Write-host "TPM Version is 1.2. Attestation is not going to work!!!!" -ForegroundColor red
}elseif($TPMVersion.SpecVersion -like "*1.15*")
{
    Write-host "TPM Version is 1.15. You are probably running this script on a VM aren't you? Attestation doesn't work on a VM!" -ForegroundColor red
}else 
{
    Write-host "TPM Version is 2.0" -ForegroundColor green
}
}


function test-firmwaretpm{
$IfxManufacturerIdInt = 0x49465800 # 'IFX'
		function IsInfineonFirmwareVersionAffected ($FirmwareVersion)
		{
			$FirmwareMajor = $FirmwareVersion[0]
			$FirmwareMinor = $FirmwareVersion[1]
			switch ($FirmwareMajor)
			{
				4 { return $FirmwareMinor -le 33 -or ($FirmwareMinor -ge 40 -and $FirmwareMinor -le 42) }
				5 { return $FirmwareMinor -le 61 }
				6 { return $FirmwareMinor -le 42 }
				7 { return $FirmwareMinor -le 61 }
				133 { return $FirmwareMinor -le 32 }
				default { return $False }
			}
		}
		function IsInfineonFirmwareVersionSusceptible ($FirmwareMajor)
		{
			switch ($FirmwareMajor)
			{
				4 { return $True }
				5 { return $True }
				6 { return $True }
				7 { return $True }
				133 { return $True }
				default { return $False }
			}
		}
		$Tpm = Get-Tpm
		$ManufacturerIdInt = $Tpm.ManufacturerId
		$FirmwareVersion = $Tpm.ManufacturerVersion -split "\."
		$FirmwareVersionAtLastProvision = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI" -Name "FirmwareVersionAtLastProvision" -ErrorAction SilentlyContinue).FirmwareVersionAtLastProvision
		if (!$Tpm)
		{
			Write-Host "No TPM found on this system, so the issue does not apply here."
		}
		else
		{
			if ($ManufacturerIdInt -ne $IfxManufacturerIdInt)
			{
				Write-Host "This non-Infineon TPM is not affected by the issue." -ForegroundColor green
			}
			else
			{
				if ($FirmwareVersion.Length -lt 2)
				{
					Write-Error "Could not get TPM firmware version from this TPM."
				}
				else
				{
					if (IsInfineonFirmwareVersionSusceptible($FirmwareVersion[0]))
					{
						if (IsInfineonFirmwareVersionAffected($FirmwareVersion))
						{
							Write-Host ("This Infineon firmware version {0}.{1} TPM is not safe. Please update your firmware." -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor red
						}
						else
						{
							Write-Host ("This Infineon firmware version {0}.{1} TPM is safe." -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green

							if (!$FirmwareVersionAtLastProvision)
							{
								Write-Host ("We cannot determine what the firmware version was when the TPM was last cleared. Please clear your TPM now that the firmware is safe.") -ForegroundColor red
							}
							elseif ($FirmwareVersion -ne $FirmwareVersionAtLastProvision)
							{
								Write-Host ("The firmware version when the TPM was last cleared was different from the current firmware version. Please clear your TPM now that the firmware is safe.") -ForegroundColor yellow
							}
						}
					}
					else
					{
						Write-Host ("This Infineon firmware version {0}.{1} TPM is safe." -f [int]$FirmwareVersion[0], [int]$FirmwareVersion[1]) -ForegroundColor green
					}
				}
			}
		}

}

############################################
# Making sure the script is run as admin  #
############################################

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$runasadmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($runasadmin -eq $false){
write-host "Script is not run as admin! Please rerun the script as admin" -ForegroundColor red
}
    	test-time
	test-connnectivity
       	get-hardwareinfo 
    	write-host "`n"
    	test-windowslicense
	write-host "`n"
	Write-Host "Checking if the device is up to date to make sure all TPM fixes are applied. Please have some patience or get yourself a membeer" -ForegroundColor yellow
	test-requiredupdates
	write-host "`n"
	test-tpmversion




# Test TPM Attestation #
$IntegrityServicesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices"
$WBCL = "WBCL"
$TaskStatesRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI\taskStates"
$EkCertificatePresent = "EkCertificatePresent"
$OOBERegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE"
$SetupDisplayedEula = "SetupDisplayedEula"

# downloading gif if attestation succeeds #

$path = "C:\temp"
if (!(Test-Path $path))
{
New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
$img = Invoke-WebRequest -Uri "https://call4cloud.nl/wp-content/uploads/2022/09/487ba55465e8cf5ff78ea5bf8cf06e4a.gif" -OutFile "$path\membeer.gif" -ErrorAction:Stop

Add-Type -AssemblyName System.Windows.Forms
$Form = New-Object System.Windows.Forms.Form
$Form.AutoSize = $true
$Form.StartPosition = "CenterScreen"

$Form.Text = "Membeer Player"
$Label = New-Object System.Windows.Forms.Label
$Label.Location = New-Object System.Drawing.Size(0,0)
$Label.AutoSize = $true
$Label.Font = New-Object System.Drawing.Font ("Comic Sans MS",20, [System.Drawing.Fontstyle]::Bold)
$Label.Text = "Attestation Working!"
$Form.Controls.Add($Label)

$gifBox = New-Object Windows.Forms.picturebox
$gifLink= (Get-Item -Path 'C:\temp\membeer.gif')
$img = [System.Drawing.Image]::fromfile($gifLink)
$gifBox.AutoSize = $true
$gifBox.Image = $img
$Form.Controls.Add($gifbox)


#testing ready for attestation with wmi instead of the get-tpm tool
write-host "Performing the first Ready For Attestation tests!" -ForegroundColor Yellow
write-host "`n"
$attestation = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'Isreadyinformation'
$attestationerror = $attestation.information
$status = $attestation.information

Write-Host "Determining if the TPM has vulnerable Firmware" -ForegroundColor Yellow 

test-firmwaretpm

    write-host "`n"
    if($attestationerror -eq "0")
    {
    write-host "TPM seems Ready For Attestation.. Let's Continue and run some more tests!" -ForegroundColor Green 
    }
    if($attestationerror -ne "0"){
    write-host "TPM is NOT Ready For Attestation.. Let's run some tests!" -ForegroundColor red 
    }
    if(!(Get-Tpm | Select-Object tpmowned).TpmOwned -eq $true)
    {
        Write-Host "Reason: TpmOwned is not owned!)" -ForegroundColor Red
    }
    if($attestationerror -eq "16777216")
    {
    write-host "The TPM has a Health Attestation related vulnerability" -ForegroundColor Green 
    } 
    If(!(Get-ItemProperty -Path $IntegrityServicesRegPath -Name $WBCL -ErrorAction Ignore))
    {
        Write-Host "Reason: Registervalue HKLM:\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCL does not exist! Measured boot logs are missing. Make sure your reboot your device!" -ForegroundColor Red
    }
    
    if($attestationerror -eq "262144"){
        write-host "Ek Certificate seems to be missing, let's try to fix it!" -ForegroundColor red
        Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue'
        sleep 5

        $taskinfo = Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\TPM\Tpm-Maintenance" -ErrorAction Ignore
        $tasklastruntime = $taskinfo.LastTaskResult  

    If($tasklastruntime -ne 0)
    {
    Write-Host "Reason: TPM-Maintenance Task could not be run! Checking and Configuring the EULA Key!" -ForegroundColor Red
    }
  
    If((!(Get-ItemProperty -Path $OOBERegPath -Name $SetupDisplayedEula -ErrorAction Ignore)) -or ((Get-ItemProperty -Path $OOBERegPath -Name $SetupDisplayedEula -ErrorAction Ignore).SetupDisplayedEula -ne 1)) 
    {
        Write-Host "Reason: Registervalue HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE\SetupDisplayedEula does not exist! EULA is not accepted!" -ForegroundColor Red
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\OOBE\' -Name  'SetupDisplayedEula' -Value '1' -PropertyType 'DWORD' –Force| Out-null
        Write-Host "SetupDisplayedEula registry key configured, rerunning the TPM-Maintanence Task" -ForegroundColor Yellow
        Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue'  
    }
    sleep 5
    $taskinfo = Get-ScheduledTaskInfo -TaskName "\Microsoft\Windows\TPM\Tpm-Maintenance" -ErrorAction Ignore
    $tasklastruntime = $taskinfo.LastTaskResult  
   
    If($tasklastruntime -ne 0)
    {
    Write-Host "TPM-Maintenance task could not be run succesfully despite the EULA key being set! Exiting now!" -ForegroundColor Red
    }

    If($tasklastruntime -eq 0){
    Write-Host "EULA Key is set and TPM-Maintenance Task has been run without issues" -ForegroundColor Green
    Write-Host "Please note, this doesn't mean the TPM-Maintenance task did its job! Let's test it again" -ForegroundColor yellow
    write-host "`n"
    }

    }if(!(test-path -path HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\*))
    {
        Write-Host "Reason:EKCert seems still to be missing in HKLM:\SYSTEM\CurrentControlSet\Services\Tpm\WMI\Endorsement\EKCertStore\Certificates\ - Launching TPM-Maintenance Task again!" -ForegroundColor Red
        Start-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -TaskName "Tpm-Maintenance" -erroraction 'silentlycontinue' 
        sleep 5
        write-host "`n"
        Write-Host "Going hardcore! Trying to install that damn EkCert on our own!!" -ForegroundColor yellow


        rundll32 tpmcoreprovisioning.dll,TpmPrepForNgc
        rundll32 tpmcoreprovisioning.dll,TpmProvision
        rundll32 tpmcoreprovisioning.dll,TpmCertInstallNvEkCerts
        rundll32 tpmcoreprovisioning.dll,TpmCertGetEkCertFromWeb
        rundll32 tpmcoreprovisioning.dll,TpmRetrieveEkCertOrReschedule
        sleep 5
        rundll32 tpmcoreprovisioning.dll,TpmVerifyDeviceHealth
        rundll32 tpmcoreprovisioning.dll,TpmRetrieveHealthCertOrReschedule
        sleep 5
        rundll32 tpmcoreprovisioning.dll,TpmCertGetWindowsAik
        rundll32 tpmcoreprovisioning.dll,TpmCheckCreateWindowsAIK
        rundll32 tpmcoreprovisioning.dll,TpmEnrollWindowsAikCertificate 


    }
    $endorsementkey = get-tpmendorsementkeyinfo   
    if($endorsementkey.IsPresent -ne $true)
    {
    Write-Host "Endorsementkey still not present!!" -ForegroundColor Red
    }else{
        Write-Host "Endorsementkey reporting for duty!" -ForegroundColor green
        Write-Host "Checking if the Endorsementkey has its required certificates attached" -ForegroundColor yellow
         
        $manufacturercerts = (TpmEndorsementKeyInfo).ManufacturerCertificates 
        $additionalcerts = (Get-TpmEndorsementKeyInfo).AdditionalCertificates

        if(((!$additionalcerts) -and (!$manufacturercerts))){
        write-host "`n"
        write-host "This is definitely not good! Additional and/or ManufacturerCerts are missing!" -ForegroundColor Red

        }else{
        write-host "We have found one of the required certificates" -ForegroundColor green
        $additionalcerts
        $manufacturercerts
        write-host "`n"
        }
    }          

    
#geting AIK Test CertEnroll error
$attestation = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'Isreadyinformation'
$attestationerror = $attestation.information


if($attestationerror -eq "0")
    {
   write-host "Retrieving AIK Certificate....." -ForegroundColor Green

$errorcert = 1
    for($num = 1 ; $errorcert -ne -1 ; $num++)
      {
        Write-Host "Fetching test-AIK cert - attempt $num"
        $certcmd = (cmd.exe /c "certreq -q -enrollaik -config """)

       
        $startcert  = [array]::indexof($certcmd,"-----BEGIN CERTIFICATE-----")
        $endcert    = [array]::indexof($certcmd,"-----END CERTIFICATE-----")
        $errorcert  = [array]::indexof($certcmd,'{"Message":"Failed to parse SCEP request."}')

            Write-Host "Checking the Output to determine if the AIK CA Url is valid!" -ForegroundColor yellow

            $Cacapserror = $CERTCMD -like "*GetCACaps: Not Found*"
            if ($CaCapserror) 
            {
            Write-Host "AIK CA Url is not valid" -ForegroundColor Red
            }else{
            Write-Host "AIK CA Url seems valid" -ForegroundColor Green
            }

       
       $certlength = $endcert - $startcert
        If($certlength -gt 1){
            write-host "Found Test AIK Certificate" -ForegroundColor Green
            $cert = $certcmd[$startcert..$endcert]
            write-host "`n"
            write-host $cert -ForegroundColor DarkGreen
            write-host "`n"
            write-host "AIK Test AIK Enrollment succeeded" -ForegroundColor Green
      }
        else{
            
            write-host "AIK TEST Certificate could not be retrieved" -ForegroundColor Red
            if($num -eq 10)
        {
                write-host "Retried 10 times, killing process" -ForegroundColor Red
                  }
        }
    }

#fetching AIkCertEnrollError
Write-Host "Running another test, to determine if the TPM is capable for key attestation... just for fun!!" -ForegroundColor Yellow

$attestationcapable = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftTpm' -ClassName 'Win32_TPM' | Invoke-CimMethod -MethodName 'IsKeyAttestationCapable'
$attestationcapable = $attestationcapable.testresult

If ($attestationcapable -ne 0){
 Write-Host "Reason: TPM doesn't seems capable for Attestation!" -ForegroundColor Red
 tpmtool getdeviceinformation 
  }else{
 Write-Host "We can almost start celebrating! Because the TPM is capable for attestation! "-ForegroundColor green
 }
   

Write-Host "Launching the real AikCertEnroll task!" -ForegroundColor Yellow
Start-ScheduledTask -TaskPath "\Microsoft\Windows\CertificateServicesClient\" -TaskName "AikCertEnrollTask"
sleep 5

$AIKError = "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Ngc\AIKCertEnroll\"
If ((Get-ItemProperty -Path $AIKError -Name "ErrorCode" -ErrorAction Ignore).errorcode -ne 0){
 Write-Host "Reason: AIK Cert Enroll Failed!" -ForegroundColor Red
 tpmtool getdeviceinformation
 }else{
 write-host "`n"
 Write-Host "AIK Cert Enroll Task Succeeded, Looks like the device is 100% Ready for Attestation! You can start the Autopilot Pre-Provioning!"-ForegroundColor green
 $Form.ShowDialog()
 }
   
   
}else{
    write-host "`n"
    write-host "TPM is still NOT suited for Autopilot Pre-Provisioning,  please re-run the test again" -ForegroundColor RED
     
   }
   
}