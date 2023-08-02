function Get-PowerPlan {
	<#
	.SYNOPSIS
		Returns Windows power plans.
	.DESCRIPTION
		Returns all Windows power plans or just the active power plan.
	.PARAMETER ID
		Optional GUID for a specific power plan (default is to return all power plans)
	.PARAMETER ComputerName
		Optional name of a remote computer. Default is local computer.
	.PARAMETER IsActive
		Optional. Return only the active power plan
	.EXAMPLE
		Get-PowerPlan
		Returns all power plans defined on the local computer
	.EXAMPLE
		Get-PowerPlan -IsActive
		Returns the current power plan for the local computer
	.EXAMPLE
		Get-PowerPlan -IsActive -ComputerName WS123
		Returns the current power plan for computer WS123
	.LINK
		https://github.com/Skatterbrainz/psPowerPlan/blob/master/docs/Get-PowerPlan.md
	#>
	[CmdletBinding()]
	param (
		[parameter()][string]$ID = "",
		[parameter()][string]$ComputerName = "",
		[parameter()][switch]$IsActive
	)
	if ([string]::IsNullOrWhiteSpace($ID)) {
		$params = @{
			Class = "Win32_PowerPlan"
			Namespace = "root\cimv2\power"
		}
		if (![string]::IsNullOrWhiteSpace($ComputerName)) {
			$params.Add("ComputerName", $ComputerName)
		}
		$plans = @(Get-WmiObject @params)
		if ($IsActive) {
			$plans = @($plans | Where-Object {$_.IsActive -eq $True})
		}
		foreach ($plan in $plans) {
			$id = $plan.InstanceID.Split('\')[1].Substring(1,36)
			[pscustomobject]@{
				Name = $plan.ElementName
				Description = $plan.Description
				Caption = $plan.Caption
				ID = $id
				IsActive = $plan.IsActive
			}
		}
	} else {
		POWERCFG -QUERY $($ID).Trim()
	}
}
function Set-PowerPlan {
	<#
	.SYNOPSIS
		Set Active Power Plan
	.DESCRIPTION
		Set Active Power Plan from a list of standard names
	.PARAMETER ID
		GUID of power plan to set active
	.PARAMETER Interactive
		If ID is not provided, and Interactive is requested, the available Power plans
		are displayed in a GridView to select one to set active.
	.EXAMPLE
		Set-PowerPlan -ID 381b4222-f694-41f0-9685-ff5bb260df2e
	.LINK
		https://github.com/Skatterbrainz/psPowerPlan/blob/master/docs/Set-PowerPlan.md
	#>
	[CmdletBinding()]
	param (
		[parameter()][string]$ID,
		[parameter()][switch]$Interactive
	)
	try {
		$plans = Get-PowerPlan
		$activeplan = $plans | Where-Object {$_.IsActive -eq $true}
		Write-Host "Active power plan is: $($activeplan.Name) - $($activeplan.ID)"
		if (![string]::IsNullOrWhiteSpace($ID)) {
			if ($ID -in ($plans.ID)) {
				if ($ID -eq $($plans | Where-Object {$_.IsActive -eq $True} | Select-Object -ExpandProperty ID)) {
					Write-Warning "*** $ID is already active"
				} else {
					POWERCFG /SETACTIVE $ID
					Write-Host "$ID is now active"
				}
			}
		} elseif ($Interactive) {
			$plan = $plans | Out-GridView -Title "Select Power Plan to set Active" -OutputMode Single
			if ($plan) {
				POWERCFG /SETACTIVE $plan.ID
				Write-Host "$($plan.ID) is now active"
			}
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

Set-PowerPlan -Interactive