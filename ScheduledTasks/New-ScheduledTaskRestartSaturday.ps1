$TaskName = 'User Scheduled Restart Saturday'
$TaskPath = 'ScheduledAction'
$Description = @"
Version 1.0.0 
Restart the computer Saturday at 10:00pm
"@

$Action = @{
    Execute = 'shutdown.exe'
    Argument = '/r /d p:4:1'
}
$Principal = @{
    UserId = $env:USERNAME
}
$Settings = @{
    AllowStartIfOnBatteries = $true
    Compatibility = 'Win8'
    MultipleInstances = 'Parallel'
    ExecutionTimeLimit = (New-TimeSpan -Minutes 60)
}

$Trigger = @{
    Once = $true
    At = (@(@(0..7) | % {$(Get-Date "22:00").AddDays($_)} | ? {($_ -gt $(Get-Date)) -and ($_.DayOfWeek -ieq "Saturday")})[0])
}
$ScheduledTask = @{
    Action = New-ScheduledTaskAction @Action
    Principal = New-ScheduledTaskPrincipal @Principal
    Settings = New-ScheduledTaskSettingsSet @Settings
    Trigger = New-ScheduledTaskTrigger @Trigger
    Description = $Description
}

New-ScheduledTask @ScheduledTask | Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Force

$Scheduler = New-Object -ComObject "Schedule.Service"
$Scheduler.Connect()
$GetTask = $Scheduler.GetFolder($TaskPath).GetTask($TaskName)
$GetSecurityDescriptor = $GetTask.GetSecurityDescriptor(0xF)
if ($GetSecurityDescriptor -notmatch 'A;;0x1200a9;;;AU') {
    $GetSecurityDescriptor = $GetSecurityDescriptor + '(A;;GRGX;;;AU)'
    $GetTask.SetSecurityDescriptor($GetSecurityDescriptor, 0)
}