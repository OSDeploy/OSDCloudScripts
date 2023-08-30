$TaskName = 'User Scheduled Restart Tonight'
$TaskPath = 'ScheduledAction'
$Description = @"
Version 1.0.0 
Restart the computer today at 1:45pm
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
    #DeleteExpiredTaskAfter = ''
    DontStopIfGoingOnBatteries = $true
    ExecutionTimeLimit = (New-TimeSpan -Minutes 10)
    MultipleInstances = 'IgnoreNew'
    Priority = 0
    RestartCount = 0
    #StartWhenAvailable = $false
    WakeToRun = $true
}
$Trigger = @{
    Once = $true
    At = (Get-Date 13:45)
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