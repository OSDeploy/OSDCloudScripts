$Namespace = 'root\HP\InstrumentedBIOS'
$Class = 'HP_BIOSSetting'

Get-WmiObject -Namespace $Namespace -Class $Class | Where-Object {$_.IsReadOnly -eq 0} | Select-Object Path, Name, CurrentValue, IsReadOnly | Sort-Object Path, Name