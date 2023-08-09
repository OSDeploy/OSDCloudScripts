# https://h20195.www2.hp.com/v2/GetDocument.aspx?docname=4AA7-8536ENW

$Namespace = 'root\HP\InstrumentedBIOS'
$Class = 'HP_BIOSSetting'
$ClassInterface = 'HP_BIOSSettingInterface'
$Name = 'Battery Health Manager'

Get-WmiObject -Namespace $Namespace -Class $Class -Filter "name='$Name'" -ErrorAction Stop