<in OOBE, use SHIFT+F10 to get to the command window>
mkdir C:\data\test\bin
copy TraceLogging.wprp C:\data\test\bin /dys

wpr.exe -start c:\data\test\bin\TraceLogging.wprp

<check WPR recording is started successfully>
wpr.exe -status

< repro, eg enrollment or sync (Settings->Accounts->Work or School->click the account name->Info->Sync button) - perhaps even twice, and wait several minutes  >

wpr.exe -stop c:\data\test\bin\results.etl
<sharing the file results.etl>

<if device could reboot during trace collecting>
wpr.exe -start c:\data\test\bin\TraceLogging.wprp -filemode -recordtempto c:\data\test\bin
<the etl file will be stored in the specified folder after reboot>
