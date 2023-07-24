$ReAgentXmlPath = 'C:\Windows\System32\Recovery\ReAgent.xml'

$ReAgentXml = @'
<?xml version='1.0' encoding='utf-8'?>

<WindowsRE version="2.0">
  <WinreBCD id="{00000000-0000-0000-0000-000000000000}"/>
  <WinreLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <ImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <PBRImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}" index="0"/>
  <PBRCustomImageLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}" index="0"/>
  <InstallState state="0"/>
  <OsInstallAvailable state="0"/>
  <CustomImageAvailable state="0"/>
  <IsAutoRepairOn state="0"/>
  <WinREStaged state="0"/>
  <OperationParam path=""/>
  <OperationPermanent state="0"/>
  <OsBuildVersion path=""/>
  <OemTool state="0"/>
  <IsServer state="0"/>
  <DownlevelWinreLocation path="" id="0" offset="0" guid="{00000000-0000-0000-0000-000000000000}"/>
  <IsWimBoot state="0"/>
  <NarratorScheduled state="0"/>
  <ScheduledOperation state="0"/>
</WindowsRE>
'@

$ReAgentXml | Out-File -FilePath $ReAgentXmlPath -Encoding UTF8 -Force