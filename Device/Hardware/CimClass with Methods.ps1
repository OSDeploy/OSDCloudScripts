Get-CimClass -ClassName * | Where-Object {$_.CimClassMethods} | Select-Object CimClassName, CimClassMethods | Sort-Object CimClassName

<#
CimClassName                            CimClassMethods
------------                            ---------------
__SystemSecurity                        {GetSD, GetSecurityDescriptor, Get9XUserList, SetSD…}
CIM_Action                              {Invoke}
CIM_AggregatePExtent                    {SetPowerState, Reset}
CIM_AggregatePSExtent                   {SetPowerState, Reset}
CIM_AlarmDevice                         {SetPowerState, Reset, SetUrgency}
CIM_Battery                             {SetPowerState, Reset}
CIM_BinarySensor                        {SetPowerState, Reset}
CIM_BootService                         {StartService, StopService}
CIM_CacheMemory                         {SetPowerState, Reset}
CIM_Card                                {IsCompatible}
CIM_CDROMDrive                          {SetPowerState, Reset}
CIM_Chassis                             {IsCompatible}
CIM_Check                               {Invoke}
CIM_ClusteringService                   {StartService, StopService, AddNode, EvictNode}
CIM_Controller                          {SetPowerState, Reset}
CIM_CoolingDevice                       {SetPowerState, Reset}
CIM_CopyFileAction                      {Invoke}
CIM_CreateDirectoryAction               {Invoke}
CIM_CurrentSensor                       {SetPowerState, Reset}
CIM_DataFile                            {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
CIM_DesktopMonitor                      {SetPowerState, Reset}
CIM_DeviceErrorCounts                   {ResetCounter}
CIM_DeviceFile                          {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
CIM_Directory                           {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
CIM_DirectoryAction                     {Invoke}
CIM_DirectorySpecification              {Invoke}
CIM_DiscreteSensor                      {SetPowerState, Reset}
CIM_DiskDrive                           {SetPowerState, Reset}
CIM_DisketteDrive                       {SetPowerState, Reset}
CIM_DiskPartition                       {SetPowerState, Reset}
CIM_DiskSpaceCheck                      {Invoke}
CIM_Display                             {SetPowerState, Reset}
CIM_ExecuteProgram                      {Invoke}
CIM_Fan                                 {SetPowerState, Reset, SetSpeed}
CIM_FileAction                          {Invoke}
CIM_FileSpecification                   {Invoke}
CIM_FlatPanel                           {SetPowerState, Reset}
CIM_HeatPipe                            {SetPowerState, Reset}
CIM_InfraredController                  {SetPowerState, Reset}
CIM_Keyboard                            {SetPowerState, Reset}
CIM_LogicalDevice                       {SetPowerState, Reset}
CIM_LogicalDisk                         {SetPowerState, Reset}
CIM_LogicalFile                         {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
CIM_MagnetoOpticalDrive                 {SetPowerState, Reset}
CIM_ManagementController                {SetPowerState, Reset}
CIM_MediaAccessDevice                   {SetPowerState, Reset}
CIM_Memory                              {SetPowerState, Reset}
CIM_MemoryCheck                         {Invoke}
CIM_ModifySettingAction                 {Invoke}
CIM_MultiStateSensor                    {SetPowerState, Reset}
CIM_NetworkAdapter                      {SetPowerState, Reset}
CIM_NonVolatileStorage                  {SetPowerState, Reset}
CIM_NumericSensor                       {SetPowerState, Reset}
CIM_OperatingSystem                     {Reboot, Shutdown}
CIM_OSVersionCheck                      {Invoke}
CIM_ParallelController                  {SetPowerState, Reset}
CIM_PCIController                       {SetPowerState, Reset}
CIM_PCMCIAController                    {SetPowerState, Reset}
CIM_PCVideoController                   {SetPowerState, Reset}
CIM_PhysicalExtent                      {SetPowerState, Reset}
CIM_PhysicalFrame                       {IsCompatible}
CIM_PhysicalPackage                     {IsCompatible}
CIM_PointingDevice                      {SetPowerState, Reset}
CIM_PotsModem                           {SetPowerState, Reset}
CIM_PowerSupply                         {SetPowerState, Reset}
CIM_Printer                             {SetPowerState, Reset}
CIM_Processor                           {SetPowerState, Reset}
CIM_ProtectedSpaceExtent                {SetPowerState, Reset}
CIM_Rack                                {IsCompatible}
CIM_RebootAction                        {Invoke}
CIM_Refrigeration                       {SetPowerState, Reset}
CIM_RemoveDirectoryAction               {Invoke}
CIM_RemoveFileAction                    {Invoke}
CIM_Scanner                             {SetPowerState, Reset}
CIM_SCSIController                      {SetPowerState, Reset}
CIM_Sensor                              {SetPowerState, Reset}
CIM_SerialController                    {SetPowerState, Reset}
CIM_Service                             {StartService, StopService}
CIM_SettingCheck                        {Invoke}
CIM_SoftwareElementVersionCheck         {Invoke}
CIM_StorageExtent                       {SetPowerState, Reset}
CIM_StorageVolume                       {SetPowerState, Reset}
CIM_SwapSpaceCheck                      {Invoke}
CIM_Tachometer                          {SetPowerState, Reset}
CIM_TapeDrive                           {SetPowerState, Reset}
CIM_TemperatureSensor                   {SetPowerState, Reset}
CIM_UninterruptiblePowerSupply          {SetPowerState, Reset}
CIM_UnitaryComputerSystem               {SetPowerState}
CIM_USBController                       {SetPowerState, Reset}
CIM_USBDevice                           {SetPowerState, Reset, GetDescriptor}
CIM_USBHub                              {SetPowerState, Reset, GetDescriptor}
CIM_UserDevice                          {SetPowerState, Reset}
CIM_VersionCompatibilityCheck           {Invoke}
CIM_VideoController                     {SetPowerState, Reset}
CIM_VolatileStorage                     {SetPowerState, Reset}
CIM_VoltageSensor                       {SetPowerState, Reset}
CIM_VolumeSet                           {SetPowerState, Reset}
CIM_WORMDrive                           {SetPowerState, Reset}
Msft_Providers                          {Suspend, Resume, UnLoad, Load}
SoftwareLicensingProduct                {UninstallProductKey, Activate, DepositOfflineConfirmationId, GetPolicyInformationDWord…}
SoftwareLicensingService                {InstallProductKey, InstallLicense, InstallLicensePackage, SetKeyManagementServiceMachine…}
SoftwareLicensingTokenActivationLicense {Uninstall}
StdRegProv                              {CreateKey, DeleteKey, EnumKey, EnumValues…}
Win32_1394Controller                    {SetPowerState, Reset}
Win32_ApplicationService                {StartService, StopService}
Win32_BaseBoard                         {IsCompatible}
Win32_BaseService                       {StartService, StopService, PauseService, ResumeService…}
Win32_Battery                           {SetPowerState, Reset}
Win32_BindImageAction                   {Invoke}
Win32_Bus                               {SetPowerState, Reset}
Win32_CacheMemory                       {SetPowerState, Reset}
Win32_CDROMDrive                        {SetPowerState, Reset}
Win32_ClassInfoAction                   {Invoke}
Win32_ClusterShare                      {Create, SetShareInfo, GetAccessMask, Delete}
Win32_CodecFile                         {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
Win32_ComputerSystem                    {SetPowerState, Rename, JoinDomainOrWorkgroup, UnjoinDomainOrWorkgroup}
Win32_Condition                         {Invoke}
Win32_CreateFolderAction                {Invoke}
Win32_CurrentProbe                      {SetPowerState, Reset}
Win32_DCOMApplicationSetting            {GetLaunchSecurityDescriptor, SetLaunchSecurityDescriptor, GetAccessSecurityDescriptor, SetAccessSecurityDescriptor…}        
Win32_DesktopMonitor                    {SetPowerState, Reset}
Win32_DfsNode                           {Create}
Win32_Directory                         {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
Win32_DirectorySpecification            {Invoke}
Win32_DiskDrive                         {SetPowerState, Reset}
Win32_DiskPartition                     {SetPowerState, Reset}
Win32_DuplicateFileAction               {Invoke}
Win32_EnvironmentSpecification          {Invoke}
Win32_ExtensionInfoAction               {Invoke}
Win32_Fan                               {SetPowerState, Reset, SetSpeed}
Win32_FileSpecification                 {Invoke}
Win32_FontInfoAction                    {Invoke}
Win32_Group                             {Rename}
Win32_HeatPipe                          {SetPowerState, Reset}
Win32_IDEController                     {SetPowerState, Reset}
Win32_InfraredDevice                    {SetPowerState, Reset}
Win32_IniFileSpecification              {Invoke}
Win32_Keyboard                          {SetPowerState, Reset}
Win32_LaunchCondition                   {Invoke}
Win32_LogicalDisk                       {SetPowerState, Reset, Chkdsk, ScheduleAutoChk…}
Win32_LogicalFileSecuritySetting        {GetSecurityDescriptor, SetSecurityDescriptor}
Win32_LogicalShareSecuritySetting       {GetSecurityDescriptor, SetSecurityDescriptor}
Win32_MappedLogicalDisk                 {SetPowerState, Reset}
Win32_MemoryArray                       {SetPowerState, Reset}
Win32_MemoryDevice                      {SetPowerState, Reset}
Win32_MIMEInfoAction                    {Invoke}
Win32_MotherboardDevice                 {SetPowerState, Reset}
Win32_MoveFileAction                    {Invoke}
Win32_NetworkAdapter                    {SetPowerState, Reset, Enable, Disable}
Win32_NetworkAdapterConfiguration       {EnableDHCP, RenewDHCPLease, RenewDHCPLeaseAll, ReleaseDHCPLease…}
Win32_NTEventlogFile                    {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
Win32_ODBCDataSourceSpecification       {Invoke}
Win32_ODBCDriverSpecification           {Invoke}
Win32_ODBCTranslatorSpecification       {Invoke}
Win32_OfflineFilesCache                 {Enable, RenameItem, RenameItemEx, Synchronize…}
Win32_OperatingSystem                   {Reboot, Shutdown, Win32Shutdown, Win32ShutdownTracker…}
Win32_PageFile                          {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
Win32_ParallelPort                      {SetPowerState, Reset}
Win32_PCMCIAController                  {SetPowerState, Reset}
Win32_PhysicalMemoryArray               {IsCompatible}
Win32_PnPEntity                         {SetPowerState, Reset, Enable, Disable…}
Win32_PnPSignedDriver                   {StartService, StopService}
Win32_PointingDevice                    {SetPowerState, Reset}
Win32_PortableBattery                   {SetPowerState, Reset}
Win32_POTSModem                         {SetPowerState, Reset}
Win32_Printer                           {SetPowerState, Reset, Pause, Resume…}
Win32_PrinterDriver                     {StartService, StopService, AddPrinterDriver}
Win32_PrintJob                          {Pause, Resume}
Win32_Process                           {Create, Terminate, GetOwner, GetOwnerSid…}
Win32_Processor                         {SetPowerState, Reset}
Win32_Product                           {Install, Admin, Advertise, Reinstall…}
Win32_ProgIDSpecification               {Invoke}
Win32_PublishComponentAction            {Invoke}
Win32_Refrigeration                     {SetPowerState, Reset}
Win32_RegistryAction                    {Invoke}
Win32_ReliabilityRecords                {GetRecordCount}
Win32_ReliabilityStabilityMetrics       {GetRecordCount}
Win32_RemoveFileAction                  {Invoke}
Win32_RemoveIniAction                   {Invoke}
Win32_ReserveCost                       {Invoke}
Win32_ScheduledJob                      {Create, Delete}
Win32_SCSIController                    {SetPowerState, Reset}
Win32_SecurityDescriptorHelper          {Win32SDToSDDL, Win32SDToBinarySD, SDDLToWin32SD, SDDLToBinarySD…}
Win32_SecuritySetting                   {GetSecurityDescriptor, SetSecurityDescriptor}
Win32_SelfRegModuleAction               {Invoke}
Win32_SerialPort                        {SetPowerState, Reset}
Win32_Service                           {StartService, StopService, PauseService, ResumeService…}
Win32_ServiceSpecification              {Invoke}
Win32_ShadowCopy                        {Create, Revert}
Win32_ShadowStorage                     {Create}
Win32_Share                             {Create, SetShareInfo, GetAccessMask, Delete}
Win32_ShortcutAction                    {Invoke}
Win32_ShortcutFile                      {TakeOwnerShip, ChangeSecurityPermissions, Copy, Rename…}
Win32_SMBIOSMemory                      {SetPowerState, Reset}
Win32_SoftwareElementCondition          {Invoke}
Win32_SoftwareFeature                   {Reinstall, Configure}
Win32_SoundDevice                       {SetPowerState, Reset}
Win32_SystemDriver                      {StartService, StopService, PauseService, ResumeService…}
Win32_SystemEnclosure                   {IsCompatible}
Win32_TapeDrive                         {SetPowerState, Reset}
Win32_TemperatureProbe                  {SetPowerState, Reset}
Win32_TerminalService                   {StartService, StopService, PauseService, ResumeService…}
Win32_TypeLibraryAction                 {Invoke}
Win32_USBController                     {SetPowerState, Reset}
Win32_USBHub                            {SetPowerState, Reset, GetDescriptor}
Win32_UserAccount                       {Rename}
Win32_UserProfile                       {ChangeOwner}
Win32_VideoController                   {SetPowerState, Reset}
Win32_VoltageProbe                      {SetPowerState, Reset}
Win32_Volume                            {SetPowerState, Reset, Chkdsk, ScheduleAutoChk…}
#>