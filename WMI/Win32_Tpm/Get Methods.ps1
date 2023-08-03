#Requires -RunAsAdministrator
Get-CimClass -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm | Select-Object -ExpandProperty CimClassMethods | Sort-Object Name

<#
Name                                  ReturnType Parameters                                                         Qualifiers
----                                  ---------- ----------                                                         ----------
AddBlockedCommand                         UInt32 {CommandOrdinal}                                                   {Description, Implemented}
ChangeOwnerAuth                           UInt32 {NewOwnerAuth, OldOwnerAuth}                                       {Description, Implemented}
Clear                                     UInt32 {OwnerAuth}                                                        {Description, Implemented}
ConvertToOwnerAuth                        UInt32 {OwnerPassPhrase, OwnerAuth}                                       {Description, Implemented}
CreateEndorsementKeyPair                  UInt32 {}                                                                 {Description, Implemented}
Disable                                   UInt32 {OwnerAuth}                                                        {Description, Implemented}
DisableAutoProvisioning                   UInt32 {OnlyForNextBoot}                                                  {Description, Implemented}
Enable                                    UInt32 {OwnerAuth}                                                        {Description, Implemented}
EnableAutoProvisioning                    UInt32 {}                                                                 {Description, Implemented}
GetCapLockoutInfo                         UInt32 {LockoutCounter, MaxTries}                                         {Description, Implemented}
GetDictionaryAttackParameters             UInt32 {LockoutRecovery, MaxTries, RecoveryTime}                          {Description, Implemented}
GetOwnerAuth                              UInt32 {OwnerAuth}                                                        {Description, Implemented}
GetOwnerAuthForEscrow                     UInt32 {OwnerAuth, OwnerAuthStatus}                                       {Description, Implemented}
GetOwnerAuthStatus                        UInt32 {OwnerAuthStatus}                                                  {Description, Implemented}
GetPhysicalPresenceConfirmationStatus     UInt32 {Operation, ConfirmationStatus}                                    {Description, Implemented}
GetPhysicalPresenceRequest                UInt32 {Request}                                                          {Description, Implemented}
GetPhysicalPresenceResponse               UInt32 {Request, Response}                                                {Description, Implemented}
GetPhysicalPresenceTransition             UInt32 {Transition}                                                       {Description, Implemented}
GetSrkADThumbprint                        UInt32 {SrkPublicKeyModulus, SrkADThumbprint}                             {Description, Implemented}
GetSrkPublicKeyModulus                    UInt32 {SrkPublicKeyModulus}                                              {Description, Implemented}
GetTcgLog                                 UInt32 {TcgLog}                                                           {Description, Implemented}
ImportOwnerAuth                           UInt32 {OwnerAuth}                                                        {Description, Implemented}
IsActivated                               UInt32 {IsActivated}                                                      {Description, Implemented}
IsAutoProvisioningEnabled                 UInt32 {IsAutoProvisioningEnabled}                                        {Description, Implemented}
IsCommandBlocked                          UInt32 {CommandOrdinal, IsCommandBlocked}                                 {Description, Implemented}
IsCommandPresent                          UInt32 {CommandOrdinal, IsCommandPresent}                                 {Description, Implemented}
IsEnabled                                 UInt32 {IsEnabled}                                                        {Description, Implemented}
IsEndorsementKeyPairPresent               UInt32 {IsEndorsementKeyPairPresent}                                      {Description, Implemented}
IsFIPS                                    UInt32 {IsFIPS}                                                           {Description, Implemented}
IsKeyAttestationCapable                   UInt32 {TestResult}                                                       {Description, Implemented}
IsLockedOut                               UInt32 {IsLockedOut}                                                      {Description, Implemented}
IsOwned                                   UInt32 {IsOwned}                                                          {Description, Implemented}
IsOwnerClearDisabled                      UInt32 {IsOwnerClearDisabled}                                             {Description, Implemented}
IsOwnershipAllowed                        UInt32 {IsOwnershipAllowed}                                               {Description, Implemented}
IsPhysicalClearDisabled                   UInt32 {IsPhysicalClearDisabled}                                          {Description, Implemented}
IsPhysicalPresenceHardwareEnabled         UInt32 {IsPhysicalPresenceHardwareEnabled}                                {Description, Implemented}
IsReady                                   UInt32 {IsReady}                                                          {Description, Implemented}
IsReadyInformation                        UInt32 {Information, IsReady}                                             {Description, Implemented}
IsSrkAuthCompatible                       UInt32 {IsSrkAuthCompatible}                                              {Description, Implemented}
OwnerAuthEscrowed                         UInt32 {OwnerAuth}                                                        {Description, Implemented}
Provision                                 UInt32 {ForceClear_Allowed, PhysicalPresencePrompts_Allowed, Information} {Description, Implemented}
RemoveBlockedCommand                      UInt32 {CommandOrdinal}                                                   {Description, Implemented}
ResetAuthLockOut                          UInt32 {OwnerAuth}                                                        {Description, Implemented}
ResetSrkAuth                              UInt32 {OwnerAuth}                                                        {Description, Implemented}
SelfTest                                  UInt32 {SelfTestResult}                                                   {Description, Implemented}
SetPhysicalPresenceRequest                UInt32 {Request, RequestParameter}                                        {Description, Implemented}
TakeOwnership                             UInt32 {OwnerAuth}                                                        {Description, Implemented}
#>