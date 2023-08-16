$Namespace = 'root\HP\InstrumentedBIOS'
$Class = 'HP_BIOSSetting'

Get-WmiObject -Namespace $Namespace -Class $Class | Where-Object {$_.IsReadOnly -eq 0} | Select-Object Path, Name, CurrentValue | Sort-Object Path, Name

<#
Path                                                           Name                                                                              CurrentValue
----                                                           ----                                                                              ------------
\                                                              Manufacturing Programming Mode                                                    Lock
\Advanced                                                      HBMA Custom MAC Address
\Advanced                                                      Host Based MAC Address                                                            System
\Advanced\AMT Options                                          BIOS Watchdog Timer (min.)                                                        5
\Advanced\AMT Options                                          CIRA Timeout (min.)                                                               1 min
\Advanced\AMT Options                                          Intel Active Management Technology (AMT)                                          Enable
\Advanced\AMT Options                                          OS Watchdog Timer (min.)                                                          5
\Advanced\AMT Options                                          Show Unconfigure ME Confirmation Prompt                                           Enable
\Advanced\AMT Options                                          SOL Terminal Emulation Mode                                                       ANSI
\Advanced\AMT Options                                          Unconfigure AMT on next boot                                                      Do Not Apply
\Advanced\AMT Options                                          USB Key Provisioning Support                                                      Disable
\Advanced\AMT Options                                          USB Redirection Support                                                           Enable
\Advanced\AMT Options                                          Verbose Boot Messages                                                             Disable
\Advanced\AMT Options                                          Watchdog Timer                                                                    Disable
\Advanced\Boot Options                                         Audio Alerts During Boot                                                          Enable
\Advanced\Boot Options                                         Fast Boot                                                                         Disable
\Advanced\Boot Options                                         Force Cold Boot                                                                   Disable
\Advanced\Boot Options                                         IPv6 during UEFI Boot                                                             Enable
\Advanced\Boot Options                                         Network (PXE) Boot                                                                Enable
\Advanced\Boot Options                                         NumLock on at boot                                                                Enable
\Advanced\Boot Options                                         Power On When AC Detected                                                         Disable
\Advanced\Boot Options                                         Power On When Lid is Opened                                                       Disable
\Advanced\Boot Options                                         Prompt on Battery Errors                                                          Enable
\Advanced\Boot Options                                         Prompt on Fixed Storage Change                                                    Enable
\Advanced\Boot Options                                         Prompt on Memory Size Change                                                      Enable
\Advanced\Boot Options                                         Startup Delay (sec.)                                                              5
\Advanced\Boot Options                                         UEFI Boot Order
\Advanced\Boot Options                                         USB Storage Boot                                                                  Enable
\Advanced\Built in Device                                      Automatic Keyboard Backlit                                                        Disable
\Advanced\Built in Device                                      Backlit keyboard timeout                                                          Never.
\Advanced\Built in Device                                      Bluetooth                                                                         Enable
\Advanced\Built in Device                                      Boost Converter                                                                   Enable
\Advanced\Built in Device                                      Fan Always on while on AC Power                                                   Disable
\Advanced\Built in Device                                      LAN / WLAN Auto Switching                                                         Disable
\Advanced\Built in Device                                      Lock Wireless Button                                                              Disable
\Advanced\Built in Device                                      Smart Card                                                                        Enable
\Advanced\Built in Device                                      Smart Card Power Savings                                                          Enable
\Advanced\Built in Device                                      Wireless Network Device (WLAN)                                                    Enable
\Advanced\Built-In Device Options                              Audio Device                                                                      Enable
\Advanced\Built-In Device Options                              Battery Health Manager                                                            Let HP manage my battery charging
\Advanced\Built-In Device Options                              Extended Idle Power States                                                        Enable
\Advanced\Built-In Device Options                              Fingerprint Device                                                                Enable
\Advanced\Built-In Device Options                              Headphone Output                                                                  Enable
\Advanced\Built-In Device Options                              Integrated Camera                                                                 Enable
\Advanced\Built-In Device Options                              Internal Speakers                                                                 Enable
\Advanced\Built-In Device Options                              Microphone                                                                        Enable
\Advanced\Built-In Device Options                              NFC                                                                               Enable
\Advanced\Built-In Device Options                              Runtime Power Management                                                          Enable
\Advanced\Built-In Device Options                              Video Memory Size                                                                 512 MB
\Advanced\Built-In Device Options                              Wake On LAN                                                                       Boot to Hard Drive
\Advanced\Configurations                                       Automatic BIOS Update Setting                                                     Disable
\Advanced\Configurations                                       Automatically Check for Updates                                                   Monthly
\Advanced\Configurations                                       Data transfer timeout
\Advanced\Configurations                                       DNS Addresses
\Advanced\Configurations                                       DNS Configuration                                                                 Automatic
\Advanced\Configurations                                       Force Check on Reboot                                                             Disable
\Advanced\Configurations                                       Force Default IP Configuration                                                    Disable
\Advanced\Configurations                                       Force HTTP no-cache                                                               Enable
\Advanced\Configurations                                       IPv4 Address
\Advanced\Configurations                                       IPv4 Configuration                                                                Automatic
\Advanced\Configurations                                       IPv4 Gateway
\Advanced\Configurations                                       IPv4 Subnet Mask
\Advanced\Configurations                                       Proxy Address
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Custom Client Download Url
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Custom Client Upload Url
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Execute On Next Boot                            Disable
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Last Execution Status
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Scheduled Execution Enabled                     Disable
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Scheduled Execution Frequency                   Weekly
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Upload Server Password
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Upload Server Username
\Advanced\Configurations                                       Remote HP PC Hardware Diagnostics Use Custom Download Url                         Disable
\Advanced\Configurations                                       Update Address
\Advanced\Configurations                                       Update BIOS via Network                                                           Enable
\Advanced\Configurations                                       Update Source                                                                     HP
\Advanced\Configurations                                       Use Proxy                                                                         Disable
\Advanced\Device Configuration                                 Enable High Resolution mode when connected to a USB-C DP alt mode dock            Disable
\Advanced\Device Configuration                                 Fast Charge                                                                       Enable
\Advanced\Device Configuration                                 Launch Hotkeys without Fn Keypress                                                Auto
\Advanced\Device Configuration                                 Power button delay before sleep or power down                                     Enable
\Advanced\Device Configuration                                 Power Control                                                                     Enable
\Advanced\Device Configuration                                 Special Keys mapped to Fn + keypress                                              Enable
\Advanced\Device Configuration                                 Swap Fn and Ctrl (Keys)                                                           Disable
\Advanced\Device Configuration                                 USB Type-C Connector System Software Interface (UCSI)                             Enable
\Advanced\Display Language                                     Select Keyboard Layout                                                            English
\Advanced\Display Language                                     Select Language                                                                   English
\Advanced\HP Sure Recover                                      OS Recovery                                                                       Enable
\Advanced\HP Sure Recover                                      Prompt before Boot Failure Recovery                                               Enable
\Advanced\HP Sure Recover                                      Recover OS after Boot Failure                                                     Disable
\Advanced\HP Sure Recover                                      Recover OS from Network                                                           Enable
\Advanced\Network Settings                                     Extended DHCP Timeout                                                             Enable
\Advanced\Port Options                                         Disable Charging Port in sleep/off if battery below (%):
\Advanced\Port Options                                         Left USB Ports                                                                    Enable
\Advanced\Port Options                                         Restrict USB Devices                                                              Allow all USB Devices
\Advanced\Port Options                                         Right USB Ports                                                                   Enable
\Advanced\Port Options                                         Thunderbolt Mode                                                                  Enable
\Advanced\Port Options                                         Thunderbolt Type-C Ports                                                          Enable
\Advanced\Port Options                                         USB Legacy Port Charging                                                          Enable
\Advanced\Scheduled Power-On                                   BIOS Power-On Hour
\Advanced\Scheduled Power-On                                   BIOS Power-On Minute
\Advanced\Scheduled Power-On                                   Friday                                                                            Disable
\Advanced\Scheduled Power-On                                   Monday                                                                            Disable
\Advanced\Scheduled Power-On                                   Saturday                                                                          Disable
\Advanced\Scheduled Power-On                                   Sunday                                                                            Disable
\Advanced\Scheduled Power-On                                   Thursday                                                                          Disable
\Advanced\Scheduled Power-On                                   Tuesday                                                                           Disable
\Advanced\Scheduled Power-On                                   Wednesday                                                                         Disable
\Advanced\System Options                                       DMA Protection                                                                    Enable
\Advanced\System Options                                       Dynamic Noise Suppression                                                         Enable
\Advanced\System Options                                       Enhanced Sign-In Security                                                         Disable
\Advanced\System Options                                       HP Application Driver                                                             Enable
\Advanced\System Options                                       Hyperthreading                                                                    Enable
\Advanced\System Options                                       Intel Dynamic Tuning                                                              Enable
\Advanced\System Options                                       Pre-boot DMA protection                                                           All PCIe Devices
\Advanced\System Options                                       Sanitization Mode Countdown Timer                                                 60
\Advanced\System Options                                       Trusted Execution Technology (TXT)                                                Enable
\Advanced\System Options                                       Turbo-boost                                                                       Enable
\Advanced\System Options                                       Virtualization Technology (VTx)                                                   Enable
\Advanced\System Options                                       Virtualization Technology for Directed I/O (VTd)                                  Enable
\Advanced\Tme Options                                          Full encryption of main memory (DRAM)                                             Disable
\Main                                                          Apply Custom Defaults and Exit                                                    No
\Main                                                          Apply Factory Defaults and Exit                                                   No
\Main                                                          Save Custom Defaults                                                              Do not Save
\Main\BIOS Event Log                                           Clear BIOS Event Log                                                              Don't Clear
\Main\System Information                                       MS Digital Marker
\Main\System Information\System IDs                            Asset Tracking Number
\Main\System Information\System IDs                            Ownership Tag
\Main\Update System BIOS                                       BIOS Rollback Policy                                                              Unrestricted Rollback to older BIOS
\Main\Update System BIOS                                       Lock BIOS Version                                                                 Disable
\Main\Update System BIOS                                       Minimum BIOS Version
\Main\Update System BIOS                                       Native OS Firmware Update Service                                                 Enable
\Security                                                      Power-On Password
\Security                                                      Setup Password
\Security\Administrator Tools\Password Policies                Allow User to Modify Power-on Password                                            Change or Delete
\Security\Administrator Tools\Password Policies                Are spaces allowed in Administrator and User passwords?                           No
\Security\Administrator Tools\Password Policies                At least one lower case character is required in Administrator and User passwords No
\Security\Administrator Tools\Password Policies                At least one number is required in Administrator and User passwords               No
\Security\Administrator Tools\Password Policies                At least one symbol is required in Administrator and User passwords               No
\Security\Administrator Tools\Password Policies                At least one upper case character is required in Administrator and User passwords No
\Security\Administrator Tools\Password Policies                BIOS Administrator visible at Power-on Authentication                             Enable
\Security\Administrator Tools\Password Policies                Password Minimum Length
\Security\Administrator Tools\Password Policies                Prompt for Admin authentication on F11 (System Recovery)                          Disable
\Security\Administrator Tools\Password Policies                Prompt for Admin authentication on F12 (Network Boot)                             Disable
\Security\Administrator Tools\Password Policies                Prompt for Admin authentication on F9 (Boot Menu)                                 Disable
\Security\Administrator Tools\Password Policies                Wake on LAN Power-on Password Policy                                              Require Password
\Security\Boot Sector (MBR/GPT) Recovery Policy                Boot Sector (MBR/GPT) Recovery Policy                                             Local user control
\Security\Fingerprint Reset on Reboot                          Fingerprint Reset on Reboot                                                       Disable
\Security\Secure Boot Configuration                            Ready BIOS for Device Guard Use                                                   Do Nothing
\Security\Secure Boot Configuration                            Secure Boot                                                                       Enable
\Security\Security Configuration\BIOS SureStart                Dynamic Runtime Scanning of Boot Block                                            Enable
\Security\Security Configuration\BIOS SureStart                Enhanced HP Firmware Runtime Intrusion Prevention and Detection                   Enable
\Security\Security Configuration\BIOS SureStart                Sure Start BIOS Settings Protection                                               Disable
\Security\Security Configuration\BIOS SureStart                Sure Start Secure Boot Keys Protection                                            Enable
\Security\Security Configuration\BIOS SureStart                Sure Start Security Event Boot Notification                                       Require Acknowledgment
\Security\Security Configuration\BIOS SureStart                Sure Start Security Event Policy                                                  Log Event and notify user
\Security\Security Configuration\BIOS SureStart                Verify Boot Block on every boot                                                   Disable
\Security\Security Configuration\HP Find Lock Wipe             Permanently Disable Remote Device Management (Set Once)                           No
\Security\Security Configuration\HP Find Lock Wipe             Remote Device Management                                                          Enable
\Security\Security Configuration\HP Secure Platform Management Enhanced BIOS Authentication Mode                                                 Disable
\Security\Security Configuration\HP Secure Platform Management Enhanced BIOS Authentication Mode Local Access Key 1
\Security\Security Configuration\HP Secure Platform Management HP Cloud Managed                                                                  Enable
\Security\Security Configuration\HP Secure Platform Management Permanently Disable HP Cloud Management (Set Once)                                No
\Security\Security Configuration\HP Secure Platform Management Permanently Disable HP Sure Run (Set Once)                                        No
\Security\Security Configuration\HP Secure Platform Management Secure Platform Management Key Endorsement Certificate
\Security\Security Configuration\HP Secure Platform Management Secure Platform Management Signing Key
\Security\Security Configuration\Physical Presence Interface   Physical Presence Interface                                                       Enable
\Security\Security Configuration\Smart Cover                   Clear TPM on boot after cover removal                                             Disable
\Security\Security Configuration\Smart Cover                   Cover Removal Sensor                                                              Disable
\Security\Security Configuration\Smart Cover                   Last Cover Removal and Count
\Security\Security Configuration\Smart Cover                   Power Off Upon Cover Removal                                                      Disable
\Security\Security Configuration\TPM Embedded Security         Clear TPM                                                                         No
\Security\Security Configuration\TPM Embedded Security         TPM Activation Policy                                                             Allow user to reject
\Security\Security Configuration\TPM Embedded Security         TPM Device                                                                        Available
\Security\Security Configuration\TPM Embedded Security         TPM State                                                                         Enable
\Security\Utilities                                            Permanent Disable Absolute Persistence Module Set Once                            No
\Security\Utilities\Hard Drive Utilities                       Allow OPAL Hard Drive SID Authentication                                          Disable
\Security\Utilities\Hard Drive Utilities                       Save/Restore GPT of System Hard Drive                                             Disabled
\Security\Utilities\Sure Option ROM                            Virtualization Based BIOS Protection                                              Enable
\Security\Utilities\Sure Option ROM                            Virtualization Based BIOS Protection Manual Recovery                              Disable
\Security\Utilities\System Management Command                  System Management Command                                                         Enable
#>