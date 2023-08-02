Get-CimClass -Namespace root/CIMV2 | `
Sort-Object -Property CimClassName | `
? CimClassName -Match 'Win32_' | `
? CimClassName -NotMatch 'PerfRawData' | `
? CimClassName -NotMatch 'PerfFormattedData' | `
Select-Object CimClassName