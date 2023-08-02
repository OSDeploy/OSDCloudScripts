# if the current Powershell session was called with administrator privileges,
# the Administrator Group's well-known SID will show up in the Groups for the current identity.
# Note that the SID won't show up unless the process is elevated.
return (([Security.Principal.WindowsIdentity]::GetCurrent()).Groups -contains "S-1-5-32-544")
