# Collect the filtered events          
$Events = Get-WinEvent -FilterHashTable @{
    LogName   = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
    ID        = @(8001,8002,8003)
} -MaxEvents 100         
            
# Parse out the event message data            
ForEach ($Event in $Events) 
{            
    # Convert the event to XML            
    $eventXML = [xml]$Event.ToXml()  
              
    # Iterate through each one of the XML message properties            
    For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) 
    {            
        # Append these as object properties            
        $AddMemberSplat = @{
            InputObject = $Event 
            MemberType  = 'NoteProperty'
            Force       = $true
            Name        = $eventXML.Event.EventData.Data[$i].Name 
            Value       = $eventXML.Event.EventData.Data[$i].'#text'
        }
        Add-Member @AddMemberSplat           
    }            
}            
            
# View the results   
$Events | Select-Object TimeCreated,ID,LevelDisplayName,SSID,OpcodeDisplayName,Reason,FailureReason | FT