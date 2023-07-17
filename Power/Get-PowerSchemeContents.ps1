<#
.DESCRIPTION
    Displays the contents of the specified power scheme.

.EXAMPLE
    powercfg /query

.EXAMPLE
    powercfg /query 381b4222-f694-41f0-9685-ff5bb260df2e 238c9fa8-0aad-41ed-83f4-97be242c8f20
    
.LINK
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options#-query-or-q-
    
.NOTES
    Author: David Segura
    Modified date: 2023-07-16

    Syntax:
    powercfg /query [scheme_GUID] [sub_GUID]

    If neither the parameter scheme_GUID or sub_GUID are provided, the settings of the current active power scheme are displayed. If the parameter sub_GUID is not specified, all settings in the specified power scheme are displayed.

    Arguments:

    scheme_GUID
    Specifies a power scheme GUID. Running powercfg /list returns a power scheme GUID.

    sub_GUID
    Specifies a power-setting subgroup GUID. A power setting subgroup GUID is returned by running powercfg /query.
#>
powercfg /query