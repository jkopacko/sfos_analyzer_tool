#### READ EXPORTED XML FROM SFOS v18 ####
[xml]$Config = Get-Content "C:\SFOS_Analyzer\Entities.xml"

#########
# WAN
# NETWORK 
# RULE 
# TYPE 
#########

### METHOD TO WRITE WAN NETWORK RESULTS FILE FUNCTION ###
$WANAnalyzerResults= "C:\SFOS_Analyzer\WANRuleResults.txt"
function WriteNetworkReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $WANAnalyzerResults -Append
}

### METHOD TO WRITE WAN NETWORK RESULTS SECTION BREAKS ###
function WriteSectionHeader ($text)
{
$text | Out-File -FilePath $NetworkAnalyzerResults -Append
}

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN MISSING LOGGING ###
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
$NetworkRulesNotLogged = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
WriteNetworkReport $NetworkRulesNotLogged  

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT FILTERING PORTS ####
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
$NetworkRulesNoPortFilter = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Services";expression={$($_.NetworkPolicy.Services)}}
WriteNetworkReport $NetworkRulesNoPortFilter

### -- Needs Tweaked -- ###
### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC ###
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT INSPECTING TRAFFIC--"
$NetworkRulesNotInspected = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.ScanVirus -Eq "Disable" -OR $_.NetworkPolicy.ProxyMode -Eq "Disable" -OR $_.NetworkPolicy.DecryptHTTPS -Eq "Disable") -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="GoogleQuic";expression={$($_.NetworkPolicy.BlockQuickQuic)}},
@{label="DPI";expression={$($_.NetworkPolicy.ScanVirus)}},
@{label="Proxy";expression={$($_.NetworkPolicy.ProxyMode)}},
@{label="Decrypt";expression={$($_.NetworkPolicy.DecryptHTTPS)}}
WriteNetworkReport $NetworkRulesNotInspected

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING SANDSTORM ###
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING SANDSTORM--"
$NetworkRulesNoSandstorm = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.Sandstorm -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN")} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Sandstorm";expression={$($_.NetworkPolicy.Sandstorm)}}
WriteNetworkReport $NetworkRulesNoSandstorm

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING APPLICATION CONTROL ###
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
$NetworkRulesNoAppC = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.ApplicationControl -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
WriteNetworkReport $NetworkRulesNoAppC

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING IPS ###
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
$NetworkRulesNoIPS = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
WriteNetworkReport $NetworkRulesNoIPS

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING SYNC SEC ###
WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
$NetworkRulesNoSyncSec = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}}
WriteNetworkReport $NetworkRulesNoSyncSec

#########
# DMZ
# NETWORK 
# RULE 
# TYPE 
#########

### METHOD TO WRITE DMZ NETWORK RESULTS FILE FUNCTION ###
$DMZAnalyzerResults= "C:\SFOS_Analyzer\DMZRuleResults.txt"
function WriteDMZReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $DMZAnalyzerResults -Append
}

### METHOD TO WRITE DMZ NETWORK RESULTS SECTION BREAKS ###
function WriteDMZSectionHeader ($text)
{
$text | Out-File -FilePath $DMZAnalyzerResults -Append
}

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ MISSING LOGGING ###
WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
$NetworkRulesNotLoggedDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
WriteDMZReport $NetworkRulesNotLoggedDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT FILTERING PORTS ###
WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
$NetworkRulesNoPortFilterDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Services";expression={$($_.NetworkPolicy.Services)}}
WriteDMZReport $NetworkRulesNoPortFilterDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING APPLICATION CONTROL ###
WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
$NetworkRulesNoAppCDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Application -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
WriteDMZReport $NetworkRulesNoAppCDMZ

## ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING IPS ###
WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
$NetworkRulesNoIPSDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
WriteDMZReport $NetworkRulesNoIPSDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING SYNC SEC ###
WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
$NetworkRulesNoSyncSecDMZ = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat) -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.NetworkPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.NetworkPolicy.MinimumDestinationHBPermitted)}} 
WriteDMZReport $NetworkRulesNoSyncSecDMZ

#########
# LAN
# NETWORK 
# RULE 
# TYPE 
#########

### METHOD TO WRITE LAN NETWORK RESULTS FILE FUNCTION ###
$LANAnalyzerResults= "C:\SFOS_Analyzer\LANRuleResults.txt"
function WriteLANReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $LANAnalyzerResults -Append
}

### METHOD TO WRITE LAN NETWORK RESULTS SECTION BREAKS ###
function WriteLANSectionHeader ($text)
{
$text | Out-File -FilePath $LANAnalyzerResults -Append
}

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN MISSING LOGGING
WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
$NetworkRulesNotLoggedLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
WriteLANReport $NetworkRulesNotLoggedLAN

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT FILTERING PORTS
WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
$NetworkRulesNoPortFilterLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Services";expression={$($_.NetworkPolicy.Services)}}
WriteLANReport $NetworkRulesNoPortFilterLAN

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING APPLICATION CONTROL
WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
$NetworkRulesNoAppCLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Application -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
WriteLANReport $NetworkRulesNoAppCLAN

## ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING IPS
WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
$NetworkRulesNoIPSLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
WriteLANReport $NetworkRulesNoIPSLAN

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING SYNC SEC
WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
$NetworkRulesNoSyncSecLAN = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat) -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.NetworkPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.NetworkPolicy.MinimumDestinationHBPermitted)}} 
WriteLANReport $NetworkRulesNoSyncSecLAN

#########
# WAN 
# USER
# RULE 
# TYPE 
#########

### METHOD TO WRITE USER WAN RESULTS FILE FUNCTION ###
$UserWANAnalyzerResults= "C:\SFOS_Analyzer\UserWANRuleResults.txt"
function WriteUserWANReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $UserWANAnalyzerResults -Append
}

### METHOD TO WRITE USER WAN RESULTS SECTION BREAKS ###
function WriteUserWANSectionHeader ($text)
{
$text | Out-File -FilePath $UserWANAnalyzerResults -Append
}

### ANALYZE USER TRAFFIC DESTINED FOR WAN MISSING LOGGING ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
$UserRulesNotLogged = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
WriteUserWANReport $UserRulesNotLogged  

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT FILTERING PORTS ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS-"
$UserRulesNoPortFilter = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Services";expression={$($_.UserPolicy.Services)}}
WriteUserWANReport $UserRulesNoPortFilter

### -- Needs tweaked to separate DPI v PROXY -- ###
### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT INSPECTING TRAFFIC--"
$UserRulesNotInspected = $Config.Configuration.FirewallRule |
Where-Object {($_.UserPolicy.ScanVirus -Eq "Disable" -OR $_.UserPolicy.ProxyMode -Eq "Disable" -OR $_.UserPolicy.DecryptHTTPS -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="GoogleQuic";expression={$($_.UserPolicy.BlockQuickQuic)}},
@{label="DPI";expression={$($_.UserPolicy.ScanVirus)}},
@{label="Proxy";expression={$($_.UserPolicy.ProxyMode)}},
@{label="Decrypt";expression={$($_.UserPolicy.DecryptHTTPS)}}
WriteUserWANReport $UserRulesNotInspected

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING SANDSTORM ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SANDSTORM--"
$UserRulesNoSandstorm = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Sandstorm -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Sandstorm";expression={$($_.UserPolicy.Sandstorm)}}
WriteUserWANReport $UserRulesNoSandstorm

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING APPLICATION CONTROL ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
$UserRulesNoAppC = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
WriteUserWANReport $UserRulesNoAppC

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING IPS ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
$UserRulesNoIPS = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
WriteUserWANReport $UserRulesNoIPS

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING SYNC SEC ###
WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
$UserRulesNoSyncSec = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}}
WriteUserWANReport $UserRulesNoSyncSec

#########
# DMZ
# USER
# RULE 
# TYPE 
#########

### METHOD TO WRITE USER DMZ RESULTS FILE FUNCTION ###
$UserDMZAnalyzerResults= "C:\SFOS_Analyzer\UserDMZRuleResults.txt"
function WriteUserDMZReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $UserDMZAnalyzerResults -Append
}

### METHOD TO WRITE USER DMZ RESULTS SECTION BREAKS ###
function WriteUserDMZSectionHeader ($text)
{
$text | Out-File -FilePath $UserDMZAnalyzerResults -Append
}

### ANALYZE USER TRAFFIC DESTINED FOR DMZ MISSING LOGGING ###
WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
$UserRulesNotLoggedDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
WriteUserDMZReport $UserRulesNotLoggedDMZ

### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT FILTERING PORTS ###
WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
$UserRulesNoPortFilterDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Services";expression={$($_.UserPolicy.Services)}}
WriteUserDMZReport $UserRulesNoPortFilterDMZ

### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING APPLICATION CONTROL ###
WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL-"
$UserRulesNoAppCDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
WriteUserDMZReport $UserRulesNoAppCDMZ

## ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING IPS ###
WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
$UserRulesNoIPSDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
WriteUserDMZReport $UserRulesNoIPSDMZ

### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING SYNC SEC ###
WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
$UserRulesNoSyncSecDMZ = $Config.Configuration.FirewallRule |
Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat) -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.UserPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.UserPolicy.MinimumDestinationHBPermitted)}} 
WriteUserDMZReport $UserRulesNoSyncSecDMZ

#########
# LAN
# USER
# RULE 
# TYPE 
#########

## METHOD TO WRITE USER LAN RESULTS FILE FUNCTION ###
$UserLANAnalyzerResults= "C:\SFOS_Analyzer\UserLANRuleResults.txt"
function WriteUserLANReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $UserLANAnalyzerResults -Append
}

### METHOD TO WRITE USER LAN RESULTS SECTION BREAKS ###
function WriteUserLANSectionHeader ($text)
{
$text | Out-File -FilePath $UserLANAnalyzerResults -Append
}

### ANALYZE USER TRAFFIC DESTINED FOR LAN MISSING LOGGING
WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
$UserRulesNotLoggedLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
WriteUserLANReport $UserRulesNotLoggedLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT FILTERING PORTS
WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
$UserRulesNoPortFilterLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Services";expression={$($_.UserPolicy.Services)}}
WriteUserLANReport $UserRulesNoPortFilterLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING APPLICATION CONTROL
WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
$UserRulesNoAppCLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
WriteUserLANReport $UserRulesNoAppCLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING IPS
WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
$UserRulesNoIPSLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
WriteUserLANReport $UserRulesNoIPSLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING SYNC SEC
WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
$UserRulesNoSyncSecLAN = $Config.Configuration.FirewallRule |
Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat) -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.UserPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.UserPolicy.MinimumDestinationHBPermitted)}} 
WriteUserLANReport $UserRulesNoSyncSecLAN

#########
# HTTP
# RULE 
# TYPE 
#########

### METHOD TO WRITE HTTP RESULTS FILE FUNCTION ###
$HTTPAnalyzerResults= "C:\SFOS_Analyzer\HTTPRuleResults.txt"
function WriteHTTPReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $HTTPAnalyzerResults -Append
}

### METHOD TO WRITE HTTP RESULTS SECTION BREAKS ###
function WriteHTTPSectionHeader ($text)
{
$text | Out-File -FilePath $HTTPAnalyzerResults -Append
}

### ANALYZE WAF RULE RUNNING ON INSECURE PORT ###
WriteHTTPSectionHeader "--THE FOLLOWING RULES ARE RUNNING ON AN INSECURE PORT--"
$HTTPProtectionResults = $Config.Configuration.FirewallRule |
Where-Object {$_.HTTPBasedPolicy.HTTPS -Eq "Disable"} |
Select-Object -Property Name, Status,
@{label="HTTPS";expression={$($_.HTTPBasedPolicy.HTTPS)}}, 
@{label="ListeningPort";expression={$($_.HTTPBasedPolicy.ListenPort)}},
@{label="Domains";expression={$($_.HTTPBasedPolicy.Domains.Domain)}},
@{label="Redirected";expression={$($_.HTTPBasedPolicy.RedirectHTTP)}}
WriteHTTPReport $HTTPProtectionResults

### ANALYZE WAF RULE NOT USING PROTOCOL SECURITY ####
WriteHTTPSectionHeader "--THE FOLLOWING RULES ARE MISSING A SECURITY TEMPLATE--"
$HTTPProtectionResults = $Config.Configuration.FirewallRule |
Where-Object {$_.HTTPBasedPolicy.ProtocolSecurity -Eq "None"} | 
Select-Object -Property Name, Status,
@{label="Protection";expression={$($_.HTTPBasedPolicy.ProtocolSecurity)}} 
WriteHTTPReport $HTTPProtectionResults

### ANALYZE WAF RULE NOT USING IPS ###
WriteHTTPSectionHeader "--THE FOLLOWING RULES ARE MISSING AN IPS POLICY--"
$HTTPProtectionResults = $Config.Configuration.FirewallRule |
Where-Object {$_.HTTPBasedPolicy.IntrusionPrevention -Eq "None"} |
Select-Object -Property Name, Status,
@{label="IPS";expression={$($_.HTTPBasedPolicy.IntrusionPrevention)}}
WriteHTTPReport $HTTPProtectionResults
