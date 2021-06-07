#### READ EXPORTED XML FROM SFOS v18 ####
[xml]$Config = Get-Content "C:\SFOS_Analyzer\Entities.xml"

###### CHECK ADMIN SETTINGS.--- NEEDS FINISHED
$AdminLoginSettings = $Config.Configuration.AdminSettings
Where-Object {$_BlockLogin -eq } | Select-Object -Property,
@{label="BlockLogin";expression={$($_.LoginSecurity.BlockLogin)}},
@{label="FailedAttempts";expression={$($_.LoginSecurity.BlockLogin.BlockLoginSettings.UnsuccessfulAttempts)}},
@{label="Interval(seconds)";expression={$($_.LoginSecurity.BlockLogin.BlockLoginSettings.Duration)}},
@{label="ForMinutes";expression={$($_.LoginSecurity.BlockLogin.BlockLoginSettings.ForMinutes}},
@{label="PasswordComplexity";expression={$($_.PasswordComplexitySettings.PasswordComplexityCheck)}},
@{label="RequiredLength";expression={$($_.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLength)}},
@{label="AlphaChars";expression={$($_.PasswordComplexitySettings.PasswordComplexity.IncludeAlphabeticCharacters)}},
@{label="NumericChars";expression={$($_.PasswordComplexitySettings.PasswordComplexity.IncludeNumericCharacter)}},
@{label="SpecialChars";expression={$($_.PasswordComplexitySettings.PasswordComplexity.IncludeSpecialCharacter)}},
@{label="MinimumLength";expression={$($_.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLengthValue)}}

##### CHECK HOTFIX -- NEEDS FINISHED
$HotfixSetting = $Config.Configuration.Hotfix | Select-Object -Property
@{label="AllowHotFix";expression={$($_.AllowAutoInstallOfHotFixes)}}

##### CHECK CENTRAL MANAGEMENT -- NEEDS FINISHED

##### CHECK AUTHENTICATION SERVERS -- NEEDS FINISHED
$AuthenticationSettings = $Config.Configuration.AuthenticationServer.ActiveDirectory | Select-Object -Property
@{label="Port";expression={$($_.Port)}}

###### NETWORK RULE TYPE ######

### WRITE TO NETWORK RESULTS FILE FUNCTION
$NetworkAnalyzerResults= "C:\SFOS_Analyzer\NetworkRuleResults.txt"
function WriteNetworkReport ($message)
{
$message >> $NetworkAnalyzerResults
}

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN MISSING LOGGING
$NetworkRulesNotLogged = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
WriteNetworkReport "Not Logging On" $NetworkRulesNotLogged  

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT FILTERING PORTS
WriteNetworkReport "Not Filtering Ports On"
$NetworkRulesNoPortFilter = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Services -Eq " " -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Services";expression={$($_.NetworkPolicy.Services)}}
WriteNetworkReport $NetworkRulesNoPortFilter

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC
WriteNetworkReport "Not Inspecting Traffic On"
$NetworkRulesNotInspected = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.ScanVirus -Eq "Disable" -OR $_.NetworkPolicy.ProxyMode -Eq "Disable" -OR $_.NetworkPolicy.DecryptHTTPS -Eq "Disable") -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="GoogleQuic";expression={$($_.NetworkPolicy.BlockQuickQuic)}},
@{label="DPI";expression={$($_.NetworkPolicy.ScanVirus)}},
@{label="Sandstorm";expression={$($_.NetworkPolicy.Sandstorm)}},
@{label="Proxy";expression={$($_.NetworkPolicy.ProxyMode)}},
@{label="Decrypt";expression={$($_.NetworkPolicy.DecryptHTTPS)}}
WriteNetworkReport $NetworkRulesNotInspected

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING SANDSTORM
WriteNetworkReport "Not Using Sandstorm On"
$NetworkRulesNoSandstorm = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Sandstorm -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Sandstorm";expression={$($_.NetworkPolicy.Sandstorm)}}
WriteNetworkReport $NetworkRulesNoSandstorm

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING APPLICATION CONTROL
WriteNetworkReport "Not Using App Control On"
$NetworkRulesNoAppC = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Application -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
WriteNetworkReport $NetworkRulesNoAppC

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING IPS
WriteNetworkReport "Not Using IPS On"
$NetworkRulesNoIPS = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
WriteNetworkReport $NetworkRulesNoIPS

### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING SYNC SEC
WriteNetworkReport "Not Using Sync Sec"
$NetworkRulesNoSyncSec = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}}
WriteNetworkReport $NetworkRulesNoSyncSec

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ MISSING LOGGING
WriteNetworkReport "Not Logging On"
$NetworkRulesNotLoggedDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
WriteNetworkReport $NetworkRulesNotLoggedDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT FILTERING PORTS
WriteNetworkReport "Not Filtering Ports On"
$NetworkRulesNoPortFilterDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Services -Eq " " -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Services";expression={$($_.NetworkPolicy.Services)}}
WriteNetworkReport $NetworkRulesNoPortFilterDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING APPLICATION CONTROL
WriteNetworkReport "Not Using App Control On"
$NetworkRulesNoAppCDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Application -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
WriteNetworkReport $NetworkRulesNoAppCDMZ

## ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING IPS
WriteNetworkReport "Not Using IPS On"
$NetworkRulesNoIPSDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
WriteNetworkReport $NetworkRulesNoIPSDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING SYNC SEC
WriteNetworkReport "Not Using Sync Sec"
$NetworkRulesNoSyncSecDMZ = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat) -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.NetworkPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.NetworkPolicy.MinimumDestinationHBPermitted)}} 
WriteNetworkReport $NetworkRulesNoSyncSecDMZ

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN MISSING LOGGING
WriteNetworkReport "Not Logging On"
$NetworkRulesNotLoggedLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
WriteNetworkReport $NetworkRulesNotLoggedLAN

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT FILTERING PORTS
WriteNetworkReport "Not Filtering Ports On"
$NetworkRulesNoPortFilterLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Services -Eq " " -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="Services";expression={$($_.NetworkPolicy.Services)}}
WriteNetworkReport $NetworkRulesNoPortFilterLAN

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING APPLICATION CONTROL
WriteNetworkReport "Not Using App Control On"
$NetworkRulesNoAppCLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.Application -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
WriteNetworkReport $NetworkRulesNoAppCLAN

## ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING IPS
WriteNetworkReport "Not Using IPS On"
$NetworkRulesNoIPSLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
WriteNetworkReport $NetworkRulesNoIPSLAN

### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING SYNC SEC
WriteNetworkReport "Not Using Sync Sec"
$NetworkRulesNoSyncSecLAN = $Config.Configuration.FirewallRule |
Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat) -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.NetworkPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.NetworkPolicy.MinimumDestinationHBPermitted)}} 
WriteNetworkReport $NetworkRulesNoSyncSecLAN

###### USER RULE TYPE ######

### WRITE TO USER RESULTS FILE FUNCTION
$UserAnalyzerResults= "C:\SFOS_Analyzer\UserRuleResults.txt"
function WriteUserReport ($message)
{
$message >> $UserAnalyzerResults
}

### ANALYZE USER TRAFFIC DESTINED FOR WAN MISSING LOGGING
WriteNetworkReport "Not Logging On"
$UserRulesNotLogged = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
WriteUserReport $UserRulesNotLogged  

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT FILTERING PORTS
WriteNetworkReport "Not Filtering Ports On"
$UserRulesNoPortFilter = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Services";expression={$($_.UserPolicy.Services)}}
WriteUserReport $UserRulesNoPortFilter

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC
WriteNetworkReport "Not Inspecting Traffic On"
$UserRulesNotInspected = $Config.Configuration.FirewallRule |
Where-Object {($_.UserPolicy.ScanVirus -Eq "Disable" -OR $_.UserPolicy.ProxyMode -Eq "Disable" -OR $_.UserPolicy.DecryptHTTPS -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="GoogleQuic";expression={$($_.UserPolicy.BlockQuickQuic)}},
@{label="DPI";expression={$($_.UserPolicy.ScanVirus)}},
@{label="Sandstorm";expression={$($_.UserPolicy.Sandstorm)}},
@{label="Proxy";expression={$($_.UserPolicy.ProxyMode)}},
@{label="Decrypt";expression={$($_.UserPolicy.DecryptHTTPS)}}
WriteUserReport $UserRulesNotInspected

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING SANDSTORM
WriteNetworkReport "Not Using Sandstorm On"
$UserRulesNoSandstorm = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Sandstorm -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Sandstorm";expression={$($_.UserPolicy.Sandstorm)}}
WriteUserReport $UserRulesNoSandstorm

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING APPLICATION CONTROL
WriteNetworkReport "Not Using App Control On"
$UserRulesNoAppC = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
WriteUserReport $UserRulesNoAppC

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING IPS
WriteNetworkReport "Not Using IPS On"
$UserRulesNoIPS = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
WriteUserReport $UserRulesNoIPS

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING SYNC SEC
WriteNetworkReport "Not Using Sync Sec"
$UserRulesNoSyncSec = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
Select-Object -Property Name, Status,
@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}}
WriteUserReport $UserRulesNoSyncSec

### ANALYZE USER TRAFFIC DESTINED FOR DMZ MISSING LOGGING
WriteUserReport "Not Logging On"
$UserRulesNotLoggedDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
WriteUserReport $UserRulesNotLoggedDMZ

### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT FILTERING PORTS
WriteUserReport "Not Filtering Ports On"
$UserRulesNoPortFilterDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Services";expression={$($_.UserPolicy.Services)}}
WriteUserReport $UserRulesNoPortFilterDMZ

### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING APPLICATION CONTROL
WriteUserReport "Not Using App Control On"
$UserRulesNoAppCDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
WriteUserReport $UserRulesNoAppCDMZ

## ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING IPS
WriteUserReport "Not Using IPS On"
$UserRulesNoIPSDMZ = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
WriteUserReport $UserRulesNoIPSDMZ

### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING SYNC SEC
WriteUserReport "Not Using Sync Sec"
$UserRulesNoSyncSecDMZ = $Config.Configuration.FirewallRule |
Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat) -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.UserPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.UserPolicy.MinimumDestinationHBPermitted)}} 
WriteUserReport $UserRulesNoSyncSecDMZ

### ANALYZE USER TRAFFIC DESTINED FOR LAN MISSING LOGGING
WriteUserReport "Not Logging On"
$UserRulesNotLoggedLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
WriteUserReport $UserRulesNotLoggedLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT FILTERING PORTS
WriteUserReport "Not Filtering Ports On"
$UserRulesNoPortFilterLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="Services";expression={$($_.UserPolicy.Services)}}
WriteUserReport $UserRulesNoPortFilterLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING APPLICATION CONTROL
WriteUserReport "Not Using App Control On"
$UserRulesNoAppCLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
WriteUserReport $UserRulesNoAppCLAN

## ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING IPS
WriteUserReport "Not Using IPS On"
$UserRulesNoIPSLAN = $Config.Configuration.FirewallRule |
Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
WriteUserReport $UserRulesNoIPSLAN

### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING SYNC SEC
WriteUserReport "Not Using Sync Sec"
$UserRulesNoSyncSecLAN = $Config.Configuration.FirewallRule |
Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat) -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
Select-Object -Property Name, Status,
@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}},
@{label="DestHB";expression={$($_.UserPolicy.DestSecurityHeartbeat)}},
@{label="DestHB_Perm";expression={$($_.UserPolicy.MinimumDestinationHBPermitted)}} 
WriteUserReport $UserRulesNoSyncSecLAN

###### HTTP RULE TYPE ###### -- NEEDS FINISHED

### WRITE TO HTTP RESULTS FILE FUNCTION -- NEEDS FINISHED
$HTTPAnalyzerResults= "C:\SFOS_Analyzer\HTTPRuleResults.txt"
function WriteUserReport ($message)
{
$message >> $HTTPAnalyzerResults
}

### CHECK NAT RULES -- NEEDS FINISHED
$NATRuleList = $Config.Configuration.NATRule  | Select-Object -Property Name, Description, Status, LinkedFirewallRule, TranslatedDestination, TranslatedService,
@{label="OutboundInterface";expression={$($_.OutboundInterfaces.Interface)}},
OverrideInterfaceNATPolicy, TranslatedSource

### WRITE TO SSL/TLS RESULTS FILE FUNCTION -- NEEDS FINISHED
$TLSAnalyzerResults= "C:\SFOS_Analyzer\UserRuleResults.txt"
function WriteUserReport ($message)
{
$message >> $TLSAnalyzerResults
}

### CHECK TLS/SSL RULES -- NEEDS FINISHED
$TLSRuleList = $Config.Configuration.NATRule  | Select-Object -Property Name, Description, Status, LinkedFirewallRule, TranslatedDestination, TranslatedService,
@{label="OutboundInterface";expression={$($_.OutboundInterfaces.Interface)}},
OverrideInterfaceNATPolicy, TranslatedSource
