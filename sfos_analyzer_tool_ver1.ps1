#### READ EXPORTED XML FROM SFOS v18 ####
[xml]$Config = Get-Content "C:\SFOS_Analyzer\Entities.xml"

#########
# SFOS
# ADMINISTRATIVE
# SETTINGS
#########

### METHOD TO WRITE WAN NETWORK RESULTS FILE FUNCTION ###
$AdminSettings= "C:\SFOS_Analyzer\AdminSettingsResults.txt"
function WriteAdminReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $AdminSettings -Append
}

#### METHOD TO WRITE WAN NETWORK RESULTS SECTION BREAKS ###
function WriteAdminHeader ($text)
{
$text | Out-File -FilePath $AdminSettings -Append
}

###### CHECK ADMIN LOGGING SETTINGS #####
if ($Config.Configuration.AdminSettings | Where-Object {$_.LoginSecurity.BlockLogin -Eq "Disable"}) 
	{$AdminLoginSettings = $Config.Configuration.AdminSettings | Where-Object {$_.LoginSecurity.BlockLogin -Eq "Disable"} | 
		Select-Object @{label="BlockLogin";expression={$($_.LoginSecurity.BlockLogin)}},
		@{label="FailedAttempts";expression={$($_.LoginSecurity.BlockLoginSettings.UnsucccessfulAttempt)}},
		@{label="Interval(seconds)";expression={$($_.LoginSecurity.BlockLoginSettings.Duration)}},
		@{label="ForMinutes";expression={$($_.LoginSecurity.BlockLoginSettings.ForMinutes)}}
		WriteAdminHeader "--YOUR SFOS HAS IS NOT BLOCKING FAILED LOGINS--"
		WriteAdminReport $AdminLoginSettings}
		
if ($Config.Configuration.AdminSettings | Where-Object {$_.PasswordComplexitySettings.PasswordComplexityCheck -Eq "Disable"}) 
	{$AdminLoginSettings = $Config.Configuration.AdminSettings | Where-Object {$_.PasswordComplexitySettings.PasswordComplexityCheck -Eq "Disable"} | 
		Select-Object @{label="PasswordComplexity";expression={$($_.PasswordComplexitySettings.PasswordComplexityCheck)}},
		@{label="RequiredLength";expression={$($_.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLength)}},
		@{label="AlphaChars";expression={$($_.PasswordComplexitySettings.PasswordComplexity.IncludeAlphabeticCharacters)}},
		@{label="NumericChars";expression={$($_.PasswordComplexitySettings.PasswordComplexity.IncludeNumericCharacter)}},
		@{label="SpecialChars";expression={$($_.PasswordComplexitySettings.PasswordComplexity.IncludeSpecialCharacter)}},
		WriteAdminHeader "--YOUR SFOS DOES NOT REQUIRE A COMPLEX ADMIN PASSWORD--"
		WriteAdminReport $AdminLoginSettings}
		
if ($Config.Configuration.AdminSettings | Where-Object {$_.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLengthValue -lt 12}) 
	{$AdminLoginSettings = $Config.Configuration.AdminSettings | Where-Object {$_.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLengthValue -lt 12} | 
		Select-Object @{label="MinimumLength";expression={$($_.PasswordComplexitySettings.PasswordComplexity.MinimumPasswordLengthValue)}}
		WriteAdminHeader "--YOUR SFOS MINIMUM PASSWORD IS LESS THAN 12--"
		WriteAdminReport $AdminLoginSettings}

else {WriteAdminHeader "--Your SFOS Admin login settings are properly configured--"}

##### CHECK HOTFIX #####
if ($Config.Configuration.Hotfix | Where-Object {$_.AllowAutoInstallOfHotFixes -Eq "Disable"})
	{$HotfixSetting = $Config.Configuration.Hotfix | Where-Object {$_.AllowAutoInstallOfHotFixes -Eq "Disable"} |
		Select-Object @{label="AllowHotFix";expression={$($_.AllowAutoInstallOfHotFixes)}}
		WriteAdminHeader "--YOUR SFOS IS NOT ALLOWING HOTFIXES--"
		WriteAdminReport $HotfixSetting}
		
else {WriteAdminheader "--Your SFOS is properly allowing hotfixes--"}
	
##### CHECK CENTRAL MANAGEMENT #####
if ($Config.Configuration.CentralManagement | Where-Object {$_.ManagementType -Ne "central"})
	{$CentralManagement = $Config.Configuration.CentralManagement | Where-Object {$_.ManagementType -Ne "central"} |
		Select-Object @{label="ManagementType";expression={$($_.ManagementType)}}
		WriteAdminHeader "--YOUR SFOS IS NOT MANAGED BY SOPHOS CENTRAL--"
		WriteAdminReport $CentralManagement}
		
else {WriteAdminHeader "--Your SFOS is properly managed through Sophos Centra--"}

#########
# SFOS
# AUTHENTICATION
# SETTINGS
#########

### METHOD TO WRITE WAN NETWORK RESULTS FILE FUNCTION ###
$AuthSettings= "C:\SFOS_Analyzer\AuthSettingsResults.txt"
function WriteAuthReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $AuthSettings -Append
}

### METHOD TO WRITE WAN NETWORK RESULTS SECTION BREAKS ###
function WriteAuthHeader ($text)
{
$text | Out-File -FilePath $AuthSettings -Append
}

##### CHECK AUTHENTICATION SERVERS ####
if ($Config.Configuration.AuthenticationServer.ActiveDirectory | Where-Object {$_.Port -Eq "389"})
	{$AuthenticationSettings = $Config.Configuration.AuthenticationServer.ActiveDirectory | Where-Object {$_.Port -Eq "389"} |
		Select-Object @{label="Port";expression={$($_.Port)}}
		WriteAuthHeader "--YOUR SFOS IS USING INSECURE AUTHENTICATION SERVERS--"
		WriteAuthReport $AuthenticationSettings}
		
else {WriteAdminHeader "--Your SFOS is properly using secure authentication ports--"}

#########
# WAN
# NETWORK 
# RULE 
# TYPE 
#########

### METHOD TO WRITE WAN NETWORK RESULTS FILE FUNCTION ###
$WANAnalyzerResults= "C:\SFOS_Analyzer\NetworkWANRuleResults.txt"
function WriteNetworkReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $WANAnalyzerResults -Append
}

### METHOD TO WRITE WAN NETWORK RESULTS SECTION BREAKS ###
function WriteSectionHeader ($text)
{
$text | Out-File -FilePath $WANAnalyzerResults -Append
}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN MISSING LOGGING ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNotLogged = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
		WriteNetworkReport $NetworkRulesNotLogged}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT FILTERING PORTS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNoPortFilter = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="Services";expression={$($_.NetworkPolicy.Services)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
		WriteNetworkReport $NetworkRulesNoPortFilter}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC USING PROXY #####
if ($Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.ProxyMode -Eq "Disable" -OR $_.NetworkPolicy.DecryptHTTPS -Eq "Disable") -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNotInspected = $Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.ProxyMode -Eq "Disable" -OR $_.NetworkPolicy.DecryptHTTPS -Eq "Disable") -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="GoogleQuic";expression={$($_.NetworkPolicy.BlockQuickQuic)}},
		@{label="Proxy";expression={$($_.NetworkPolicy.ProxyMode)}},
		@{label="Decrypt";expression={$($_.NetworkPolicy.DecryptHTTPS)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT INSPECTING TRAFFIC ON PROXY MODE--"
		WriteNetworkReport $NetworkRulesNotInspected}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC USING DPI ENGINE ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.ScanVirus -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNotInspectedDPI = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.ScanVirus -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="GoogleQuic";expression={$($_.NetworkPolicy.BlockQuickQuic)}},
		@{label="DPI";expression={$($_.NetworkPolicy.ScanVirus)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT INSPECTING TRAFFIC WITH DPI ENGINE--"
		WriteNetworkReport $NetworkRulesNotInspectedDPI}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING SANDSTORM ####
if ($Config.Configuration.FirewallRule |Where-Object {($_.NetworkPolicy.Sandstorm -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN")})
	{$NetworkRulesNoSandstorm = $Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.Sandstorm -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN")} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="Sandstorm";expression={$($_.NetworkPolicy.Sandstorm)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING SANDSTORM--"
		WriteNetworkReport $NetworkRulesNoSandstorm}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING APPLICATION CONTROL ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.ApplicationControl -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNoAppC = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.ApplicationControl -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
		WriteNetworkReport $NetworkRulesNoAppC}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNoIPS = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
		WriteNetworkReport $NetworkRulesNoIPS}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR WAN NOT USING SYNC SEC ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"})
	{$NetworkRulesNoSyncSec = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
		@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}}
		WriteSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
		WriteNetworkReport $NetworkRulesNoSyncSec}

else {WriteSectionHeader "Your network rules destined for WAN are well configured."}

#########
# DMZ
# NETWORK 
# RULE 
# TYPE 
#########

#### METHOD TO WRITE DMZ NETWORK RESULTS FILE FUNCTION ####
$DMZAnalyzerResults= "C:\SFOS_Analyzer\NetworkDMZRuleResults.txt"
function WriteDMZReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $DMZAnalyzerResults -Append
}

#### METHOD TO WRITE DMZ NETWORK RESULTS SECTION BREAKS ####
function WriteDMZSectionHeader ($text)
{
$text | Out-File -FilePath $DMZAnalyzerResults -Append
}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ MISSING LOGGING ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$NetworkRulesNotLoggedDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
		WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
		WriteDMZReport $NetworkRulesNotLoggedDMZ}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT FILTERING PORTS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$NetworkRulesNoPortFilterDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="Services";expression={$($_.NetworkPolicy.Services)}}
		WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
		WriteDMZReport $NetworkRulesNoPortFilterDMZ}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING APPLICATION CONTROL ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Application -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$NetworkRulesNoAppCDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Application -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
		WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
		WriteDMZReport $NetworkRulesNoAppCDMZ}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$NetworkRulesNoIPSDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
		WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
		WriteDMZReport $NetworkRulesNoIPSDMZ}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR DMZ NOT USING SYNC SEC ####
if ($Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat) -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$NetworkRulesNoSyncSecDMZ = $Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat) -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
		@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}},
		@{label="DestHB";expression={$($_.NetworkPolicy.DestSecurityHeartbeat)}},
		@{label="DestHB_Perm";expression={$($_.NetworkPolicy.MinimumDestinationHBPermitted)}} 
		WriteDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
		WriteDMZReport $NetworkRulesNoSyncSecDMZ}

else {WriteDMZSectionHeader "Your SFOS DMZ rules are properly configured"}

#########
# LAN
# NETWORK 
# RULE 
# TYPE 
#########

#### METHOD TO WRITE LAN NETWORK RESULTS FILE FUNCTION ####
$LANAnalyzerResults= "C:\SFOS_Analyzer\NetworkLANRuleResults.txt"
function WriteLANReport ($results)
{
($results | Format-List | Out-String) | Out-File -Filepath $LANAnalyzerResults -Append
}

#### METHOD TO WRITE LAN NETWORK RESULTS SECTION BREAKS ####
function WriteLANSectionHeader ($text)
{
$text | Out-File -FilePath $LANAnalyzerResults -Append
}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN MISSING LOGGING ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"})
	{$NetworkRulesNotLoggedLAN = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.LogTraffic -Eq "Disable" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="LoggingStatus";expression={$($_.NetworkPolicy.LogTraffic)}}
		WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
		WriteLANReport $NetworkRulesNotLoggedLAN}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT FILTERING PORTS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"})
	{$NetworkRulesNoPortFilterLAN = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Services -Eq $null -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="Services";expression={$($_.NetworkPolicy.Services)}}
		WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
		WriteLANReport $NetworkRulesNoPortFilterLAN}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING APPLICATION CONTROL ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Application -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"})
	{$NetworkRulesNoAppCLAN = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.Application -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="AppControl";expression={$($_.NetworkPolicy.ApplicationControl)}}
		WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
		WriteLANReport $NetworkRulesNoAppCLAN}

#### ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"})
	{$NetworkRulesNoIPSLAN = $Config.Configuration.FirewallRule | Where-Object {$_.NetworkPolicy.IntrusionPrevention -Eq "None" -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="IPS";expression={$($_.NetworkPolicy.IntrusionPrevention)}}
		WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
		WriteLANReport $NetworkRulesNoIPSLAN}

###ANALYZE NETWORK TRAFFIC DESTINED FOR LAN NOT USING SYNC SEC ####
if ($Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat -Eq "Disable") -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"})
	{$NetworkRulesNoSyncSecLAN = $Config.Configuration.FirewallRule | Where-Object {($_.NetworkPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.NetworkPolicy.DestSecurityHeartbeat -Eq "Disable") -AND $_.NetworkPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.NetworkPolicy.Action)}}, 
		@{label="SourceHB";expression={$($_.NetworkPolicy.SourceSecurityHeartbeat)}},
		@{label="SourceHB_Perm";expression={$($_.NetworkPolicy.MinimumSourceHBPermitted)}},
		@{label="DestHB";expression={$($_.NetworkPolicy.DestSecurityHeartbeat)}},
		@{label="DestHB_Perm";expression={$($_.NetworkPolicy.MinimumDestinationHBPermitted)}} 
		WriteLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
		WriteLANReport $NetworkRulesNoSyncSecLAN}

else {WriteLANSectionHeader "--Your SFOS LAN rules are property configured--"}

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

#### ANALYZE USER TRAFFIC DESTINED FOR WAN MISSING LOGGING ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNotLogged = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
		WriteUserWANReport $UserRulesNotLogged} 

#### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT FILTERING PORTS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNoPortFilter = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="Services";expression={$($_.UserPolicy.Services)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
		WriteUserWANReport $UserRulesNoPortFilter}

#### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC USING PROXY MODE ####
if ($Config.Configuration.FirewallRule | Where-Object {( $_.UserPolicy.ProxyMode -Eq "Disable" -OR $_.UserPolicy.DecryptHTTPS -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"}) 
	{$UserRulesNotInspected = $Config.Configuration.FirewallRule | Where-Object {($_.UserPolicy.ProxyMode -Eq "Disable" -OR $_.UserPolicy.DecryptHTTPS -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |	
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="GoogleQuic";expression={$($_.UserPolicy.BlockQuickQuic)}},
		@{label="Proxy";expression={$($_.UserPolicy.ProxyMode)}},
		@{label="Decrypt";expression={$($_.UserPolicy.DecryptHTTPS)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT INSPECTING TRAFFIC ON PROXY--"
		WriteUserWANReport $UserRulesNotInspected}

#### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT INSPECTING TRAFFIC USING DPI ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.ScanVirus -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNotInspectedDPI = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.ScanVirus -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="GoogleQuic";expression={$($_.UserPolicy.BlockQuickQuic)}},
		@{label="DPI";expression={$($_.UserPolicy.ScanVirus)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT INSPECTING TRAFFIC ON DPI--"
		WriteUserWANReport $UserRulesNotInspectedDPI}

#### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING SANDSTORM ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Sandstorm -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNoSandstorm = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Sandstorm -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="Sandstorm";expression={$($_.UserPolicy.Sandstorm)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SANDSTORM--"
		WriteUserWANReport $UserRulesNoSandstorm}

#### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING APPLICATION CONTROL ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNoAppC = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
		WriteUserWANReport $UserRulesNoAppC}
		
#### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNoIPS = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
		WriteUserWANReport $UserRulesNoIPS}

### ANALYZE USER TRAFFIC DESTINED FOR WAN NOT USING SYNC SEC ###
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"})
	{$UserRulesNoSyncSec = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "WAN"} |
		Select-Object -Property Name, Status,
		@{label="UserPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
		@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}}
		WriteUserWANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
		WriteUserWANReport $UserRulesNoSyncSec}
		
else {"--Your SFOS User WAN rules are properly configured--"}

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

#### ANALYZE USER TRAFFIC DESTINED FOR DMZ MISSING LOGGING ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$UserRulesNotLoggedDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
		WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
		WriteUserDMZReport $UserRulesNotLoggedDMZ}

#### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT FILTERING PORTS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$UserRulesNoPortFilterDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="Services";expression={$($_.UserPolicy.Services)}}
		WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
		WriteUserDMZReport $UserRulesNoPortFilterDMZ}

#### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING APPLICATION CONTROL ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$UserRulesNoAppCDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
		WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL-"
		WriteUserDMZReport $UserRulesNoAppCDMZ}

#### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$UserRulesNoIPSDMZ = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
		WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
		WriteUserDMZReport $UserRulesNoIPSDMZ}

#### ANALYZE USER TRAFFIC DESTINED FOR DMZ NOT USING SYNC SEC ####
if ($Config.Configuration.FirewallRule | Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"})
	{$UserRulesNoSyncSecDMZ = $Config.Configuration.FirewallRule | Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "DMZ"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
		@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}},
		@{label="DestHB";expression={$($_.UserPolicy.DestSecurityHeartbeat)}},
		@{label="DestHB_Perm";expression={$($_.UserPolicy.MinimumDestinationHBPermitted)}} 
		WriteUserDMZSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
		WriteUserDMZReport $UserRulesNoSyncSecDMZ}
		
else {WriteUserDMZSectionHeader "--Your SFOS DMZ User rules are properly configured--"}

#########
# LAN
# USER
# RULE 
# TYPE 
#########

### METHOD TO WRITE USER LAN RESULTS FILE FUNCTION ###
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

#### ANALYZE USER TRAFFIC DESTINED FOR LAN MISSING LOGGING ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"})
	{$UserRulesNotLoggedLAN = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.LogTraffic -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="LoggingStatus";expression={$($_.UserPolicy.LogTraffic)}}
		WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT LOGGING--"
		WriteUserLANReport $UserRulesNotLoggedLAN}

#### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT FILTERING PORTS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"})
	{$UserRulesNoPortFilterLAN = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Services -Eq " " -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="Services";expression={$($_.UserPolicy.Services)}}
		WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT FILTERING PORTS--"
		WriteUserLANReport $UserRulesNoPortFilterLAN}

#### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING APPLICATION CONTROL ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"})
	{$UserRulesNoAppCLAN = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.Application -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="AppControl";expression={$($_.UserPolicy.ApplicationControl)}}
		WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING APP CONTROL--"
		WriteUserLANReport $UserRulesNoAppCLAN}

#### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"})
	{$UserRulesNoIPSLAN = $Config.Configuration.FirewallRule | Where-Object {$_.UserPolicy.IntrusionPrevention -Eq "Disable" -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="IPS";expression={$($_.UserPolicy.IntrusionPrevention)}}
		WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING IPS--"
		WriteUserLANReport $UserRulesNoIPSLAN}

#### ANALYZE USER TRAFFIC DESTINED FOR LAN NOT USING SYNC SEC ####
if ($Config.Configuration.FirewallRule | Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"})
	{$UserRulesNoSyncSecLAN = $Config.Configuration.FirewallRule | Where-Object {($_.UserPolicy.SourceSecurityHeartbeat -Eq "Disable" -OR $_.UserPolicy.DestSecurityHeartbeat -Eq "Disable") -AND $_.UserPolicy.DestinationZones.Zone -Eq "LAN"} |
		Select-Object -Property Name, Status,
		@{label="NetworkPolicy";expression={$($_.UserPolicy.Action)}}, 
		@{label="SourceHB";expression={$($_.UserPolicy.SourceSecurityHeartbeat)}},
		@{label="SourceHB_Perm";expression={$($_.UserPolicy.MinimumSourceHBPermitted)}},
		@{label="DestHB";expression={$($_.UserPolicy.DestSecurityHeartbeat)}},
		@{label="DestHB_Perm";expression={$($_.UserPolicy.MinimumDestinationHBPermitted)}} 
		WriteUserLANSectionHeader "--THE FOLLOWING RULES ARE NOT USING SYNC SEC--"
		WriteUserLANReport $UserRulesNoSyncSecLAN}

else {WriteUserLANSectionHeader "--Your SFOS User LAN rules are properly configured--"}

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

#### ANALYZE WAF RULE RUNNING ON INSECURE PORT ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.HTTPBasedPolicy.HTTPS -Eq "Disable"})
	{$HTTPProtectionResults = $Config.Configuration.FirewallRule | Where-Object {$_.HTTPBasedPolicy.HTTPS -Eq "Disable"} |
		Select-Object -Property Name, Status,
		@{label="HTTPS";expression={$($_.HTTPBasedPolicy.HTTPS)}}, 
		@{label="ListeningPort";expression={$($_.HTTPBasedPolicy.ListenPort)}},
		@{label="Domains";expression={$($_.HTTPBasedPolicy.Domains.Domain)}},
		@{label="Redirected";expression={$($_.HTTPBasedPolicy.RedirectHTTP)}}
		WriteHTTPSectionHeader "--THE FOLLOWING RULES ARE RUNNING ON AN INSECURE PORT--"
		WriteHTTPReport $HTTPProtectionResults}

### ANALYZE WAF RULE NOT USING PROTOCOL SECURITY ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.HTTPBasedPolicy.ProtocolSecurity -Eq "None"})
	{$HTTPProtectionResults = $Config.Configuration.FirewallRule | Where-Object {$_.HTTPBasedPolicy.ProtocolSecurity -Eq "None"} | 
		Select-Object -Property Name, Status,
		@{label="Protection";expression={$($_.HTTPBasedPolicy.ProtocolSecurity)}}
		WriteHTTPSectionHeader "--THE FOLLOWING RULES ARE MISSING A SECURITY TEMPLATE--"
	WriteHTTPReport $HTTPProtectionResults}

#### ANALYZE WAF RULE NOT USING IPS ####
if ($Config.Configuration.FirewallRule | Where-Object {$_.HTTPBasedPolicy.IntrusionPrevention -Eq "None"})
	{$HTTPProtectionResults = $Config.Configuration.FirewallRule | Where-Object {$_.HTTPBasedPolicy.IntrusionPrevention -Eq "None"} |
		Select-Object -Property Name, Status,
		@{label="IPS";expression={$($_.HTTPBasedPolicy.IntrusionPrevention)}}
		WriteHTTPSectionHeader "--THE FOLLOWING RULES ARE MISSING AN IPS POLICY--"
		WriteHTTPReport $HTTPProtectionResults}
