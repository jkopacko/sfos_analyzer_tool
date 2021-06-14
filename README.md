# Sophos Firewall Analyzer Tool v1.0

## Purpose

Constantly grooming your firewall policies can be troublesome, especially for large organizations that have hundreds of rules. This tool works to save you time and ensure one is following best practices or at least considering potential weaknesses. This is my **FIRST ATTEMPT** at writing a script to function more as a program - so feedback is welcomed and appreciated to improve its functionality. Later versions will include an HTML formatted report of the results. For now, logs will need interpreted.

## Instructions

### On your Windows Workstation: 

1) Create a folder in your C:\ titled "SFOS_Analyzer." 
2) Download the sfos_analyzer_tool_v1 script
3) Place the script within C:\SFOS_Analyzer

**You can run the script from anyone on the machine and should function just fine but for my steps, it assumes your ps1 file is within this folder.**

### Head into your Sophos XG or XGS console and perform the following:

1) Navigate to System > Backup & Firmware > Import Export
2) Under "Export", ensure "Export full configuration" is selected and click "Export"
3) Extract the tar file using 7Zip or another tool of your choosing
4) Find the file name "Entities.xml" and copy it to your SFOS_Analyzer folder previously created
5) Open Powershell as Administrator
6) Type `cd C:\SFOS_Analyzer`
7) Type `sfos_analyzer_tool_v1.ps1 -windowstyle hidden`

**NOTE: I hate seeing the console throwing code**

### Interpreting The Results

| Log Name | Description |
| --- | --- |
| AdminSettingsResults | Reviews Login Settings, Hotfix & Central Mgmt Status |
| AuthSettingsResults | Review Active Directory Auth Port |
| HTTPRuleResults | Reviews WAF rules |
| NetworkDMZRuleResults | Reviews network rules destined for the DMZ Zone |
| NetworkLANRuleResults | Reviews network rules destined for the LAN Zone |
| NetworkWANRuleResults | Review network rules destined for the WAN Zone |
| UserDMZRuleResults | Reviews user rules destined for the DMZ Zone |
| UserLANRuleResults | Reviews user rules destined for the LAN Zone |
| UserWANResults | Reviews user rules destined for the WAN Zone |


**NOTE: These are all .txt files**
