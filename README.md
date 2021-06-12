# Sophos Firewall Analyzer Tool v1.0

## Purpose

Constantly grooming your firewall policies can be troublesome, especially for large organizations that have hundreds of rules. This tool works to save you time and ensure one is following best practices or at least considering potential weaknesses. This is my **FIRST ATTEMPT** at writing a script to function more as a program - so feedback is welcomed and appreciated to improve its functionality. Later versions will include an HTML formatted report of the results. For now, logs will need interpreted.

## Instructions

Download the script and create a folder in your C:\ titled "SFOS_Analyzer." You can run the script from anyone on the machine and should function just fine.

Head into your Sophos XG or XGS console and perform the following:

1) Navigate to System > Backup & Firmware > Import Export
2) Under "Export", ensure "Export full configuration" is selected and click "Export"
3) Extract the tar file using 7Zip or another tool of your choosing
4) Find the file name "Entities.xml" and copy it to your SFOS_Analyzer folder previously created
5) Run the script and review the results

### Interpreting The Results
