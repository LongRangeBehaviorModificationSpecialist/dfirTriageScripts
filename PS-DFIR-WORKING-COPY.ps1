<# EDITED BY : mikespon  |  DLU : 2021-12-12 #>

<# To return a the current date/time as a string in UTC time, use:

>>  [DateTime]::UtcNow.ToString('u') will return:
   '2023-09-19 15:09:45Z'

>>  [DateTime]::UtcNow.ToString('u').Replace('Z','UTC') will return:
    '2023-09-19 15:09:45UTC'

>>  (Get-Date).ToUniversalTime() will return:
    'Tuesday, September 19, 2023 3:13:37 PM'

To get just the hours, min, and seconds in UTC time, use:
>>  (Get-Date).ToUniversalTime().ToString("HHmmss") will return:
   '151337'
#>

# Getting the computer name
$computerName = $env:computername
# Getting the username of the currently logged on user
$userName = (Get-Item env:\USERNAME).value

# Assigning variables to use in the script
$header = "<title>$computerName.$userName Triage Data</title> 
<style>
    * {font-family:Arial, Helvetica, sans-serif;}
    h1 {color:#e68a00; font-size:28px;}
    h2 {color:#000099; font-size:1.35em;}
    .data {font-family:'Times New Roman'; font-weight:bold; color:#f00; font-size:1.20em;}
    table {font-size:1.05em; border:0px;}
    td {padding:4px; margin:0px; border:0; font-size:1.05em;}
    th {background:#395870; background:linear-gradient(#49708f, #293f50); color:#fff; font-size:1.05em; text-transform:uppercase; padding:10px 15px; vertical-align:middle;}
    tbody tr:nth-child(even) {background:#f0f0f2;}
    .RunningStatus {color:#008000; font-weight:bold;}
    .StopStatus {color:#ff0000; font-weight:bold;}
    #CreationDate {color:#ff3300; font-size:12px;}
    .dropbtn {color:#fff; background-color:#007bff; border-color:#007bff; padding:16px; font-size:16px; border:none; width:auto;}
    .dropdown {position:relative; display:inline-block; width:auto;}
    .dropdown-content {display:none; width:auto; height:30rem; overflow-y:scroll; position:absolute; background-color:#f1f1f1; box-shadow:0px 8px 16px 0px rgba(0,0,0,0.2); z-index:1; white-space:nowrap;}
    .dropdown-content a {color:#212529; padding:12px 16px; text-decoration:none; display:block;}
    .dropdown-content a:hover {color:#fff; background-color:#3492d1;}
	.dropdown-content a:active {color:#fff; background-color:#007bff;}
    .dropdown:hover .dropdown-content {display:block; width:auto;}
    .dropdown:hover .dropbtn {background-color:#03366d }
	.dropdown-item {color:#212529; white-space:nowrap; background-color:transparent; border:0px;}
    .top {display:inline; font-size:12px; color:dodgerblue }
</style>"

$quickLinks = "
<div class='dropdown'>
    <button class='dropbtn'>Jump to Section</button>
    <div class='dropdown-content'>
        <a href='#RegActiveSetupInstalls'>Active Setup Installs</a>
        <a href='#RegAppPathKeys'>APP Paths Keys</a>
        <a href='#RegAppCertDLLs'>AppCert DLLs</a>
        <a href='#RegAppInit'>AppInit_DLLs</a>
        <a href='#AppInventoryEvents'>Application Inventory Events</a>
        <a href='#RegApprovedShellExts'>Approved Shell Extentions</a>
        <a href='#AuditPolicy'>Audit Policy</a>
        <a href='#RegBCDRelated'>BCD Related</a>
        <a href='#RegBrowserHelperObjects'>Browser Helper Objects</a>
        <a href='#RegBrowserHelperObjectsx64'>Browser Helper Objects 64 Bit</a>
        <a href='#CompressedFiles'>Compressed Files</a>
        <a href='#CompInfo'>Computer Information</a>
        <a href='#RegAddressBarHistory'>Desktop Address Bar History</a>
        <a href='#DiskPart'>Disk Partition Information</a>
        <a href='#Last50dlls'>.dll files (last 50 created)</a>
        <a href='#RegLoadedDLLs'>DLLs Loaded by Explorer.exe Shell</a>
        <a href='#DNSCache'>DNS Cache</a>
        <a href='#DownloadedExeFiles'>Downloaded Executable Files</a>
        <a href='#EncryptedFiles'>Encrypted Files</a>
        <a href='#EnvVars'>Environment Variables</a>
        <a href='#EventLog4625'>Event Log - Account Failed To Log On (ID: 4625)</a>
        <a href='#EventLog4624'>Event Log - Account Logon (ID: 4624)</a>
        <a href='#EventLog1002'>Event Log - Application Crashes (ID: 1002)</a>
        <a href='#EventLog1102'>Event Log - Audit Log was Cleared (ID: 1102)</a>
        <a href='#EventLog1014'>Event Log - DNS Failed Resolution Events (ID: 1014)</a>
        <a href='#EventLog4648'>Event Log - Logon Was Attempted Using Explicit Credentials (ID: 4648)</a>
        <a href='#EventLog4673'>Event Log - Privilege Use (ID: 4673)</a>
        <a href='#EventLog4674'>Event Log - Privilege Use (ID: 4674)</a>
        <a href='#EventLog4688'>Event Log - Process Execution (ID: 4688)</a>
        <a href='#EventLog7036'>Event Log - Service Control Manager Events (ID: 7036)</a>
        <a href='#EventLog7045'>Event Log - Service Creation (ID: 7045)</a>
        <a href='#EventLog4672'>Event Log - Special Logon (ID: 4672)</a>
        <a href='#EventLog4616'>Event Log - System Time Was Changed (ID: 4616)</a>
        <a href='#EventLog4720'>Event Log - User Account Was Created (ID: 4720)</a>
        <a href='#EventLog64001'>Event Log - WFP Events (ID: 64001)</a>
        <a href='#RegEXEFileShell'>EXE File Shell Command</a>
        <a href='#FileTimelineExeFiles'>File Timeline Executable Files (Past 30 Days)</a>
        <a href='#HotFixes'>Hot Fixes</a>
        <a href='#RegIEExtensionsFromHKCU'>IE Extensions from HKCU</a>
        <a href='#RegIEExtensionsFromHKLM'>IE Extensions from HKLM</a>
        <a href='#RegIEExtensionsFromWow'>IE Extensions from Wow6432Node</a>
        <a href='#InstalledApps'>Installed Applications</a>
        <a href='#Cookies'>Internet Cookies</a>
        <a href='#RegInternetSettings'>Internet Settings</a>
        <a href='#RegTrustedDomains'>Internet Trusted Domains</a>
        <a href='#LinkFiles'>Link File Analysis - Last 5 days</a>
        <a href='#RegLSAPackages'>LSA Packages Loaded</a>
        <a href='#Logs'>Log Files</a>
        <a href='#LogonSessions'>Logon Sessions</a>
        <a href='#MappedDrives'>Mapped Drives</a>
        <a href='#Netstat'>Netstat Innformation</a>
        <a href='#NetTCP'>NetTCP Connections</a>
        <a href='#NetworkConfig'>Network Configuration Info</a>
        <a href='#OpenShares'>Open Shares</a>
        <a href='#PhyMem'>Physical Memory Information</a>
        <a href='#Prefetch'>Prefetch List</a>
        <a href='#RegProgramExecuted'>Programs Executed By Session Manager</a>
        <a href='#RegRunMRUKeys'>RunMRU Keys</a>
        <a href='#Drivers'>Running Drivers</a>
        <a href='#RunningProcesses'>Running Processes</a>
        <a href='#RunningServices'>Running Services</a>
        <a href='#RunningSVCHOSTs'>Running SVCHOSTs</a>
        <a href='#ScheduledJobs'>Scheduled Jobs</a>
        <a href='#ScheduledTaskEvents'>Scheduled Task Events</a>
        <a href='#RegSVCValues'>Security Center SVC Values</a>
        <a href='#ShadowCopy'>Shadow Copy List</a>
        <a href='#RegShellUserInit'>Shell and UserInit Values</a>
        <a href='#RegShellCommands'>Shell Commands</a>
        <a href='#RegShellFolders'>Shell Folders</a>
        <a href='#RegStartMenu'>Start Menu</a>
        <a href='#StartupApps1'>Startup Applications(1)</a>
        <a href='#StartupApps2'>Startup Applications(2)</a>
        <a href='#StartupApps3'>Startup Applications(3)</a>
        <a href='#StartupApps4'>Startup Applications(4)</a>
        <a href='#StartupApps5'>Startup Applications(5)</a>
        <a href='#StartupApps6'>Startup Applications(6)</a>
        <a href='#StartupApps7'>Startup Applications(7)</a>
        <a href='#SystemInfo-1'>System Information</a>
        <a href='#SystemInfo-2'>System Information (Additional)</a>
        <a href='#TempInternetFiles'>Temporary Internet Files</a>
        <a href='#TerminalServiceEvents'>Terminal Services Events</a>
        <a href='#TypedURLs'>Typed URLs</a>
        <a href='#RegUAC'>UAC Group Policy Settings</a>
        <a href='#USBDevices'>USB Devices</a>
        <a href='#UserAccount'>User Account</a>
        <a href='#AllUsers'>User Accounts (All)</a>
        <a href='#RegUserShellFolders'>User Shell Folders (Startup)</a>
    </div>
</div>"

$banner = "

******************************************************************
*   ____  _____ ___ ____      ____   ____ ____  ___ ____ _____   *
*  |  _ \|  ___|_ _|  _ \    / ___| / ___|  _ \|_ _|  _ \_   _|  *
*  | | | | |_   | || |_) |   \___ \| |   | |_) || || |_) || |    *
*  | |_| |  _|  | ||  _ <     ___) | |___|  _ < | ||  __/ | |    *
*  |____/|_|   |___|_| \_\   |____/ \____|_| \_\___|_|    |_|    *
*                                                                *
******************************************************************
"

# Getting date and time values to use in the naming of the output directory and the output .html file
$date = (Get-Date).ToString('yyyy-MM-dd')
$dirDate = Get-Date -Format yyyyMMdd_HHmmss
$titleTime = (Get-Date).ToString('HHmmss')
$time = (Get-Date).ToString("HHmmss' hrs '(K)' UTC'")
# $diff = $duration.ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
# Getting the fully qualified domain name of the current machine
$domainName = $env:userdnsdomain
# Getting the current IP address of the machine on which this script is run
$IP = Test-Connection $computerName -TimeToLive 2 -Count 1
$ip = $ip.ipv4address | Select-Object -ExpandProperty IPAddressToString
# Get the current working directory so the $outputFolder is stored in the same directory from which this script is executed
$cwd = Get-Location
# Naming the directory to store the results
$outputFolder = $dirDate + "_"+ $IP + "_"+ $computerName + $domainName
# Making the directory to store the results
$resultsFolder = New-Item -Path $cwd -Name $outputFolder -ItemType Directory
$ramFolder = New-Item -Path $resultsFolder -Name "RAM" -ItemType Directory
# Setting the name of the .html file to display the results
$resultsFile = "$computerName-$userName-$date-$titleTime.html"
$logFile = "$resultsFolder\Script.log"
# List of file types to use in commands
$executableFiles = @("*.EXE", "*.COM", "*.BAT", "*.BIN", "*.JOB", "*.WS", ".WSF", "*.PS1", ".PAF", "*.MSI", "*.CGI", "*.CMD", "*.JAR", "*.JSE", "*.SCR", "*.SCRIPT", "*.VB", "*.VBE", "*.VBS", "*.VBSCRIPT", "*.DLL")
$startTime = Get-Date
# Variable to ass the "Return to Top" link next to each header
$return = "<a href='#top' class='top'>(Return to Top)</a>"

# Clear the terminal screen before displaying the DFIR banner and instructions
Clear-Host

Write-Host $banner
Write-Host "Compiled by Michael Sponheimer
DLU: 2023-09-28

INSTRUCTIONS

1.  You are about to run the DFIR Powershell Script.
2.  This will gather information from the target machine and place most of the results into a .html file.
3.  There are three (3) prompts that will require your input at the beginning.
4.  DO NOT close any pop-up windows that appear.
5.  Other text files will be created used to document other data and settings.

"
Read-Host -Prompt "Press ENTER to run the DFIR Script"

$ssa = "`n$(Get-Date -Format "MM-dd-yyyy HH:mm:ss '('K UTC')'") -- Script execution started`n"
Write-Output $ssa >> $logFile


$dateFormat = "yyyy-MM-dd HH:mm:ss"
Write-Host `n$ssa`n  -ForegroundColor Yellow

# Having the user of the script enter some basic information to add to the report and the .log file
$operator = Read-Host -Prompt "Please enter your name for the report"
Write-Host ""
Write-Output "$(Get-Date -Format $dateFormat) -- Operator Name : $operator" >> $logFile
$agency = Read-Host -Prompt "Enter Agency Name"
Write-Host ""
Write-Output "$(Get-Date -Format $dateFormat) -- Agency Name : $agency" >> $logFile
$caseNumber = Read-Host -Prompt "Enter Case Number"
Write-Host ""
Write-Output "$(Get-Date -Format $dateFormat) -- Case Number : $caseNumber" >> $logFile

# RAM Acquisition Execution
$getRAM = Read-Host -Prompt "Do you want to collect the computer's RAM? (Enter 'y' or 'n')"

# If the user wants to collect the RAM
if ($getRAM -eq 'y')
{
    Write-Host "`n$(Get-Date -Format $dateFormat) -- RAM acquisition has begun. Please wait..." -ForegroundColor Yellow
    # Start the process to acquire RAM from the current machine
    Start-Process -NoNewWindow -FilePath ".\bin\MagnetRAMCapture.exe" -ArgumentList "/accepteula /go /silent" -Wait
    # Once the RAM has been acquired, move the file to the RAM folder
    Move-Item -Path .\bin\*.raw -Destination $ramFolder
    # Get the name of the acquired RAM .raw file
    $ramFileName = (Get-ChildItem -Path $ramFolder\*.raw).Name
    # Get the SHA1 hash value of the acquired RAM .raw file
    $ramHashValue = (Get-FileHash $ramFolder\*.raw -Algorithm SHA1).Hash
    # Write the file name and the hash value of the RAM acquisition file to the log file for documentation
    Write-Output "$(Get-Date -Format $dateFormat) -- Computer RAM acquired successfully
                       File Name:  $ramFileName (SHA1 Hash Value: $ramHashValue).
                       Save Location:  $ramFolder\$ramFileName" >> $logFile
    Write-Host "`n$(Get-Date -Format $dateFormat) -- RAM acquisition completed successfully
                       File Name: $ramFileName
                       SHA1 Hash Value: $ramHashValue`n" -ForegroundColor Yellow
}
# If the user does not want to collect the RAM
else
{
    # Display message that the RAM was not collected
    Write-Warning -Message "`nRAM was NOT be collected.`n"
    # Write message that RAM was not collected to the .log file
    Write-Output "$(Get-Date -Format $dateFormat) -- RAM Acquisition DECLINED by the user" >> $logFile
}

# Process Capture Execution
$getProcesses = Read-Host -Prompt "Do you want to run MAGNET ProcessCapture? (Enter 'y' or 'n')"
# If the user wants to execute the Process Capture
if ($getProcesses -eq 'y')
{
    Write-Host "`n$(Get-Date -Format $dateFormat) -- Process Capture has begun.  Please wait..." -ForegroundColor Yellow
    # Run MAGNETProcessCapture.exe from the \bin directory and save the output to the results folder.  The program will create its own directory to save the results with the following naming convention: MagnetProcessCapture-YYYYMMDD-HHMMSS
    Start-Process -NoNewWindow -FilePath ".\bin\MagnetProcessCapture.exe" -ArgumentList "/saveall '$resultsFolder'" -Wait
    # Write success message to the .log file
    Write-Output "$(Get-Date -Format $dateFormat) -- Process Capture completed successfully." >> $logFile
    # Write output to the screen
    Write-Host "$(Get-Date -Format $dateFormat) -- Process Capture completed successfully.`n" -ForegroundColor Yellow
}
# If the user does not want to execute the Process Capture
else
{
    Write-Warning -Message "`nProcessCapture was not run.  Proceeding to run the remainder of the script.`n"
    Write-Output "$(Get-Date -Format $dateFormat) -- Process Capture was declined by the user." >> $logFile
}

# Get user input to determine whether to get the hash values of all the saved files.
# The if/else statement is written toward the end of the script.
$hashResults = Read-Host -Prompt "Do you want to make a file to store all the resulting hash values? (Enter 'y' or 'n')"

Write-Host "`nData acquisition started.  Please wait - this may take a hot minute...`n" -ForegroundColor Blue

# Information for the .html report header
$topSection = "
<h1 id='top'> Live Forensic Triage Script </h1> 
<p>Computer Name: <span class='data'>$computerName</span>&nbsp;&nbsp;|&nbsp;&nbsp;User ID: <span class='data'>$userName</span></p>
<p>Script Began Date and Time: <span class='data'>$date at $time</span></p>
<p>Script Run By: <span class='data'>$operator</span>&nbsp;&nbsp;|&nbsp;&nbsp;Agency: <span class='data'>$agency</span>&nbsp;&nbsp;|&nbsp;&nbsp;Case Number: <span class='data'>$caseNumber</span></p>
"

# Setting HTML report headers
ConvertTo-Html -Head $header -PreContent $topSection > $resultsFolder\$resultsFile
ConvertTo-Html -Fragment -PreContent $quickLinks | Out-File -Append $resultsFolder\$resultsFile

# Main Routine

Write-Host "$(Get-Date -Format $dateFormat) -- Running SysInternals PSInfo"
Write-Output "$(Get-Date -Format $dateFormat) -- Running SysInternals PSInfo PS Command = '$PSInfo'`n" >> $logFile
.\bin\PsInfo.exe -accepteula -s -h -d > $resultsFolder\PSInfo.txt

# Get recursive directory file listing
Write-Host "$(Get-Date -Format $dateFormat) -- Running Full directory listing"
Write-Output "$(Get-Date -Format $dateFormat) -- Running Full directory listing PS Command = 'cmd.exe /c `"dir C:\ /A:H /Q /R /S /X`"'`n"
cmd.exe /c "dir C:\ /A:H /Q /R /S /X"


$commandGetComputerInfo = "Get-ComputerInfo"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting Computer Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting Computer Information PS Command = '$commandGetComputerInfo'`n" >> $logFile
$commandGetComputerInfo | ConvertTo-Html -As List -Fragment -Precontent "<h2 id='CompInfo'> Computer Information $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetSystemInfo = "systeminfo /FO CSV | ConvertFrom-Csv | Select-Object * -ExcludeProperty 'Hotfix(s)', 'Network Card(s)'"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting System Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting System Information PS Command = '$commandGetSystemInfo '`n" >> $logFile
$commandGetSystemInfo | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='SystemInfo-1'> System Information $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetAddSystemInfo = "Get-CimInstance -ErrorAction Ignore Win32_ComputerSystem | Select-Object -Property *"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting Additional System Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting Additional System Information PS Command = '$commandGetAddSystemInfo'`n" >> $logFile
$commandGetAddSystemInfo | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='SystemInfo-2'> Additional System Infomation $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$getPhysicalMemory = "Get-CimInstance -ErrorAction Ignore Win32_PhysicalMemory |  Select-Object -Property *"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting Physical Memory Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting Physical Memory Information PS Command = '$getPhysicalMemory'`n" >> $logFile
$getPhysicalMemory | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='PhyMem'> Device Physical Memory $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetEnv = "Get-ChildItem -Path env: -ErrorAction Ignore"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting Environment Variables"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting Environment Variables PS Command = '$commandGetEnv'`n" >> $logFile
$commandGetEnv | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='EnvVars'> User Environment Variables $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetDiskPartInfo = "Get-WmiObject -ErrorAction Ignore Win32_DiskPartition"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting Disk Partition Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting Disk Partition Information PS Command = '$commandGetDiskPartInfo'`n" >> $logFile
$commandGetDiskPartInfo | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='DiskPart'> Disk Partition Information $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetUserAccounts = "Get-WmiObject -ErrorAction Ignore Win32_UserProfile | Select-Object LocalPath, SID, @{N='last used'; E={$_.ConvertToDateTime($_.LastUseTime)}}"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting User Accounts and Current Login Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting User Accounts and Current Login Information PS Command = '$commandGetUserAccounts'`n" >> $logFile
$commandGetUserAccounts | ConvertTo-Html -Fragment -PreContent "<h2 id='UserAccount'> User Account and Current Login Information $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetMoreUserInfo = "Get-CimInstance -Class Win32_UserAccount -ErrorAction Ignore | Select-Object PSComputerName, Name, PasswordExpires, PasswordRequired, LocalAccount, SID, SIDType, Status, Disabled"
Write-Host "$(Get-Date -Format $dateFormat) -- Getting Additional User Account Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Getting Additional User Account Information PS Command = '$commandGetMoreUserInfo'`n" >> $logFile
$commandGetMoreUserInfo | ConvertTo-Html -Fragment -PreContent "<h2 id='AllUsers'> Other Computer User Accounts $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandLogonSessions = "Get-CimInstance -ErrorAction Ignore win32_LogonSession | Select-Object -Property *"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Logon Sessions"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Logon Sessions PS Command = '$commandLogonSessions'`n" >> $logFile
$commandLogonSessions | ConvertTo-Html -Fragment -PreContent "<h2 id='LogonSessions'> Logon Sessions $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandNetworkConfigInfo = "Get-WmiObject -ErrorAction Ignore Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq 'True'}| Select-Object DHCPEnabled, @{N='IpAddress'; E={$_.IpAddress -join '; '}}, @{N='DefaultIPgateway'; E={$_.DefaultIPgateway -join ';'}}, DNSDomain"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Network Configuration Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Network Configuration Information PS Command = '$commandNetworkConfigInfo'`n" >> $logFile
$commandNetworkConfigInfo | ConvertTo-Html -Fragment -PreContent "<h2 id='NetworkConfig'> Network Configuration Information $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps = "Get-WmiObject -ErrorAction Ignore Win32_StartupCommand | Select-Object Command, User, Caption"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications PS Command = '$commandGetStartupApps'`n" >> $logFile
# Will get information from this command
$commandGetStartupApps | ConvertTo-Html -Fragment -PreContent "<h2 id='StartupApps1'> Startup Applications $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps2 = "Get-ItemProperty -ErrorAction Ignore 'hklm:\software\wow6432node\microsoft\windows\currentversion\run' | Select-Object * -ExcludeProperty PS*"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications (from HKLM:\software\wow6432node\microsoft\windows\currentversion\run) PS Command = '$commandGetStartupApps2'`n" >> $logFile
$commandGetStartupApps2 | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='StartupApps2'> Startup Applications - Additional For 64 Bit Systems $return </h2> <h4> (FROM: HKLM:\software\wow6432node\microsoft\windows\currentversion\run) </h4>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps3 = "Get-ItemProperty -ErrorAction Ignore 'hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | Select-Object * -ExcludeProperty PS*"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications (from HKLM:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run) PS Command = '$commandGetStartupApps3'`n" >> $logFile
$commandGetStartupApps3 | ConvertTo-Html -Fragment -PreContent "<h2 id='StartupApps3'> Startup Applications - Additional For 64 Bit Systems $return </h2> <h4> (FROM: HKLM:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run) </h4>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps4 = "Get-ItemProperty -ErrorAction Ignore 'hklm:\software\wow6432node\microsoft\windows\currentversion\runonce' | Select-Object * -ExcludeProperty PS*"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications (from HKLM:\software\wow6432node\microsoft\windows\currentversion\runonce) PS Command = '$commandGetStartupApps4'`n" >> $logFile
$commandGetStartupApps4 | ConvertTo-Html -Fragment -PreContent "<h2 id='StartupApps4'> Startup Applications - Additional For 64 Bit Systems (Run Once) $return </h2> <h4> (FROM: HKLM:\software\wow6432node\microsoft\windows\currentversion\runonce) </h4>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps5 = "Get-ItemProperty -ErrorAction Ignore 'hkcu:\software\wow6432node\microsoft\windows\currentversion\run' | Select-Object * -ExcludeProperty PS*"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications (from HKCU:\software\wow6432node\microsoft\windows\currentversion\run) PS Command = '$commandGetStartupApps5'`n" >> $logFile
$commandGetStartupApps5 | ConvertTo-Html -Fragment -PreContent "<h2 id='StartupApps5'> Startup Applications - Additional For 64 Bit Systems $return </h2> <h4> (FROM: HKCU:\software\wow6432node\microsoft\windows\currentversion\run) </h4>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps6 = "Get-ItemProperty -ErrorAction Ignore 'hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | Select-Object * -ExcludeProperty PS*"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications (from HKCU:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run) PS Command = '$commandGetStartupApps6'`n" >> $logFile
$commandGetStartupApps6 | ConvertTo-Html -Fragment -PreContent "<h2 id='StartupApps6'> Startup Applications - Additional For 64 Bit Systems $return </h2> <h4> (FROM: HKCU:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run) </h4>" | Out-File -Append $resultsFolder\$resultsFile


$commandGetStartupApps7 = "Get-ItemProperty -ErrorAction Ignore 'hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce' | Select-Object * -ExcludeProperty PS*"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Startup Applications (from HKCU:\software\wow6432node\microsoft\windows\currentversion\runonce) PS Command = '$commandGetStartupApps7'`n" >> $logFile
$commandGetStartupApps7 | ConvertTo-Html -Fragment -PreContent "<h2 id='StartupApps7'> Startup Applications - Additional For 64 Bit Systems $return </h2> <h4> (FROM: HKCU:\software\wow6432node\microsoft\windows\currentversion\runonce) </h4>" | Out-File -Append $resultsFolder\$resultsFile


$cmd = netstat -nao | Select-String "ESTA"
Write-Host "$(Get-Date -Format $dateFormat) -- Running netstat command"
Write-Output "$(Get-Date -Format $dateFormat) -- Running netstat command PS Command = '$cmd'`n" >> $logFile
Write-Output "$(Get-Date -Format $dateFormat) -- Writing netstat output to .html file
                       PS Command = 'foreach (element in cmd) {
                                          data = element -split ' ' | Where-Object {$_ -ne ''}
                                          New-Object -TypeName psobject -Property @{
                                              'Local IP : Port#' = data[1];
                                              'Remote IP : Port#' = data[2];
                                              'Process ID'  = data[4];
                                              'Process Name' = ((Get-process | Where-Object {$_.ID -eq data[4]})).Name
                                              'Process File Path' = ((Get-process | Where-Object {$_.ID -eq data[4]})).path
                                              'Process Start Time' = ((Get-process | Where-Object {$_.ID -eq data[4]})).starttime
                                              'Associated DLLs and File Path' = ((Get-process | Where-Object {$_.ID -eq data[4]})).Modules | Select-Object @{N='Module'; E={$_.filename -join '; '}} | Out-String}`"" >> $logFile
Write-Output "" >> $logFile
ConvertTo-Html -Fragment -PreContent "<h2 id='Netstat'> Netstat Output $return </h2>" | Out-File -Append $resultsFolder\$resultsFile

foreach ($element in $cmd)
{
    $data = $element -split ' ' | Where-Object {$_ -ne ''}
    New-Object -TypeName psobject -Property @{
        'Local IP : Port#'              = $data[1];
        'Remote IP : Port#'             = $data[2];
        'Process ID'                    = $data[4];
        'Process Name'                  = ((Get-process | Where-Object {$_.ID -eq $data[4]})).Name
        'Process File Path'             = ((Get-process | Where-Object {$_.ID -eq $data[4]})).path
        'Process Start Time'            = ((Get-process | Where-Object {$_.ID -eq $data[4]})).starttime
        # 'Process File Version'          = ((Get-process | Where-Object {$_.ID -eq $data[4]})).
        'Associated DLLs and File Path' = ((Get-process | Where-Object {$_.ID -eq $data[4]})).Modules | Select-Object @{N='Module'; E={$_.filename -join '; '}} | Out-String
   } | ConvertTo-Html -Property 'Local IP : Port#', 'Remote IP : Port#', 'Process ID', 'Process Name', 'Process Start Time', 'Process File Path', 'Associated DLLs and File Path' -Fragment | Out-File -Append $resultsFolder\$resultsFile
}


$commandRunningProcesses = "Get-WmiObject -ErrorAction Ignore Win32_Process | Select-Object ProcessName, @{N='CreationDate'; E={$_.ConvertToDateTime($_.CreationDate)}}, ProcessId, ParentProcessId, CommandLine, SessionID | Sort-Object ParentProcessId -desc"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Running Processes"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Running Processes PS Command = '$commandRunningProcesses'`n" >> $logFile
$commandRunningProcesses | ConvertTo-Html -Fragment -PreContent "<h2 id='RunningProcesses'> Running Processes Sorted by ParentProcessID $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandSVCHostsAndProcesses = "Get-WmiObject -ErrorAction Ignore Win32_Process | Where-Object {$_.Name -eq 'svchost.exe'} | Select-Object ProcessId | ForEach-Object {$P=$_.ProcessID; Get-WmiObject Win32_Service | Where-Object {$_.processId -eq $P} | Select-Object ProcessID, Name, DisplayName, State, ServiceType, StartMode, PathName, Status}"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering SVCHOST and Associated Process"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering SVCHOST and Associated Process PS Command = '$commandSVCHostsAndProcesses'`n" >> $logFile
$commandSVCHostsAndProcesses | ConvertTo-Html -Fragment -PreContent "<h2 id='RunningSVCHOSTs'> Running SVCHOST and Associated Processes $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandRunningServices = "Get-WmiObject -ErrorAction Ignore win32_Service | Select-Object Name, ProcessId, State, DisplayName, PathName | Sort-Object State"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Running Services"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Running Services PS Command = '$commandRunningServices'`n" >> $logFile
$servicesInfo = $commandRunningServices | ConvertTo-Html -Fragment -PreContent "<h2 id='RunningServices'> Running Services (Sorted by State) $return </h2>"
# Editing the .html so the status field is color coded on the results file
$servicesInfo = $servicesInfo -Replace '<td>Running</td>','<td class="RunningStatus">Running</td>' 
$servicesInfo = $servicesInfo -Replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'
$servicesInfo | Out-File -Append $resultsFolder\$resultsFile


$commandRunningDriverInfo = "driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path | Sort-Object Path"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Running Driver Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Running Driver Information PS Command = $commandRunningDriverInfo`n" >> $logFile
$commandRunningDriverInfo | ConvertTo-Html -Fragment -PreContent "<h2 id='Drivers'> Drivers Running, Startup Mode and Path (Sorted by Path) $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# DISABLED JUST DURING TESTING
# WILL RE-ENABLE WHEN DONE
# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+


$commandGetLast50dlls = "Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction Ignore -include *.dll | Select-Object Name, CreationTime, LastAccessTime, Directory | Sort-Object CreationTime -desc | Select-Object -first 50"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering last 50 .dll files created"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering last 50 .dll files created PS Command = '$commandGetLast50dlls'`n" >> $logFile
$commandGetLast50dlls | ConvertTo-Html -Fragment -PreContent "<h2 id='Last50dlls'> Last 50 DLLs Created $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandListOpenFiles = "openfiles /query"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering List of Open Files"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering List of Open Files PS Command = '$commandListOpenFiles'`n" >> $logFile
$commandListOpenFiles > "$resultsFolder\$computerName-$userName-$date-OpenFiles.txt"


$commandGetOpenShares = "Get-WmiObject -ErrorAction Ignore Win32_Share | Select-Object Name, Path, Description"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Open Shares"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Open Shares PS Command = '$commandGetOpenShares'`n" >> $logFile
$commandGetOpenShares | ConvertTo-Html -Fragment -PreContent "<h2 id='OpenShares'> Open Shares $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandMapDrives = "Get-ItemProperty -ErrorAction Ignore 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU' | Select-Object * -ExcludeProperty PS*"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Mapped Drives"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Mapped Drives PS Command = '$commandMapDrives'`n" >> $logFile
$commandMapDrives | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='MappedDrives'> Mapped Drives $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandListScheduledJobs = "Get-WmiObject -ErrorAction Ignore Win32_ScheduledJob"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering List of Scheduled Jobs"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering List of Scheduled Jobs PS Command = '$commandListScheduledJobs'`n" >> $logFile
$commandListScheduledJobs | ConvertTo-Html -Fragment -PreContent "<h2 id='ScheduledJobs'> Scheduled Jobs $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandScheduledTaskEvents = "Get-WinEvent -ErrorAction Ignore -logname Microsoft-Windows-TaskScheduler\Operational | Select-Object TimeCreated, ID, Message"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Schedule Task Events"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Schedule Task Events PS Command = '$commandScheduledTaskEvents'`n" >> $logFile
$commandScheduledTaskEvents | ConvertTo-Html -Fragment -PreContent "<h2 id='ScheduledTaskEvents'> Scheduled Task Events $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandAppliedHotFixes = "Get-HotFix -ErrorAction Ignore | Select-Object HotfixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Applied HotFixes"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Applied HotFixes PS Command = '$commandAppliedHotFixes'`n" >> $logFile
$commandAppliedHotFixes | ConvertTo-Html -Fragment -PreContent "<h2 id='HotFixes'> HotFixes Applied (Sorted by Installed Date) $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandInstalledApplications = "Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation | Sort-Object InstallDate -Desc"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Installed Applications"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Installed Applications PS Command = '$commandInstalledApplications'`n" >> $logFile
$commandInstalledApplications | ConvertTo-Html -Fragment -PreContent "<h2 id='InstalledApps'> Installed Applications (Sorted by Installed Date) $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# DISABLED JUST DURING TESTING
# WILL RE-ENABLE WHEN DONE
# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+


$commandLinkFileAnalysis = "Get-WmiObject -ErrorAction Ignore Win32_ShortcutFile | Select-Object FileName, Caption, @{N='CreationDate'; E={$_.ConvertToDateTime($_.CreationDate)}}, @{N='LastAccessed'; E={$_.ConvertToDateTime($_.LastAccessed)}}, @{N='LastModified'; E={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.lastModified -gt ((Get-Date).addDays(-5))} | Sort-Object LastModified -Descending"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Link File Analysis (last 5 days)"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Link File Analysis (last 5 days) PS Command = '$commandLinkFileAnalysis'`n" >> $logFile
$commandLinkFileAnalysis | ConvertTo-Html -Fragment -PreContent "<h2 id='LinkFiles'> Link File Analysis - Last 5 days $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandListCompressedLists = "Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction Ignore -include $executableFiles | Where-Object {$_.Attributes -band [IO.FileAttributes]::Compressed}"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering List of Compressed Files"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering List of Compressed Files PS Command = '$commandListCompressedLists'`n" >> $logFile
$commandListCompressedLists | ConvertTo-Html -Fragment -PreContent "<h2 id='CompressedFiles'> Compressed Files $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandListEncryptedFiles = "Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction Ignore -include $executableFiles | Where-Object {$_.Attributes -band [IO.FileAttributes]::Encrypted}"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering List of Encrypted Files"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering List of Encrypted Files PS Command = '$commandListEncryptedFiles'`n" >> $logFile
$commandListEncryptedFiles | ConvertTo-Html -Fragment -PreContent "<h2 id='EncryptedFiles'> Encrypted Files $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandVolumeShadowCopies = "Get-WmiObject -ErrorAction Ignore Win32_ShadowCopy | Select-Object DeviceObject, @{N='CreationDate'; E={$_.ConvertToDateTime($_.InstallDate)}}"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering List of Volume Shadow Copies"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering List of Volume Shadow Copies PS Command = '$commandVolumeShadowCopies'`n" >> $logFile
$commandVolumeShadowCopies | ConvertTo-Html -Fragment -PreContent "<h2 id='ShadowCopy'> ShadowCopy List $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandPrefetchFiles = "Get-ChildItem -path 'C:\windows\prefetch\*.pf' -ErrorAction Ignore | Select-Object Name, LastAccessTime, CreationTime | Sort-Object LastAccessTime"
Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Prefetch File Information"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Prefetch File Information PS Command = '$commandPrefetchFiles'`n" >> $logFile
$commandPrefetchFiles | ConvertTo-Html -Fragment -PreContent "<h2 id='Prefetch'> Prefetch Files $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$commandDNSCache = "ipconfig /displaydns | Select-String 'Record Name' | Sort-Object"
Write-Host "$(Get-Date -Format $dateFormat) -- Parsing the DNS Cache"
Write-Output "$(Get-Date -Format $dateFormat) -- Parsing the DNS Cache PS Command = '$commandDNSCache'`n" >> $logFile
$commandDNSCache | ConvertTo-Html -Fragment -PreContent "<h2 id='DNSCache'> DNS Cache $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


Write-Host "$(Get-Date -Format $dateFormat) -- Gathering List of Available Log Files"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering List of Available Log Files`n" >> $logFile
Get-WinEvent -ErrorAction Ignore -ListLog * | Where-Object {$_.IsEnabled} | Sort-Object -Property LogName -Descending | Select-Object LogName, FileSize, LastWriteTime | ConvertTo-Html -Fragment -PreContent "<h2 id='Logs'> List of Available Logs $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


Write-Host "$(Get-Date -Format $dateFormat) -- Gathering Temporary Internet Files (Last 5 days)"
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Temporary Internet Files (Last 5 days)`n" >> $logFile
$la = $env:LOCALAPPDATA ; Get-ChildItem -Recurse -ErrorAction Ignore $la\Microsoft\Windows\'Temporary Internet Files' | Select-Object Name, LastWriteTime, CreationTime, Directory | Where-Object {$_.lastwritetime -gt ((Get-Date).addDays(-5))} | Sort-Object CreationTime -Desc | ConvertTo-Html -Fragment -PreContent "<h2 id='TempInternetFiles'> Temporary Internet Files - Last 5 days - Sorted by Creation Time $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GSCI = "$(Get-Date -Format $dateFormat) -- Gathering Stored Cookie Information"
Write-Host $GSCI
Write-Output $GSCI >> $logFile
$a = $env:APPDATA ; Get-ChildItem -r -ErrorAction Ignore $a\Microsoft\Windows\cookies | Select-Object Name | ForEach-Object {$N=$_.Name; Get-Content -ErrorAction Ignore $a\Microsoft\Windows\cookies\$N | Select-String '/'} | ConvertTo-Html -Fragment -PreContent "<h2 id='Cookies'> Cookies $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GTURLS = "$(Get-Date -Format $dateFormat) -- Gathering Typed URL Data"
Write-Host $GTURLS
Write-Output $GTURLS >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Internet Explorer\TypedUrls' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -Fragment -PreContent "<h2 id='TypedURLs'> Typed URLs $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GISRK = "$(Get-Date -Format $dateFormat) -- Gathering Internet Setting Registry Keys"
Write-Host $GISRK
Write-Output $GISRK >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegInternetSettings'> Important Registry Keys - Internet Settings $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GTIDRK = "$(Get-Date -Format $dateFormat) -- Gathering Trusted Internet Domain Registry Keys"
Write-Host $GTIDRK
Write-Output $GTIDRK >> $logFile
Get-ChildItem -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains' | Select-Object PSChildName | ConvertTo-Html -Fragment -PreContent "<h2 id='RegTrustedDomains'> Important Registry Keys - Internet Trusted Domains </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GAIDLLRK = "$(Get-Date -Format $dateFormat) -- Gathering AppInit_DLL Registry Keys "
Write-Host $GAIDLLRK
Write-Output $GAIDLLRK >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select-Object AppInit_DLLs | ConvertTo-Html -Fragment -PreContent "<h2 id='RegAppInit'> Important Registry Keys - AppInit_DLLs $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GUACGPS = "$(Get-Date -Format $dateFormat) -- Gathering UAC Group Policy Settings"
Write-Host $GUACGPS
Write-Output $GUACGPS >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegUAC'> Important Registry Keys - UAC Group Policy Settings $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GActSetupI = "$(Get-Date -Format $dateFormat) -- Gathering Active Setup Installs"
Write-Host $GActSetupI
Write-Output $GActSetupI >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Active Setup\Installed Components\*' | Select-Object ComponentID, '(default)', StubPath | ConvertTo-Html -Fragment -PreContent "<h2 id='RegActiveSetupInstalls'> Important Registry Keys - Active Setup Installs $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GAppPathRegKeys = "$(Get-Date -Format $dateFormat) -- Gathering App Path Registry Keys"
Write-Host $GAppPathRegKeys
Write-Output $GAppPathRegKeys >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*' | Select-Object PSChildName, '(default)' | ConvertTo-Html -Fragment -PreContent "<h2 id='RegAppPathKeys'> Important Registry Keys - APP Paths Keys $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GLDLLFLBES = "$(Get-Date -Format $dateFormat) -- Gathering List of .dll Files Loaded by Explorer.exe Shell"
Write-Host $GLDLLFLBES
Write-Output $GLDLLFLBES >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\microsoft\windows nt\CurrentVersion\winlogon\*\*' | Select-Object '(default)', DllName | ConvertTo-Html -Fragment -PreContent "<h2 id='RegLoadedDLLs'> Important Registry keys - DLLs Loaded by Explorer.exe Shell $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GSUIV = "$(Get-Date -Format $dateFormat) -- Gathering Shell and UserInit Values"
Write-Host $GSUIV
Write-Output $GSUIV >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\microsoft\windows nt\CurrentVersion\winlogon' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegShellUserInit'> Important Registry Keys - Shell and UserInit Values $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GSCSVCV = "$(Get-Date -Format $dateFormat) -- Gathering Security Center SVC Values"
Write-Host $GSCSVCV
Write-Output $GSCSVCV >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\microsoft\security center\svc' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -Fragment -PreContent "<h2 id='RegSVCValues'> Important Registry Keys - Security Center SVC Values $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GDABH = "$(Get-Date -Format $dateFormat) -- Gathering Desktop Address Bar History"
Write-Host $GDABH
Write-Output $GDABH >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegAddressBarHistory'> Important Registry Keys - Desktop Address Bar History $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GRMRUKI = "$(Get-Date -Format $dateFormat) -- Gathering RunMRU Key Information"
Write-Host $GRMRUKI
Write-Output $GRMRUKI >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\RunMRU' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -Fragment -PreContent "<h2 id='RegRunMRUKeys'> Important Registry Keys - RunMRU Keys $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GSMD = "$(Get-Date -Format $dateFormat) -- Gathering Start Menu Data"
Write-Host $GSMD
Write-Output $GSMD >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Startmenu' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -Fragment -PreContent "<h2 id='RegStartMenu'> Important Registry Keys - Start Menu $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GPEBSM = "$(Get-Date -Format $dateFormat) -- Gathering Programs Executed by Session Manager"
Write-Host $GPEBSM
Write-Output $GPEBSM >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegProgramExecuted'> Important Registry Keys - Programs Executed By Session Manager $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GSFI = "$(Get-Date -Format $dateFormat) -- Gathering Shell Folder Information"
Write-Host $GSFI
Write-Output $GSFI >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegShellFolders'> Important Registry Keys - Shell Folders $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GUSSFI = "$(Get-Date -Format $dateFormat) -- Gathering User Startup Shell Folder Information"
Write-Host $GUSSFI
Write-Output $GUSSFI >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders' | Select-Object startup | ConvertTo-Html -Fragment -PreContent "<h2 id='RegUserShellFolders'> Important Registry Keys - User Shell Folders (Startup) $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GASE = "$(Get-Date -Format $dateFormat) -- Gathering Approved Shell Extensions"
Write-Host $GASE
Write-Output $GASE >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegApprovedShellExts'> Important Registry Keys - Approved Shell Extentions $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GAppCertDLL = "$(Get-Date -Format $dateFormat) -- Gathering AppCert DLLs"
Write-Host $GAppCertDLL
Write-Output $GAppCertDLL >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -Fragment -PreContent "<h2 id='RegAppCertDLLs'> Important Registry Keys - AppCert DLLs $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEXEFSCC = "$(Get-Date -Format $dateFormat) -- Gathering EXE File Shell Command Configuration"
Write-Host $GEXEFSCC
Write-Output $GEXEFSCC >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Classes\exefile\shell\open\command' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -Fragment -PreContent "<h2 id='RegEXEFileShell'> Important Registry Keys - EXE File Shell Command Configured $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GSC = "$(Get-Date -Format $dateFormat) -- Gathering Shell Commands"
Write-Host $GSC
Write-Output $GSC >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Classes\HTTP\shell\open\command' | Select-Object '(default)' | ConvertTo-Html -Fragment -PreContent "<h2 id='RegShellCommands'> Important Registry Keys - Shell Commands $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GBCDRD = "$(Get-Date -Format $dateFormat) -- Gathering BCD Related Data"
Write-Host $GBCDRD
Write-Output $GBCDRD >> $logFile
Get-ItemProperty -ErrorAction Ignore "hklm:\BCD00000000\*\*\*\*" | Select-Object Element | Select-String "exe" | Select-Object Line | ConvertTo-Html -Fragment -PreContent "<h2 id='RegBCDRelated'> Important Registry Keys - BCD Related $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GLLSAPD = "$(Get-Date -Format $dateFormat) -- Gathering Loaded LSA Packages Data"
Write-Host $GLLSAPD
Write-Output $GLLSAPD >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SYSTEM\currentcontrolset\control\lsa' | Select-Object * -ExcludeProperty PS* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='RegLSAPackages'> Important Registry Keys - LSA Packages Loaded $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GBHO = "$(Get-Date -Format $dateFormat) -- Gathering Browser Helper Objects"
Write-Host $GBHO
Write-Output $GBHO >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | Select-Object '(default)' | ConvertTo-Html -Fragment -PreContent "<h2 id='RegBrowserHelperObjects'> Important Registry Keys - Browser Helper Objects $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GBHO64B = "$(Get-Date -Format $dateFormat) -- Gathering Browser Helper Objects (64 Bit)"
Write-Host $GBHO64B
Write-Output $GBHO64B >> $logFile
Get-ItemProperty -ErrorAction Ignore 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | Select-Object '(default)' | ConvertTo-Html -Fragment -PreContent "<h2 id='RegBrowserHelperObjectsx64'> Important Registry Keys - Browser Helper Objects 64 Bit $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GIEED = "$(Get-Date -Format $dateFormat) -- Gathering Internet Explorer Extensions Data"
Write-Host $GIEED
Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Internet Explorer Extensions Data (from HKCU:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*)" >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hkcu:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*' | Select-Object ButtonText, Icon | ConvertTo-Html -Fragment -PreContent "<h2 id='RegIEExtensionsFromHKCU'> Important Registry Keys - IE Extensions from HKCU $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Registry Keys (Internet Explorer Extensions from HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*)" >> $logFile
Get-ItemProperty -ErrorAction Ignore "hklm:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*" | Select-Object ButtonText, Icon | ConvertTo-Html -Fragment -PreContent "<h2 id='RegIEExtensionsFromHKLM'> Registry Keys - IE Extensions from HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\* $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


Write-Output "$(Get-Date -Format $dateFormat) -- Gathering Registry Keys (Internet Explorer Extensions from HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\*)" >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\*' | Select-Object ButtonText, Icon | ConvertTo-Html -Fragment -PreContent "<h2 id=''RegIEExtensionsFromWow> Registry Keys - IE Extensions from HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\* $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GLUSBD = "$(Get-Date -Format $dateFormat) -- Gathering List of USB Devices"
Write-Host $GLUSBD
Write-Output $GLUSBD >> $logFile
Get-ItemProperty -ErrorAction Ignore 'hklm:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object FriendlyName, PSChildName, ContainerID | ConvertTo-Html -Fragment -PreContent "<h2 id='USBDevices'> List of USB Devices $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# DISABLED JUST DURING TESTING
# WILL RE-ENABLE WHEN DONE
# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+


$GTOEF = "$(Get-Date -Format $dateFormat) -- Gathering Timeline of Executable Files (Past 30 Days)"
Write-Host $GTOEF
Write-Output $GTOEF >> $logFile
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction Ignore -include $executableFiles | Where-Object {-not $_.PSIsContainer -and $_.LastWriteTime -gt ((Get-Date).addDays(-30))} | Select-Object FullName, LastWriteTime, @{N='Owner'; E={($_ | Get-ACL).Owner}} | Sort-Object LastWriteTime -desc | ConvertTo-Html -Fragment -PreContent "<h2 id='FileTimelineExeFiles'> File Timeline Executable Files (Past 30 Days) $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GDEF = "$(Get-Date -Format $dateFormat) -- Gathering Downloaded Executable Files"
Write-Host $GDEF
Write-Output $GDEF >> $logFile
Get-ChildItem -Path C:\ -Recurse -Force -ErrorAction Ignore -include $executableFiles | ForEach-Object {$P=$_.FullName; Get-Item $P -Stream *} | Where-Object {$_.Stream -match "Zone.Identifier"} | Select-Object FileName, Stream, @{N='LastWriteTime'; E={(Get-ChildItem $P).LastWriteTime}} | ConvertTo-Html -Fragment -PreContent "<h2 id='DownloadedExeFiles'> Downloaded Executable Files $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL1002= "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Application Crashes)"
Write-Host $GEL1002
Write-Output $GEL1002 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='application'; ID=1002} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog1002'> Event Log [Application Crashes (ID: 1002)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL1014 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Failed DNS Resolution Events)"
Write-Host $GEL1014
Write-Output $GEL1014 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='system'; ID=1014} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog1014'> Event Log [DNS Failed Resolution Events (ID: 1014)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL1102 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Audit Log Cleared)"
Write-Host $GEL1102
Write-Output $GEL1102 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='application'; ID=1102} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog1102'> Event Log [Audit Log was Cleared (ID: 1102)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4616 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Changed System Time)"
Write-Host $GEL4616
Write-Output $GEL4616 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4616} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4616'> Event Log [The System Time Was Changed (ID: 4616)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4624 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Account Logon History)"
Write-Host $GEL4624
Write-Output $GEL4624 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4624} | Select-Object TimeCreated, ID, TaskDisplayName, Message, UserId, ProcessId, ThreadId, MachineName | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4624'> Event Log [Account Logon (ID: 4624)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4625 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Failed Account Logon History)"
Write-Host $GEL4625
Write-Output $GEL4625 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4625} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4625'> Event Log [An Account Failed To Log On (ID: 4625)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4684 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Logons Using Explicit Credentials)"
Write-Host $GEL4684
Write-Output $GEL4684 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4648} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4648'> Event Log [A Logon Was Attempted Using Explicit Credentials (ID: 4648)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4672 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Privlege Use ID: 4672)"
Write-Host $GEL4672
Write-Output $GEL4672 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4672} | Select-Object TimeCreated, ID, TaskDisplayName, Message, UserId, ProcessId, ThreadId, MachineName | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4672'> Event Log [Special Logon (ID: 4672)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4673 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Privlege Use ID: 4673)"
Write-Host $GEL4673
Write-Output $GEL4673 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4673} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4673'> Event Log [Privilege Use (ID: 4673)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4674 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Privlege Use ID: 4674)"
Write-Host $GEL4674
Write-Output $GEL4674 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4674} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4674'> Event Log [Privilege Use (ID: 4674)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4688 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Process Execution)"
Write-Host $GEL4688
Write-Output $GEL4688 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4688} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4688'> Event Log [Process Execution (ID: 4688)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL4720 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (User Account Created)"
Write-Host $GEL4720
Write-Output $GEL4720 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='security'; ID=4720} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog4720'> Event Log [A User Account Was Created (ID: 4720)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL7036 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Service Control Manager Events)"
Write-Host $GEL7036
Write-Output $GEL7036 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='system'; ID=7036} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog7036'> Event Log [Service Control Manager Events (ID: 7036)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL7045 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (Service Creation)"
Write-Host $GEL7045
Write-Output $GEL7045 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='system'; ID=7045} | Select-Object TimeCreated, ID, Message, UserId, ProcessId, ThreadId, MachineName | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog7045'> Event Log [Service Creation (ID: 7045)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GEL64001 = "$(Get-Date -Format $dateFormat) -- Gathering Event Log (WFP Event)"
Write-Host $GEL64001
Write-Output $GEL64001 >> $logFile
Get-WinEvent -max 50 -ErrorAction Ignore -FilterHashtable @{Logname='system'; ID=64001} | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='EventLog64001'> Event Log [WFP Events (ID: 64001)] $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GAIE = "$(Get-Date -Format $dateFormat) -- Gathering Application Inventory Events"
Write-Host $GAIE
Write-Output $GAIE >> $logFile
Get-WinEvent -ErrorAction Ignore -logname Microsoft-Windows-Application-Experience/Program-Inventory | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='AppInventoryEvents'> Application Inventory Events $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


$GTSE = "$(Get-Date -Format $dateFormat) -- Gathering Terminal Service Events"
Write-Host $GTSE
Write-Output $GTSE >> $logFile
Get-WinEvent -ErrorAction Ignore -logname Microsoft-Windows-TerminalServices-LocalSessionManager/Operational | Select-Object TimeCreated, ID, Message | ConvertTo-Html -Fragment -PreContent "<h2 id='TerminalServiceEvents'> Terminal Services Events $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


# Copying network connections
$CNCI = "$(Get-Date -Format $dateFormat) -- Copying Network Connection Information"
Write-Host $CNCI
Write-Output $CNCI >> $logFile
Get-NetTCPConnection -ErrorAction Ignore | Sort-Object LocalAddress -desc | ConvertTo-Html -Fragment -PreContent "<h2 id='NetTCP'> NetTCP Connections $return </h2>" | Out-File -Append $resultsFolder\$resultsFile


# Copying Hosts file data
$CHFD = "$(Get-Date -Format $dateFormat) -- Copying *hosts* data to HostsFile.txt file"
Write-Host $CHFD
Write-Output $CHFD >> $logFile
Get-Content $env:windir\system32\drivers\etc\hosts | Out-File -FilePath $resultsFolder\$computerName-$userName-$date-HostsFile.txt -Encoding ASCII


# Copying Services file data
$CSFD = "$(Get-Date -Format $dateFormat) -- Copying *services* data to ServiceFile.txt file"
Write-Host $CSFD
Write-Output $CSFD >> $logFile
Get-Content $env:windir\system32\drivers\etc\services | Out-File -FilePath $resultsFolder\$computerName-$userName-$date-ServicesFile.txt -Encoding ASCII


# Audit Policy
$CCAP = "$(Get-Date -Format $dateFormat) -- Copying Computer Audit Policy to AuditPolicy.txt file"
Write-Host $CCAP
Write-Output $CCAP >> $logFile
# auditpol /get /category:* | Select-String 'No Auditing' -notmatch | Out-File -FilePath $resultsFolder\$computerName-$userName-$date-AuditPolicy.txt -Encoding ASCII
auditpol /get /category:* | ConvertTo-Html -As List -Fragment -PreContent "<h2 id='AuditPolicy'> Audit Policy $return </h2>"| Out-File -Append $resultsFolder\$resultsFile


# Firewall Config
$CFCI = "$(Get-Date -Format $dateFormat) -- Copying Firewall Configuration Information to FirewallConfig.txt file"
Write-Host $CFCI
Write-Output $CFCI >> $logFile
netsh firewall show config | Out-File -FilePath $resultsFolder\$computerName-$userName-$date-FirewallConfig.txt -Encoding ASCII
netsh advfirewall firewall show rule name=all verbose > $resultsFolder\$computerName-$userName-$date-FirewallRules.txt


if ($hashResults -eq 'y')
{
    # Get the hash values of all the saved files in the output directory
    Write-Host "$(Get-Date -Format $dateFormat) -- Hashing saved files.  Please wait..."
    Write-Output "$(Get-Date -Format $dateFormat) -- Hashing saved files" >> $logFile
    # Command that actually gets the hash values of all the files located in the results folder and converts the results to an .html table
    Get-ChildItem -Path $resultsFolder -Recurse -Force -File | Select-Object -Property Directory, BaseName, Extension, PSIsContainer, @{N='SizeInKB'; E={[double]('{0:N2}' -f ($_.Length/1KB))}}, @{N='FileHash'; E={(Get-FileHash -Algorithm SHA1 $_.FullName).Hash}}, Mode, Attributes, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC | Sort-Object -Property DirectoryName, Name | Sort-Object Directory | ConvertTo-Html | Out-File $resultsFolder\HashValues.html -Encoding ASCII
    # Hashing of the saved files is completed
    $FHC = "$(Get-Date -Format $dateFormat) -- File Hashing Completed"
    Write-Host $FHC
    Write-Output $FHC >> $logFile
}
else
{
    Write-Warning -Message "`nSaved files were not hashed. Proceeding to run the remainder of the script.`n"
    Write-Output "$(Get-Date -Format $dateFormat) -- File hashing was DECLINED by the user." >> $logFile
}

# Get the time the script was completed
$duration = (Get-Date) - $startTime
# Calculate the total run time of the script and format the results
$diff = $duration.ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")

# Get the current date at the end of the script run
$durationText = "Script completed at: $(Get-Date -Format "MM-dd-yyyy HH:mm:ss '('K UTC')'")"

# Display message that the script has completed and list the total time it took to process
Write-Host `n$durationText -ForegroundColor Yellow
Write-Host "[$diff]`n" -ForegroundColor Yellow
Write-Host "The results are available in the following directory:" -ForegroundColor Green
Write-Host "`t$resultsFolder`n" -ForegroundColor Green

Write-Output "" >> $logFile
Write-Output $durationText >> $logFile
Write-Output "" >> $logFile
Write-Output "Total execution time : [$diff]" >> $logFile

# Prompt the user whether they want to open the result file.  If the user chooses anything but "y", the script will exit.
$openFile = Read-Host -Prompt "Do you want to open the results file now? (Enter 'y' or 'n')"
if ($openFile -eq 'y')
{
    Invoke-Item "$resultsFolder\$resultsFile"
}
else
{
    Exit
}

# Popup message upon completion
# (New-Object -ComObject wscript.shell).popup("The Script has finished running")


<# TO ADD TO SCRIPT

--> Check system directories for executables not signed as part of an operating system release
    gci C:\windows\*\*.exe -File -force |get-authenticodesignature|?{$_.IsOSBinary -notmatch 'True'}
#>
