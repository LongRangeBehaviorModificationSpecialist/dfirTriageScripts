# EDITED BY : mikespon

function Write-LogMessage
{

    param (
        [string]$logString
    )

    $timeStamp = (Get-Date).toString("yyyy-MM-dd HH:mm:ss")
    $logMessage = "$timeStamp | $logString"
    Add-Content $logFile -Value $logMessage
}


# Importing variables to use later in the script
. ".\inc\vars.ps1"

# Date Last Updated
$dlu = "2023-09-28"
# Getting the computer name
$computerName = $env:computername

# Assigning variables to use in the script
$banner = "
******************************************************************
*                         === VECTOR ===                         *
*                           NOVA ICAC                            *
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
$date = Get-Date -Format yyyyMMdd_HHmmss
# Getting the fully qualified domain name of the current machine
$domainName = $env:userdnsdomain
# Getting the current IP address of the machine from on this script is run
$IP = Test-Connection $computerName -TimeToLive 2 -Count 1
$ip = $ip.ipv4address | Select-Object -ExpandProperty IPAddressToString
# Get the current working directory so the $outputFolder is stored in the same directory from which this script is executed
$cwd = Get-Location
# Naming the directory to store the results
$outputFolder = $date + "_"+ $IP + "_"+ $computerName + $domainName
# Making the directories to store the result files
$resultsFolder = New-Item -Path $cwd -Name $outputFolder -ItemType Directory
$deviceFolder = New-Item -Path $resultsFolder -Name "DEVICEINFO" -ItemType Directory
$deviceFolderName = ($deviceFolder).Name
$userFolder = New-Item -Path $resultsFolder -Name "'USERINFO" -ItemType Directory
$userFolderName = ($userFolder).Name
$networkFolder = New-Item -Path $resultsFolder -Name "NETWORK" -ItemType Directory
$networkFolderName = ($networkFolder).Name
$processFolder = New-Item -Path $resultsFolder -Name "PROCESSES" -ItemType Directory
$processFolderName = ($processFolder).Name
$systemFolder = New-Item -Path $resultsFolder -Name "SYSTEM" -ItemType Directory
$systemFolderName = ($systemFolder).Name
$prefetchFolder = New-Item -Path $resultsFolder -Name "PREFETCH" -ItemType Directory
$prefetchFolderName = ($prefetchFolder).Name
$logFolder = New-Item -Path $resultsFolder -Name "LOGFILES" -ItemType Directory
$logFolderName = ($logFolder).Name
$firewallFolder = New-Item -Path $resultsFolder -Name "FIREWALL" -ItemType Directory
$firewallFolderName = ($firewallFolder).Name
$logFile = "$resultsFolder\Script.log"
# List of file types to use in some commands
$executableFiles = @("*.EXE", "*.COM", "*.BAT", "*.BIN", "*.JOB", "*.WS", ".WSF", "*.PS1", ".PAF", "*.MSI", "*.CGI", "*.CMD", "*.JAR", "*.JSE", "*.SCR", "*.SCRIPT", "*.VB", "*.VBE", "*.VBS", "*.VBSCRIPT", "*.DLL")
$startTime = Get-Date
$dateFormat = "MM-dd-yyyy HH:mm:xxss"

# Clear the terminal screen before displaying the DFIR banner and instructions
Clear-Host

# Display the DFIR banner and instructions to the user
Write-Output $banner
Write-Output "Compiled by Michael Sponheimer
Last Updated: $dlu

=============
INSTRUCTIONS
=============

[1]  You are about to run the VECTOR DFIR Powershell Script.
[2]  This will gather information from the target machine and
     save the data to numerous text files.
[3]  The results will be stored in a folder that is in the same
     folder from which this script is run.
[4]  There are three (3) prompts that will require user input
     at the beginning.
[5]  **DO NOT** close any pop-up windows that may appear.
"

# Stops the script until the user presses the ENTER key so the script does not begin before the user is ready
Read-Host -Prompt "Press ENTER to run the DFIR Script"
# Write the data to the log file and display start time message on the screen
Write-Output "--- Script Log for VECTOR DFIR Script Usage ---`n" | Write-LogMessage
$startTime = "Script execution started`n"
Write-Output $startTime | Write-LogMessage


Write-Host "$startTime`n" -ForegroundColor Yellow

# Havie the user of the script enter some basic information to add to the log file
$user = Read-Host -Prompt "[A]  Enter your name for the report"
Write-Output "Operator Name : $user" | Write-LogMessage

$agency = Read-Host -Prompt "[B]  Enter Agency Name"
Write-Output "Agency Name : $agency" | Write-LogMessage

$caseNumber = Read-Host -Prompt "[C]  Enter Case Number"
Write-Output "Case Number : $caseNumber" | Write-LogMessage

Write-Output "Output Folder : $resultsFolder" | Write-LogMessage

# Ask the user if they wish to collect the RAM of the running computer
$getRAM = Read-Host -Prompt "`nDo you want to collect the computer's RAM? (Enter 'y' or 'n')"
# Ask the user if they wish to run the MAGNETProcessCapture program on the computer
$getProcess = Read-Host -Prompt "`nDo you want to run MAGNET ProcessCapture? (Enter 'y' or 'n')"
# Get user input to determine whether to get the hash values of all the saved files
# The if/else statement for this action is written toward the end of the script
$hashResults = Read-Host -Prompt "`nDo you want to make a file to store all the resulting hash values? (Enter 'y' or 'n')"

# RAM Acquisition Execution
# If the user wants to collect the RAM
if ($getRAM -eq 'y')
{
    # Create a folder called "RAM" to store the captured RAM file
    $ramFolder = New-Item -Path $resultsFolder -Name "RAM" -ItemType Directory
    Write-Host "`n$(Get-Date -Format $dateFormat) | RAM acquisition has begun. Please wait..." -ForegroundColor Yellow
    # Start the process to acquire RAM from the current machine
    Start-Process -NoNewWindow -FilePath ".\bin\MagnetRAMCapture.exe" -ArgumentList "/accepteula /go /silent" -Wait
    # Once the RAM has been acquired, move the file to the 'RAM' folder
    Move-Item -Path .\bin\*.raw -Destination $ramFolder
    # Get the name of the acquired RAM .raw file
    $ramFileName = (Get-ChildItem -Path $ramFolder\*.raw).Name
    # Get the SHA1 hash value of the acquired RAM .raw file
    $ramHashValue = (Get-FileHash $ramFolder\*.raw -Algorithm SHA1).Hash
    # Write the file name and the hash value of the acquired RAM file to the log for documentation
    Write-Output "Computer RAM acquired successfully.
    File Name:  $ramFileName (SHA1 Hash Value: $ramHashValue).
    Save Location:  $ramFolder\$ramFileName`n" | Write-LogMessage
      # Write a message, the file name, and the hash value of the RAM file to the screen
    Write-Host "$(Get-Date -Format $dateFormat) | RAM acquisition completed successfully.
                       File Name: $ramFileName
                       SHA1 Hash Value: $ramHashValue`n" -ForegroundColor Yellow
}
# If the user does not want to collect the RAM
else
{
    # Display message that the RAM was not collected
    Write-Warning -Message "`nRAM will NOT be collected."
    # Write message that RAM was not collected to the .log file
    Write-Output "RAM Acquisition DECLINED by the user." | Write-LogMessage
}

# ProcessCapture Execution
# If the user wants to execute the ProcessCapture
if ($getProcess -eq 'y')
{
    Write-Host "`n$(Get-Date -Format $dateFormat) | Process Capture has begun. Please wait..." -ForegroundColor Yellow
    # Run MAGNETProcessCapture.exe from the \bin directory and save the output to the results folder.
    # The program will create its own directory to save the results with the following naming convention: 'MagnetProcessCapture-YYYYMMDD-HHMMSS'
    Start-Process -NoNewWindow -FilePath ".\bin\MagnetProcessCapture.exe" -ArgumentList "/saveall `"$resultsFolder`"" -Wait
    # Write success message to the log file
    Write-Output "Process Capture completed successfully." | Write-LogMessage
    # Write success message to the screen
    Write-Host "$(Get-Date -Format $dateFormat) | Process Capture completed successfully.`n" -ForegroundColor Yellow
}
# If the user does not want to execute ProcessCapture
else
{
    Write-Warning -Message "`nProcess Capture will NOT be run."
    Write-Output "Process Capture DECLINED by the user." | Write-LogMessage
}

Write-Host "`nData acquisition started. Please wait - this may take a hot minute...`n" -ForegroundColor Blue


# Begin main routine
$systemProcess = "PS_info.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Running SysInternals PSInfo"
Write-Output "Running SysInternals PSInfo, Output File = $deviceFolderName\$systemProcess" | Write-LogMessage
# Run the command
.\bin\PsInfo.exe -accepteula -s -h -d | Out-File -FilePath $deviceFolder\$systemProcess


# Get recursive directory file listing
$FullDirList = "full_dir_list.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Full Directory Listing"
Write-Output "Getting Full Directory Listing, Output File = $deviceFolderName\$FullDirList" | Write-LogMessage
# Run the command
cmd.exe /c "dir C:\ /A:H /Q /R /S /X" | Out-File -FilePath $deviceFolder\$FullDirList


$ComputerInfo = "computer_info.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Computer Information"
Write-Output "Getting Computer Information, Output File = $deviceFolderName\$ComputerInfo" | Write-LogMessage
# Run the command
Get-ComputerInfo | Out-File -FilePath $deviceFolder\$ComputerInfo


$SystemInfo = "system_info.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting System Information"
Write-Output "Getting System Information, Output File = $deviceFolderName\$SystemInfo" | Write-LogMessage
# Run both commands and append the results of the second command to the first output file
systeminfo /FO LIST | Out-File -FilePath $deviceFolder\$SystemInfo
Get-CimInstance -Class Win32_ComputerSystem -EA 0 | Select-Object -Property * | Out-File -Append -FilePath $deviceFolder\$SystemInfo


$PhysicalMemory = "physical_memory.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Physical Memory Information"
Write-Output "Getting Physical Memory Information, Output File = $deviceFolderName\$PhysicalMemory" | Write-LogMessage
# Run the command
Get-CimInstance -Class Win32_PhysicalMemory -EA 0 | Select-Object -Property * | Out-File -FilePath $deviceFolder\$PhysicalMemory


$EnvVars = "env_vars.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Environment Variables"
Write-Output "Getting Environment Variables, Output File = $deviceFolderName\$EnvVars" | Write-LogMessage
# Run the command
Get-ChildItem -Path env: -EA 0 | Format-List | Out-File -FilePath $deviceFolder\$EnvVars


$DiskPart = "disk_partitions.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Disk Partition Information"
Write-Output "Getting Disk Partition Information, Output File = $deviceFolderName\$DiskPart" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_DiskPartition -EA 0 | Format-List | Out-File -FilePath $deviceFolder\$DiskPart


$userAccounts = "user_accounts.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting User Accounts and Current Login Information"
Write-Output "Getting User Accounts and Current Login Information, Output File = $userFolderName\$userAccounts" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_UserProfile -EA 0 | Select-Object LocalPath, SID, @{N="last used"; E={$_.ConvertToDateTime($_.lastusetime)}} | Out-File -FilePath $userFolder\$userAccounts


$MoreUserInfo = "user_accounts_additional_info.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Additional User Account Information"
Write-Output "Getting Additional User Account Information, Output File = $userFolderName\$MoreUserInfo" | Write-LogMessage
# Run the command
Get-CimInstance -Class Win32_UserAccount -EA 0 | Select-Object PSComputerName, Name, PasswordExpires, PasswordRequired, LocalAccount, SID, SIDType, Status, Disabled | Out-File -FilePath $userFolder\$MoreUserInfo


$LogonSessions = "logon_sessions.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Logon Sessions"
Write-Output "Getting Logon Sessions, Output File = $userFolderName\$LogonSessions" | Write-LogMessage
# Run the command
Get-CimInstance -Class Win32_LogonSession -EA 0 | Select-Object -Property * | Out-File -FilePath $userFolder\$LogonSessions


$NetworkConfig = "network_config.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Network Configuration Information"
Write-Output "Getting Network Configuration Information, Output File = $networkFolderName\$NetworkConfig" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -EA 0 | Where-Object {$_.IPEnabled -eq "True"} | Select-Object DHCPEnabled, @{N="IpAddress"; E={$_.IpAddress -join "; "}}, @{N="DefaultIPgateway"; E={$_.DefaultIPgateway -join ";"}}, DNSDomain | Out-File -FilePath $networkFolder\$NetworkConfig


$StartUpApps = "start_up_apps.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Startup Applications"
Write-Output "Getting Startup Applications from the following sources:
                       [A]  Win32_StartupCommand
                       [B]  HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
                       [C]  HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
                       [D]  HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
                       [E]  HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run
                       [F]  HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
                       [G]  HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce
                       Output File = $deviceFolderName\$StartUpApps" | Write-LogMessage
# Run the following commands and append results to the first Startup Application text file
Get-CimInstance -ClassName Win32_StartupCommand -EA 0 | Select-Object Caption, User, Command | Format-List | Out-File -FilePath $deviceFolder\$StartUpApps
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -Append -FilePath $deviceFolder\$StartUpApps
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -Append -FilePath $deviceFolder\$StartUpApps
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -Append -FilePath $deviceFolder\$StartUpApps
Get-ItemProperty "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -Append -FilePath $deviceFolder\$StartUpApps
Get-ItemProperty "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -Append -FilePath $deviceFolder\$StartUpApps
Get-ItemProperty "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -Append -FilePath $deviceFolder\$StartUpApps


# Get all netstat entries where there is an ESTABLISHED connection and then run that output through the foreach loop to gather additional information about each connection
$cmd = netstat -nao | Select-String "ESTA"
$netstatDetailed = "netstat_detailed.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Information Related to ESTABLISHED Connections"
Write-Output "Getting Information Related to ESTABLISHED Connections, Output File = $networkFolderName\$netstatDetailed" | Write-LogMessage


# Run the command for each object returned by the $cmd command
foreach ($element in $cmd)
{
    $data = $element -split " " | Where-Object {$_ -ne ""}
    New-Object -TypeName PSObject -Property @{
        "Local IP : Port#"              = $data[1];
        "Remote IP : Port#"             = $data[2];
        "Process ID"                    = $data[4];
        "Process Name"                  = ((Get-Process | Where-Object {$_.ID -eq $data[4]})).Name
        "Process File Path"             = ((Get-Process | Where-Object {$_.ID -eq $data[4]})).Path
        "Process Start Time"            = ((Get-Process | Where-Object {$_.ID -eq $data[4]})).StartTime
        "Associated DLLs and File Path" = ((Get-Process | Where-Object {$_.ID -eq $data[4]})).Modules | Select-Object @{N="Module"; E={$_.FileName -join "; "}} | Out-String
    } | Out-File -Append -FilePath $networkFolder\$netstatDetailed
}


$netstatAllConnections = "netstat_all_connections.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Basic Internet Connection Information"
Write-Output "Getting Basic Internet Connection Information, Output File = $networkFolderName\$netstatAllConnections" | Write-LogMessage
# Run the command
netstat -nao | Out-File -FilePath $networkFolder\$netstatAllConnections


$runningProcesses = "running_processes.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Running Processes"
Write-Output "Getting Running Processes, Output File = $processFolderName\$runningProcesses" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_Process -EA 0 | Select-Object ProcessName, @{N="CreationDate"; E={$_.ConvertToDateTime($_.CreationDate)}}, ProcessId, ParentProcessId, CommandLine, SessionID | Sort-Object ParentProcessId -Desc | Out-File -FilePath $processFolder\$runningProcesses


$SVCHostsAndProcess = "SVC_host_and_processes.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting SVCHOST and Associated Process"
Write-Output "Getting SVCHOST and Associated Process, Output File = $processFolderName\$SVCHostsAndProcess" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_Process -EA 0 | Where-Object {$_.name -eq "svchost.exe"} | Select-Object ProcessId | ForEach-Object {$P=$_.ProcessID; Get-CimInstance -ClassName Win32_Service | Where-Object {$_.processId -eq $P} | Select-Object ProcessID, Name, DisplayName, State, ServiceType, StartMode, PathName, Status} | Out-File -FilePath $processFolder\$SVCHostsAndProcess


$RunningServices = "running_services.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Running Services"
Write-Output "Getting Running Services, Output File = $processFolderName\$RunningServices" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_Service -EA 0 | Select-Object Name, ProcessId, State, DisplayName, PathName | Sort-Object State | Out-File -FilePath $processFolder\$RunningServices


$RunningDriverInfo = "running_drivers.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Running Driver Information"
Write-Output "Getting Running Driver Information, Output File = $processFolderName\$RunningDriverInfo" | Write-LogMessage
# Run the command
driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select-Object "Display Name", "Start Mode", Path | Sort-Object Path | Format-List | Out-File -FilePath $processFolder\$RunningDriverInfo


# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# DISABLED DURING TESTING
# WILL RE-ENABLE WHEN DONE
# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

<#
$Last50dlls = "last_50_dll_files.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting last 50 .dll files created"
Write-Output "Getting last 50 .dll files created, Output File = $systemFolderName\$Last50dlls" | Write-LogMessage
# Run the command
Get-ChildItem -Path C:\ -Recurse -Force -Include *.dll -EA 0 | Select-Object Name, CreationTime, LastAccessTime, Directory | Sort-Object CreationTime -Desc | Select-Object -first 50 | Out-File -FilePath $systemFolder\$Last50dlls
#>


$OpenFilesList = "list_of_open_files.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting List of Open Files"
Write-Output "Getting List of Open Files, Output File = $systemFolderName\$OpenFilesList" | Write-LogMessage
# Run the command
openfiles /query | Out-File -FilePath $systemFolder\$OpenFilesList


$OpenShares = "open_shares.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Open Shares"
Write-Output "Getting Open Shares, Output File = $systemFolderName\$OpenShares" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_Share -EA 0 | Select-Object Name, Path, Description | Out-File -FilePath $systemFolder\$OpenShares


$MappedDrives = "mapped_drives.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Mapped Drives"
Write-Output "Getting Mapped Drives, Output File = $systemFolderName\$MappedDrives" | Write-LogMessage
# Run the command
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$MappedDrives


$ScheduledJobs = "scheduled_jobs.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting List of Scheduled Jobs"
Write-Output "Getting List of Scheduled Jobs, Output File = $systemFolderName\$ScheduledJobs" | Write-LogMessage
# Run the command
Get-CIMinstance -ClassName Win32_ScheduledJob -EA 0 | Out-File -FilePath $systemFolder\$ScheduledJobs


$ScheduledTasks = "Scheduled_task_events.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Schedule Task Events"
Write-Output "Getting Schedule Task Events, Output File = $systemFolderName\$ScheduledTasks" | Write-LogMessage
# Run the command
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler\Operational -EA 0 | Select-Object TimeCreated, ID, Message | Out-File -FilePath $systemFolder\$ScheduledTasks


$HotFixes = "hot_fixes.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Applied HotFixes"
Write-Output "Getting Applied HotFixes, Output File = $systemFolderName\$HotFixes" | Write-LogMessage
# Run the command
Get-HotFix -EA 0 | Select-Object HotfixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending | Out-File -FilePath $systemFolder\$HotFixes


$InstalledApps = "installed_apps.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Installed Applications"
Write-Output "Getting Installed Applications, Output File = $systemFolderName\$InstalledApps" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -EA 0 | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation | Sort-Object InstallDate -Desc | Out-File -FilePath $systemFolder\$InstalledApps


# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# DISABLED DURING TESTING
# WILL RE-ENABLE WHEN DONE
# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+


# $LinkFiles = "link_files.txt"
# Write-Host "$(Get-Date -Format $dateFormat) | Getting Link File Analysis (last 5 days)"
# Write-Output "Getting Link File Analysis (last 5 days), Output File = $systemFolderName\$LinkFiles" | Write-LogMessage
# # Run the command
# Get-CimInstance -ClassName Win32_ShortcutFile -EA 0 | Select-Object FileName, Caption, @{N="CreationDate"; E={$_.ConvertToDateTime($_.CreationDate)}}, @{N="LastAccessed"; E={$_.ConvertToDateTime($_.LastAccessed)}}, @{N="LastModified"; E={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.lastModified -gt ((Get-Date).AddDays(-5))} | Sort-Object LastModified -Descending | Out-File -FilePath $systemFolder\$LinkFiles


# $CompressedFiles = "compressed_files.txt"
# Write-Host "$(Get-Date -Format $dateFormat) | Getting List of Compressed Files"
# Write-Output "Getting List of Compressed Files, Output File = $systemFolderName\$CompressedFiles" | Write-LogMessage
# # Run the command
# Get-ChildItem -Path C:\ -Recurse -Force -Include $executableFiles -EA 0 | Where-Object {$_.Attributes -band [IO.FileAttributes]::Compressed} | Out-File -FilePath $systemFolder\$CompressedFiles


# $EncryptedFiles = "encrypted_files.txt"
# Write-Host "$(Get-Date -Format $dateFormat) | Getting List of Encrypted Files"
# Write-Output "Getting List of Encrypted Files, Output File = $systemFolderName\$EncryptedFiles" | Write-LogMessage
# # Run the command
# Get-ChildItem -Path C:\ -Recurse -Force -Include $executableFiles -EA 0 | Where-Object {$_.Attributes -band [IO.FileAttributes]::Encrypted} | Out-File -FilePath $systemFolder\$EncryptedFiles


$VolumeShadowCopies = "volume_shadow_copies.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting List of Volume Shadow Copies"
Write-Output "Getting List of Volume Shadow Copies, Output File = $systemFolderName\$VolumeShadowCopies" | Write-LogMessage
# Run the command
Get-CimInstance -ClassName Win32_ShadowCopy -EA 0 | Select-Object DeviceObject, @{N="CreationDate"; E={$_.ConvertToDateTime($_.InstallDate)}} | Out-File -FilePath $systemFolder\$VolumeShadowCopies


$PrefetchFiles = "prefetch_files.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Prefetch File Information"
Write-Output "Getting Prefetch File Information, Output File = $prefetchFolderName\$PrefetchFiles" | Write-LogMessage
# Run the command
Get-ChildItem -Path "C:\Windows\Prefetch\*.pf" -EA 0 | Select-Object Name, LastAccessTime, CreationTime | Sort-Object LastAccessTime | Format-List | Out-File -FilePath $prefetchFolder\$PrefetchFiles


$DNSCache = "DNS_cache.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Parsing the DNS Cache"
Write-Output "Parsing the DNS Cache, Output File = $systemFolderName\$DNSCache" | Write-LogMessage
# Run both commands and append the output of the second one to the first text file
ipconfig /displaydns | Out-File -FilePath $systemFolder\$DNSCache
ipconfig /displaydns | Select-String "Record Name" | Sort-Object | Out-File -Append -FilePath $systemFolder\$DNSCache


$TempInternetFiles = "temp_internet_files.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Temporary Internet Files (Last 5 days)"
Write-Output "Getting Temporary Internet Files (Last 5 days), Output File = $systemFolderName\$TempInternetFiles" | Write-LogMessage
# Run the command
Get-ChildItem -Recurse -Force "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files" -EA 0 | Select-Object Name, LastWriteTime, CreationTime, Directory | Where-Object {$_.LastWriteTime -gt ((Get-Date).AddDays(-5))} | Sort-Object CreationTime -Desc | Out-File -FilePath $systemFolder\$TempInternetFiles


$StoredCookies = "stored_cookies.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Stored Cookie Information"
Write-Output "Getting Stored Cookie Information, Output File = $systemFolderName\$StoredCookies" | Write-LogMessage
# Run the command
Get-ChildItem -Recurse -Force -EA 0 "$env:APPDATA\Microsoft\Windows\cookies" | Select-Object Name | ForEach-Object {$N=$_.Name; Get-Content "$env:APPDATA\Microsoft\Windows\cookies\$N" -EA 0 | Select-String "/"} | Out-File -FilePath $systemFolder\$StoredCookies


$TypedURLs = "typed_URLs.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Typed URL Data"
Write-Output "Getting Typed URL Data, Output File = $systemFolderName\$TypedURLs" | Write-LogMessage
# Run the command
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$TypedURLs


$InternetSettings = "internet_settings.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Internet Setting Registry Keys"
Write-Output "Getting Internet Setting Registry Keys, Output File = $SystemFileName\$InternetSettings" | Write-LogMessage
# Run the command
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $SystemFile\$InternetSettings


$TrustedInternetDomains = "trusted_internet_domains.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Trusted Internet Domain Registry Keys"
Write-Output "Getting Trusted Internet Domain Registry Keys, Output File = $systemFolderName\$TrustedInternetDomains" | Write-LogMessage
# Run the command
Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains" -EA 0 | Select-Object PSChildName | Out-File -FilePath $systemFolder\$TrustedInternetDomains


$AppInitDllKey = "appinit_dll_key.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting AppInit_DLL Registry Keys"
Write-Output "Getting AppInit_DLL Registry Keys, Output File = $systemFolderName\$AppInitDllKey" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -EA 0 | Select-Object AppInit_DLLs | Out-File -FilePath $systemFolder\$AppInitDllKey


$UACGroupPolicy = "UAC_group_policy.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting UAC Group Policy Settings"
Write-Output "Getting UAC Group Policy Settings Output File = $systemFolderName\$UACGroupPolicy" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$UACGroupPolicy


$ActiveSetup = "active_setup_installs.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Active Setup Installs"
Write-Output "Getting Active Setup Installs, Output File = $systemFolderName\$ActiveSetup" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\*" -EA 0 | Select-Object ComponentID, Version, '(Default)', StubPath | Format-List | Out-File -FilePath $systemFolder\$ActiveSetup


$AppPathRegKeys = "AppPathRegKeys.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting App Path Registry Keys"
Write-Output "Getting App Path Registry Keys, Output File = $systemFolderName\$AppPathRegKeys" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*" -EA 0 | Select-Object PSChildName, '(Default)' | Format-List | Out-File -FilePath $systemFolder\$AppPathRegKeys


$DLLByExplorerOF = "DllsLoadedByExplorerShell.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting List of .dll Files Loaded by Explorer.exe Shell"
Write-Output "Getting List of .dll Files Loaded by Explorer.exe Shell, Output File = $systemFolderName\$DLLByExplorerOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\*\*" -EA 0 | Select-Object '(Default)', DllName | Out-File -FilePath $systemFolder\$DLLByExplorerOF


$ShellUserInitOF = "ShellandUserInitValues.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Shell and UserInit Values"
Write-Output "Getting Shell and UserInit Values, Output File = $systemFolderName\$ShellUserInitOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$ShellUserInitOF


$SVCValuesOF = "SVCValues.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Security Center SVC Values"
Write-Output "Getting Security Center SVC Values, Output File = $systemFolderName\$SVCValuesOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Security Center\Svc" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$SVCValuesOF


$AddBarHstOF = "DesktopAddressBar.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Desktop Address Bar History"
Write-Output "Getting Desktop Address Bar History, Output File = $systemFolderName\$AddBarHstOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$AddBarHstOF


$RunMRUKeyOF = "RunMRUKeyInfo.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting RunMRU Key Information"
Write-Output "Getting RunMRU Key Information, Output File = $systemFolderName\$RunMRUKeyOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$RunMRUKeyOF


$StartMenuData = "start_menu_data.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Start Menu Data"
Write-Output "Getting Start Menu Data, Output File = $systemFolderName\$StartMenuData" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartMenu" -EA 0 | Select-Object * -ExcludeProperty PS* | Format-List | Out-File -FilePath $systemFolder\$StartMenuData


$ProgExeOF = "ProgExeBySessionManager.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Programs Executed by Session Manager"
Write-Output "Getting Programs Executed by Session Manager, Output File = $systemFolderName\$ProgExeOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$ProgExeOF


$ShellFolderInfoOF = "ShellFolderInfo.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Shell Folder Information"
Write-Output "Getting Shell Folder Information, Output File = $systemFolderName\$ShellFolderInfoOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$ShellFolderInfoOF


$StartUpShellInfoOF = "StartUpShellFolderInfo.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting User Startup Shell Folder Information"
Write-Output "Getting User Startup Shell Folder Information, Output File = $systemFolderName\$StartUpShellInfoOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" -EA 0 | Select-Object startup | Out-File -FilePath $systemFolder\$StartUpShellInfoOF


$ShellExtsOF = "ApprovedShellExts.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Approved Shell Extensions"
Write-Output "Getting Approved Shell Extension, Output File = $systemFolderName\$ShellExtsOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$ShellExtsOF


$AppCertsOF = "AppCertDLLs.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting AppCert DLLs"
Write-Output "Getting AppCert DLLs, Output File = $systemFolderName\$AppCertsOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$AppCertsOF


$ExeFileShellsOF = "ExeFileShellCommands.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting EXE File Shell Command Configuration"
Write-Output "Getting EXE File Shell Command Configuration, Output File = $systemFolderName\$ExeFileShellsOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Classes\exefile\shell\open\command" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$ExeFileShellsOF


$ShellCommandsOF = "ShellCommands.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Shell Commands"
Write-Output "Getting Shell Commands, Output File = $systemFolderName\$ShellCommandsOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Classes\http\shell\open\command" -EA 0 | Select-Object '(Default)' | Out-File -FilePath $systemFolder\$ShellCommandsOF


$BCDRelatedOF = "BCDRelatedData.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting BCD Related Data"
Write-Output "Getting BCD Related Data, Output File = $systemFolderName\$BCDRelatedOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\BCD00000000\*\*\*\*" -EA 0 | Select-Object Element | Select-String "exe" | Select-Object Line | Out-File -FilePath $systemFolder\$BCDRelatedOF


$LSAPackOF = "LoadedLSAPackages.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Loaded LSA Packages Data"
Write-Output "Getting Loaded LSA Packages Data, Output File = $systemFolderName\$LSAPackOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -EA 0 | Select-Object * -ExcludeProperty PS* | Out-File -FilePath $systemFolder\$LSAPackOF


$BrowserHelperOF = "BrowserHelperObjects.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Browser Helper Objects"
Write-Output "Getting Browser Helper Objects, Output File = $systemFolderName\$BrowserHelperOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*" -EA 0 | Select-Object '(Default)' | Out-File -FilePath $systemFolder\$BrowserHelperOF


$BrowserHelperx64OF = "BrowserHelperObjectsx64.txt"
Write-Host  "$(Get-Date -Format $dateFormat) | Getting Browser Helper Objects (64 Bit)"
Write-Output "Getting Browser Helper Objects (64 Bit), Output File = $systemFolderName\$BrowserHelperx64OF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*" -EA 0 | Select-Object '(Default)' | Out-File -FilePath $systemFolder\$BrowserHelperx64OF


$IEExtensionsOF = "IEExtensions.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Internet Explorer Extensions Data"
Write-Output "Getting Internet Explorer Extensions Data from the following sources:
            [A]  HKCU:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*
            [B]  HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*
            [C]  HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\*
            Output File = $systemFolderName\$IEExtensionsOF" | Write-LogMessage
# Run the commands
Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*" -EA 0 | Select-Object ButtonText, Icon | Out-File -FilePath $systemFolder\$IEExtensionsOF
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*" -EA 0 | Select-Object ButtonText, Icon | Out-File -Append -FilePath $systemFolder\$IEExtensionsOF
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\*" -EA 0 | Select-Object ButtonText, Icon | Out-File -Append -FilePath $systemFolder\$IEExtensionsOF


$USBDevicesOF = "USBDevices.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting List of USB Devices"
Write-Output "Getting List of USB Devices, Output File = $systemFolderName\$USBDevicesOF" | Write-LogMessage
# Run the command
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -EA 0 | Select-Object FriendlyName, PSChildName, ContainerID | Out-File -FilePath $systemFolder\$USBDevicesOF


# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# DISABLED DURING TESTING
# WILL RE-ENABLE WHEN DONE
# =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+


# $ExeTimelineOF = "TimelineOfExecutables.txt"
# Write-Host "$(Get-Date -Format $dateFormat) | Getting Timeline of Executable Files (Past 10 Days) -- This may take some time to complete..."
# Write-Output "Getting Timeline of Executable Files (Past 10 Days), Output File = $systemFolderName\$ExeTimelineOF" | Write-LogMessage
# # Run the command
# Get-ChildItem -Path C:\ -Recurse -Force -include $executableFiles -EA 0 | Where-Object {-Not $_.PSIsContainer -and $_.LastWriteTime -gt ((Get-Date).AddDays(-10))} | Select-Object FullName, LastWriteTime, @{N="Owner"; E={($_ | Get-ACL).Owner}} | Sort-Object LastWriteTime -Desc | Out-File -FilePath $systemFolder\$ExeTimelineOF


# $DownloadedExesOF = "DownloadedExecutables.txt"
# Write-Host "$(Get-Date -Format $dateFormat) | Getting Downloaded Executable Files"
# Write-Output "Getting Downloaded Executable Files, Output File = $systemFolderName\$DownloadedExesOF" | Write-LogMessage
# # Run the command
# Get-ChildItem -Path C:\ -Recurse -Force -include $executableFiles -EA 0 | ForEach-Object {$P=$_.FullName; Get-Item $P -Stream *} | Where-Object {$_.Stream -match "Zone.Identifier"} | Select-Object filename, stream, @{N = 'LastWriteTime'; E={(Get-ChildItem $P).LastWriteTime}} | Out-File -FilePath $systemFolder\$DownloadedExesOF


# ==================================
# GET DATA FROM WINDOWS EVENT LOGS
# ==================================


$logFolderOF = "AvailableLogFiles.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting List of Available Log Files"
Write-Output "Getting List of Available Log Files, Output File = $logFolderName\$logFolderOF" | Write-LogMessage
# Run the command
Get-WinEvent -ListLog * -EA 0 | Where-Object {$_.IsEnabled} | Select-Object LogName, RecordCount, FileSize, LogMode, LogFilePath, LastWriteTime | Sort-Object -Property @{Expression="RecordCount"; Descending=$true} | Out-File -FilePath $logFolder\$logFolderOF


$EvtLog1002OF = "01002-ApplicationCrashes.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Application Crashes)"
Write-Output "Getting Event Log (Application Crashes), Output File = $logFolderName\$EvtLog1002OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Application"; ID=1002} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog1002OF


$EvtLog1014OF = "01014-FailedDNSResolution.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Failed DNS Resolution Events)"
Write-Output "Getting Event Log (Failed DNS Resolution Events), Output File = $logFolderName\$EvtLog1014OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="System"; ID=1014} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog1014OF


$EvtLog1102OF = "01102-AuditLogCleared.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Audit Log Cleared)"
Write-Output "Getting Event Log (Audit Log Cleared), Output File = $logFolderName\$EvtLog1102OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Application"; ID=1102} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog1102OF


$EvtLog4616OF = "04616-ChangedSystemTime.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Changed System Time)"
Write-Output "Getting Event Log (Changed System Time), Output File = $logFolderName\$EvtLog4616OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4616} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4616OF


$EvtLog4624OF = "04624-AccountLogons.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Account Logon History)"
Write-Output "Getting Event Log (Account Logon History), Output File = $logFolderName\$EvtLog4624OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4624} -EA 0 | Select-Object TimeCreated, ID, TaskDisplayName, Message, UserId, ProcessId, ThreadId, MachineName | Format-List | Out-File -FilePath $logFolder\$EvtLog4624OF


$EvtLog4625OF = "04625-FailedAccountLogons.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Failed Account Logon History)"
Write-Output "Getting Event Log (Failed Account Logon History), Output File = $logFolderName\$EvtLog4625OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4625} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4625OF


$EvtLog4648OF = "04648-LogonUsingExplicitCreds.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Logons Using Explicit Credentials)"
Write-Output "Getting Event Log (Logons Using Explicit Credentials), Output File = $logFolderName\$EvtLog4648OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4648} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4648OF


$EvtLog4672OF = "04672-PrivilegeUse.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Privilege Use ID: 4672)"
Write-Output "Getting Event Log (Privilege Use ID: 4672), Output File = $logFolderName\$EvtLog4672OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4672} -EA 0 | Select-Object TimeCreated, ID, TaskDisplayName, Message, UserId, ProcessId, ThreadId, MachineName | Format-List | Out-File -FilePath $logFolder\$EvtLog4672OF


$EvtLog4673OF = "04673-PrivilegeUse.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Privlege Use ID: 4673)"
Write-Output "Getting Event Log (Privlege Use ID: 4673), Output File = $logFolderName\$EvtLog4673OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50  -FilterHashtable @{Logname="Security"; ID=4673} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4673OF


$EvtLog4674OF = "04674-PrivilegeUse.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Privlege Use ID: 4674)"
Write-Output "Getting Event Log (Privlege Use ID: 4674), Output File = $logFolderName\$EvtLog4674OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4674} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4674OF


$EvtLog4688OF = "04688-ProcessExecution.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Process Execution)"
Write-Output "Getting Event Log (Process Execution), Output File = $logFolderName\$EvtLog4688OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4688} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4688OF


$EvtLog4720OF = "04720-UserAccountCreated.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (User Account Created)"
Write-Output "Getting Event Log (User Account Created), Output File = $logFolderName\$EvtLog4720OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="Security"; ID=4720} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog4720OF


$EvtLog7036OF = "07036-ServiceControlManagerEvents.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Service Control Manager Events)"
Write-Output "Getting Event Log (Service Control Manager Events), Output File = $logFolderName\$EvtLog7036OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="System"; ID=7036} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog7036OF


$EvtLog7045OF = "07045-ServiceCreation.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (Service Creation)"
Write-Output "Getting Event Log (Service Creation), Output File = $logFolderName\$EvtLog7045OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="System"; ID=7045} -EA 0 | Select-Object TimeCreated, ID, Message, UserId, ProcessId, ThreadId, MachineName | Format-List | Out-File -FilePath $logFolder\$EvtLog7045OF


$EvtLog64001OF = "64001-WFPEvent.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Event Log (WFP Event)"
Write-Output "Getting Event Log (WFP Event), Output File = $logFolderName\$EvtLog64001OF" | Write-LogMessage
# Run the command
Get-WinEvent -Max 50 -FilterHashtable @{Logname="System"; ID=64001} -EA 0 | Select-Object TimeCreated, ID, Message | Format-List | Out-File -FilePath $logFolder\$EvtLog64001OF


$AppInvEvtsOF = "AppInventoryEvents.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Application Inventory Events"
Write-Output "Getting Application Inventory Events, Output File = $logFolderName\$AppInvEvtsOF" | Write-LogMessage
# Run the command
Get-WinEvent -LogName Microsoft-Windows-Application-Experience/Program-Inventory -EA 0 | Select-Object TimeCreated, ID, Message | Sort-Object -Property @{Expression="TimeCreated"; Descending=$true} | Format-List | Out-File -FilePath $logFolder\$AppInvEvtsOF


$TermServOF = "TerminalServiceEvents.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Terminal Service Events"
Write-Output "Getting Terminal Service Events, Output File = $logFolderName\$TermServOF" | Write-LogMessage
# Run the command
Get-WinEvent -LogName Microsoft-Windows-TerminalServices-LocalSessionManager/Operational -EA 0 | Select-Object TimeCreated, ID, Message | Sort-Object -Property @{Expression="TimeCreated"; Descending=$true} | Format-List | Out-File -FilePath $logFolder\$TermServOF


# Copying network connections
$NetTCPOF = "NetTCPConnections.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Network Connection Information"
Write-Output "Getting Network Connection Information, Output File = $networkFolderName\$NetTCPOF" | Write-LogMessage
# Run the command
Get-NetTCPConnection -EA 0 | Sort-Object LocalAddress -Desc | Out-File -FilePath $networkFolder\$NetTCPOF


# Copying Hosts file data
$HostsFileOF = "HostsFile.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting *hosts* Data"
Write-Output "Getting *hosts* Data, Output File = $systemFolderName\$HostsFileOF" | Write-LogMessage
# Run the command
Get-Content $env:windir\system32\drivers\etc\hosts | Out-File -FilePath $systemFolder\$HostsFileOF


# Copying Services file data
$ServiceFileOF = "ServiceFile.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting *services* Data"
Write-Output "Getting *services* Data, Output File = $systemFolderName\$ServiceFileOF" | Write-LogMessage
# Run the command
Get-Content $env:windir\system32\drivers\etc\services | Out-File -FilePath $systemFolder\$ServiceFileOF


# Audit Policy
$AuditPolicyOF = "AuditPolicy.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Computer Audit Policy"
Write-Output "Getting Computer Audit Policy, Output File = $systemFolderName\$AuditPolicyOF" | Write-LogMessage
# Run the command
auditpol /get /category:* | Out-File -FilePath $systemFolder\$AuditPolicyOF


# Firewall Config
$FWOF = "FirewallRules.txt"
Write-Host "$(Get-Date -Format $dateFormat) | Getting Firewall Configuration"
Write-Output "Getting Firewall Configuration, Output File = $firewallFolderName\$FWOF" | Write-LogMessage
# Run the command
netsh firewall show config | Out-File -FilePath $firewallFolder\$FWOF


# If the user wanted to get hash values for the saved output files
if ($hashResults -eq "y")
{
    <#
        Setting the initial values of these variables that will be used to replace the
        placeholder text in the HashValues.html file before it is finalized.  The $DataIndex
        variable is set to "-1" because the first value in the .html file should be zero.
    #>
    $global:DataIndex = -1
    $global:FileIndex = 0
    $HashOutputFile = "$resultsFolder\HashValues.html"
    <#
        Creates a temp file to hold the saved html formatted text before it is imported into the main HashValues.html file.
        This file is deleted when it is no longer needed.
    #>
    $TempFile = "$resultsFolder\HashValuesTEMP.html"
    # Get the hash values of all the saved files in the output directory
    Write-Host "`n$(Get-Date -Format $dateFormat) | Hashing saved files. Please wait..." -ForegroundColor Yellow
    Write-Output "Hashing saved files" | Write-LogMessage
    # Write the html file heading and necessary css data from the variables located in the '.\inc\vars.ps1' file
    Write-Output $InfoHtmlFileHeaderSort > $HashOutputFile
    Write-Output $InfoHtmlTableHeaderSort >> $HashOutputFile
    # Command that actually gets the hash values of all the files located in the results folder
    $Cmd = Get-ChildItem -Path $resultsFolder -Recurse -Force -File | Select-Object -Property Name, @{N="FileHash"; E={(Get-FileHash -Algorithm SHA1 $_.FullName).Hash}}, CreationTimeUTC | Sort-Object -Property Name
    <#
        Converts the output of the $cmd variable above to html format and then removes some
        duplicate lines of text that are not needed.
        These lines are replaced by the imported variables from the '.\inc\vars.ps1' file
    #>
    $Info = $Cmd | ConvertTo-Html -Fragment
    $Info = $Info -Replace "<table>", ""
    $Info = $Info -Replace "<colgroup><col/><col/><col/></colgroup>", ""
    $Info = $Info -Replace "<tr><th>Name</th><th>FileHash</th><th>CreationTimeUtc</th></tr>", ""
    $Info = $Info -Replace "</table>", ""
    # Write the output html text to a temporary file
    $Info | Out-File -Append $TempFile
    # Removes blank lines from the temporary file
    (Get-Content $TempFile) | Where-Object {$_.Trim() -ne ""} | Set-Content $TempFile
    # Add two columns to the html text in the temporary file
    (Get-Content $TempFile) -Replace "<tr><td>", "<tr><td class='bs-checkbox'><input data-index='DataPH' name='btSelectItem' type='checkbox'></td><td>FilePH</td><td>" | Set-Content $TempFile
    # Read the content of the temporary file and use Regex to replace the placeholder text of "DataPH" with a 4-digit sequential integer with leading zeros
    $Content = (Get-Content $TempFile)
    $Content | ForEach-Object {[Regex]::Replace($_, "DataPH", {return ($global:DataIndex += 1).ToString("0000")})} | Set-Content $TempFile
    # Read the content of the temporary file and use Regex to replace the placeholder text of "FilePH" with a 4-digit sequential integer with leading zeros
    $Content2 = (Get-Content $TempFile)
    $Content2 | ForEach-Object {[Regex]::Replace($_, "FilePH", {return ($global:FileIndex += 1).ToString("0000")})} | Set-Content $TempFile
    # Read the final contents of the temporary file after all the substitutions have been made and append that text to the bottom of the 
    (Get-Content $TempFile) | Out-File -Append -FilePath $HashOutputFile
    # Write the final variable text to the final html file that was imported from the '.\inc\vars.ps1' file
    Write-Output $InfoHtmlTableFooterSort >> $HashOutputFile
    # Deletes the temporary file because it is no longer needed
    Remove-Item $TempFile
    #===================================================
    # Get-ChildItem -Path $resultsFolder -Recurse -Force -File | Select-Object -Property Directory, BaseName, Extension, PSIsContainer, @{N="SizeInKB"; E={[double]("{0:N2}" -f ($_.Length/1KB))}}, @{N="FileHash"; E={(Get-FileHash $_.FullName).Hash}}, Mode, Attributes, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC | Sort-Object -Property DirectoryName, Name | Sort-Object Directory | ConvertTo-Html | Out-File $resultsFolder\HashValues.html
    #===================================================
    # Hashing of the saved files is completed
    # Display message in the terminal window and write an entry to the log file
    Write-Host "`n$(Get-Date -Format $dateFormat) | File Hashing Completed" -ForegroundColor Yellow
    Write-Output "File Hashing Completed, Output File = \HashValues.html" | Write-LogMessage
}
else
{
    # If the user did not want to get the hash values for the saved output files
    Write-Warning -Message "`nSaved files were not hashed.  Proceeding to run the remainder of the script.`n"
    Write-Output "File hashing was DECLINED by the user.  Output files NOT hashed." | Write-LogMessage
}


# Get the time the script was completed
$duration = (Get-Date) - $startTime
# Calculate the total run time of the script and formats the results
$diff = $duration.ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")
# Gets the date/time when the script is finished running
$durationText = "$(Get-Date -Format "MM-dd-yyyy HH:mm:ss '('K UTC')'") -- Script exection completed."


# Display a message that the script has completed and list the total time run time on the screen
Write-Host "`n$durationText" -ForegroundColor Yellow
Write-Host "[$diff]`n" -ForegroundColor Yellow
Write-Host "The results are available in the following directory:" -ForegroundColor Green
Write-Host "`t$resultsFolder`n" -ForegroundColor Green


# Write the date/time when the script finished and the total execution time to the log file
Write-Output "`n$durationText`n" | Write-LogMessage
Write-Output "Total execution time : [$diff]`n" | Write-LogMessage
Write-Output "--- END SCRIPT LOG FILE ---" | Write-LogMessage


# Popup message upon completion
# (New-Object -ComObject wscript.shell).popup("The Script has finished running")


<# TO ADD TO SCRIPT
--> Check system directories for executables not signed as part of an operating system release
    Get-ChildItem -Path "C:\Windows\*\*.exe" -File -Force | Get-AuthenticodeSignature | ? {$_.IsOSBinary -notmatch 'True'}
    ANOTHER VERSION OF THE ABOVE COMMAND:
    Get-ChildItem -Force -Recurse -Path "C:\Windows\*\*.exe" -File | Get-AuthenticodeSignature | Where-Object {$_.status -eq "Valid"}

    get-childitem -Recurse -include *.exe | Select-Object -Property Name, Directory, @{N = 'FileHash'; E = {(Get-FileHash $_.FullName).Hash}}, CreationTimeUtc, LastAccessTimeUtc | ConvertTo-Html | Out-File -FilePath "C:\Users\VSP\Desktop\EXETestdoc.html"
#>
