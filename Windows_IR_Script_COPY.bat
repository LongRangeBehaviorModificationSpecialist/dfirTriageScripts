@ECHO off
REM ========================================
REM SAMPLE WINDOWS INCIDENT RESPONSE SCRIPT
REM Originally created by Magnet Forensics
REM Modified By : MikeSpon
REM DLU : 2021-12-03
REM ========================================

IF NOT EXIST TEMP MKDIR TEMP 
DEL /F /Q TEMP\*.*


REM Setup the variable for the results folder
ECHO.
ECHO     Setting up variable for the folder

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$date = Get-Date -format yyyyMMdd_HHmmss; $name = $env:computername; $FQDN = $env:userdnsdomain; $IP = test-connection $name -timetolive 2 -count 1; $ip=$ip.ipv4address | Select-Object -ExpandProperty IPAddressToString; $logfile = $date + \"_\"+ $IP + \"_\"+ $name + $FQDN " $logfile > temp\temp.txt

REM Convert the powershell variable to a batch variable
type temp\temp.txt > temp\temp2.txt
FOR /F %%B in (temp\temp2.txt) do SET FOLDER=%%B

SET TIMESTAMP=%DATE:~4,2%-%DATE:~7,2%-%DATE:~10,4% %TIME:~0,2%:%TIME:~3,2%:%TIME:~6,2%

@REM SET TIMESTAMP=%DATE:~6,4%_%DATE:~3,2%_%DATE:~0,2% | %TIME:~0,2%:%TIME:~3,2%:%TIME:~6,2%

REM Set up the LINE variable to use later in the program
set LINE==========================================

ECHO.
ECHO %LINE%
ECHO.
ECHO     OUTPUT FOLDER NAME  :  %FOLDER%
ECHO     TIME                :  %TIMESTAMP%
ECHO     ComputerName        :  %ComputerName%
ECHO     Username            :  %UserName%
ECHO     Start Date          :  %ScanStartDate%
ECHO.
ECHO %LINE%
ECHO.
ECHO --Configuring Script Logging

REM Create the output folders to organize the results files
ECHO.
ECHO %LINE%
ECHO.
ECHO --Creating RAM output directories
ECHO.
ECHO %LINE%
MKDIR %FOLDER%\CONFIG
MKDIR %FOLDER%\RAM


REM Get the date and time this script was run and save info as "stopdate" and "stoptime"
For /F "tokens=*" %%a in ('date /t') do SET startdate=%%a
For /F "tokens=*" %%a in ('time /t') do SET starttime=%%a

ECHO.
ECHO --Writing the Configuration File

REM Get the value of the %USERPROFILE% variable - the current Windows user
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO The User Profile Used: %USERPROFILE% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt

ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt

REM Print the startdate and starttime variables to the log file
ECHO Start Date: %startdate% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO Start Time: %starttime% >> %FOLDER%\CONFIG\collection_log_file.txt

REM Add formatting to the collection_log_file
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt


GOTO SKIPRAM

set /P CAPTURERAM=Do you want to capture a RAM Image? (enter "y" or "n"): 

REM Review the value entered by the user
ECHO.
    if /i {%CAPTURERAM%}=={y} (goto :ACQUIRERAM)

goto NOACQUIRERAM

:ACQUIRERAM

REM Collect Computer RAM
ECHO.
ECHO Now collecting RAM, this may take a hot minute. . .
ECHO.

REM Launch MAGNET RAM Capture
COPY BIN\MAGNET\MagnetRAMCapture.exe %FOLDER%\RAM
START "" "%FOLDER%\RAM\MagnetRAMCapture.exe" /accepteula /go /silent

REM Wait to run any additional commands until RAM is collected
:CheckRun
TIMEOUT 5 >NUL
tasklist /FI "IMAGENAME eq MagnetRAMCapture.exe" 2>NUL | find /I /N
"MagnetRAMCapture.exe">NUL
if "%ERRORLEVEL%"=="0" goto CheckRun

REM Stop Service
net stop ieframdump

DEL /F /Q %FOLDER%\RAM\*.tmp
DEL /F /Q %FOLDER%\RAM\*.exe
:DONERAM

:NOACQUIRERAM
ECHO     Proceeding without acquiring computer RAM . . .

:SKIPRAM

REM Create the remaining output folders
ECHO.
ECHO --Creating the remaining output directories
MKDIR %FOLDER%\FIREWALL
MKDIR %FOLDER%\NETWORK
MKDIR %FOLDER%\PREFETCH
MKDIR %FOLDER%\PROCESS
MKDIR %FOLDER%\PROCESSCAPTURE
MKDIR %FOLDER%\SERVICES
MKDIR %FOLDER%\SYSTEM
MKDIR %FOLDER%\WIRELESS

REM Make System Report
ECHO.
ECHO --Gathering Basic System Information

ECHO     %TIMESTAMP% -- Running "msinfo32" for SystemInformationFullReport.txt report
msinfo32 /report %FOLDER%\SYSTEM\SystemInformationFullReport.txt

REM Get the local computer name
ECHO     %TIMESTAMP% -- Getting local computer name
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "\"ComputerName: \" + $env:COMPUTERNAME" >> %FOLDER%\SYSTEM\System_Information.txt

REM ==================================
REM COULD ALSO TRY THE BELOW COMMAND
REM ==================================
REM Get-CimInstance Win32_OperatingSystem | Select-Object  Caption, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice,  BuildNumber, CSName | FL

REM Get-CimInstance -ClassName Win32_Process
REM Get-CimInstance -ClassName Win32_Product  <--INSTALLED APPLICATIONS (Need to widen columns to show all data)
REM Get-CimInstance -ClassName Win32_Product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage
REM Get-CimClass | Where-Object CimClassName -like Win32_Comp*


REM The command below will get more information about active processes
REM Get-WmiObject win32_process | select processname,@{NAME='CreationDate';EXPRESSION={$_.ConvertToDateTime($_.CreationDate)}},ProcessId,CommandLine | sort CreationDate -desc | format-table –auto -wrap

REM



REM Get System Manufacturer
ECHO     %TIMESTAMP% -- Getting System Manufacturer
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysInfo = Get-WmiObject -Class Win32_ComputerSystem -namespace root/CIMV2 | Select Manufacturer,Model; $SysManufacturer = $SysInfo.Manufacturer; \"System Manufacturer:\" + $SysManufacturer" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get System Model
ECHO     %TIMESTAMP% -- Getting System Model
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysInfo = Get-WmiObject -Class Win32_ComputerSystem -namespace root/CIMV2 | Select Manufacturer,Model; $SysModel = $SysInfo.Model; \"System Model:\" + $SysModel" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get HDD Serial number
ECHO     %TIMESTAMP% -- Getting HDD Serial Number
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$HardSerial = Get-WMIObject Win32_BIOS -Computer $env:COMPUTERNAME | select SerialNumber; $HardSerialNo = $HardSerial.SerialNumber; \"Serial Number:\" + $HardSerialNo" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get OS Information
ECHO     %TIMESTAMP% -- Getting OS information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$OS = (Get-WmiObject Win32_OperatingSystem -computername $env:COMPUTERNAME ).caption; \"Operating System:\" + $OS" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get System uptime
ECHO     %TIMESTAMP% -- Getting System uptime
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysBootTime = Get-WmiObject Win32_OperatingSystem; $BootTime = $SysBootTime.ConvertToDateTime ($SysBootTime.LastBootUpTime); \"System Uptime:\" + $BootTime" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get RAM size
ECHO     Getting RAM size
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysRam = Get-WmiObject -Class Win32_OperatingSystem -computername $env:COMPUTERNAME | Select TotalVisibleMemorySize; $Ram = [Math]::Round($SysRam.TotalVisibleMemorySize/1024KB); \"System RAM:\" + $Ram +\" GB\"" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get CPU information
ECHO     Getting CPU information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysCpu = Get-WmiObject Win32_Processor | Select Name; $Cpu = $SysCpu.Name; \"Processor:\" + $Cpu" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get OS Serial Number
ECHO     Getting OS Serial Number
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysSerialNo = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $env:COMPUTERNAME);$SerialNo = $SysSerialNo.SerialNumber; \"OS Serial Number:\" + $SerialNo" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get Username
ECHO     Getting Username
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "\"Username: \" + $env:USERNAME" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get Domain information
ECHO     Getting Domain information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "\"Account Domain: \" + $env:USERDOMAIN" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get User's SID
ECHO     Getting User's SID and
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$UserInfo = Get-WmiObject -Class Win32_UserAccount -namespace root/CIMV2 | Where-Object {$_.Name -eq $env:UserName}| Select AccountType,SID,PasswordRequired; $UserPass = $UserInfo.PasswordRequired; $UserSid = $UserInfo.SID; \"User SID: \" + $UserSid" >> %FOLDER%\SYSTEM\System_Information.txt

REM Determine is User is an Admin
ECHO     Determining if User has Admin privileges
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'); \"Current User is Admin:\" + $IsAdmin" >> %FOLDER%\SYSTEM\System_Information.txt

REM Determine if the User has a password
ECHO     Determining if User has a password set
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$UserInfo = Get-WmiObject -Class Win32_UserAccount -namespace root/CIMV2 | Where-Object {$_.Name -eq $env:UserName}| Select AccountType,SID,PasswordRequired; $UserPass = $UserInfo.PasswordRequired; \"Password Required:\" + $UserPass" >> %FOLDER%\SYSTEM\System_Information.txt

REM Determine if a firewall is active
ECHO     Determining if a firewall is active
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$Firewall = New-Object -com HNetCfg.FwMgr ; $FireProfile = $Firewall.LocalPolicy.CurrentProfile ; $FireProfile = $FireProfile.FirewallEnabled; \"Firewall Service is Active:\" + $FireProfile" >> %FOLDER%\SYSTEM\System_Information.txt

REM Save other OS information to a seperate file
ECHO     Gathering other relevant OS information
set > %FOLDER%\SYSTEM\System_Environment.txt

REM Get list of OS information using Windows native WMIC command
%windir%\System32\Wbem\wmic os get Caption, CSDVersion, CSName, CurrentTimeZone, InstallDate, LocalDateTime > %FOLDER%\SYSTEM\System_OS_Info.txt

REM Get Network hardware information
ECHO     Gathering Network hardware information
%windir%\System32\Wbem\wmic nicconfig get description,IPAddress,MACaddress /format:CSV | findstr /I /C:":" >> %FOLDER%\SYSTEM\System_Network_Hardware_Info.txt

REM Get computer information and save to a file
ECHO     Getting computer information
%windir%\System32\Wbem\wmic csproduct get vendor,name,version,identifyingnumber,uuid,description,skunumber /value /format:CSV > %FOLDER%\SYSTEM\Computer_Make_Model_SN.txt

REM Get list of installed OS patches
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
ECHO     Getting list of installed OS patches
%windir%\System32\Wbem\wmic qfe list /format:CSV > %FOLDER%\SYSTEM\System_Patches.csv

REM Get timezone information
ECHO     Getting timezone information
%windir%\System32\Wbem\wmic timezone list brief /format:CSV > %FOLDER%\SYSTEM\System_TimeZone.txt

REM Get time zone info via another method
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "[System.TimeZoneInfo]::Local > %FOLDER%\System\System_TimeZone2.txt"

REM Get list of local account users
ECHO     Getting list of local account users
%windir%\System32\Wbem\wmic useraccount list full > %FOLDER%\SYSTEM\UserAccounts_Full.txt

REM Get list of autorun programs
ECHO     Getting list of autorun programs
REM MAS - CHANGED FILE TYPE FROM .txt to .csv
%windir%\System32\Wbem\wmic startup list brief /format:CSV > %FOLDER%\SYSTEM\AutoStartup_Programs.csv
REM ADDED BY MAS
%windir%\System32\Wbem\wmic startup list full /format:CSV > %FOLDER%\SYSTEM\AutoStartup_Programs_Full.txt

REM Get list of Event Logs
ECHO     Getting list of Windows Event Logs
%windir%\System32\Wbem\wmic nteventlog get name /format:CSV > %FOLDER%\SYSTEM\System_Event_Log_List.txt

REM Get Domain information using Windows native WMIC command
ECHO     Getting NTDomain information
%windir%\System32\Wbem\wmic ntdomain list brief /format:CSV > %FOLDER%\SYSTEM\NTDomain_Info.txt

REM Get list of services
ECHO     Getting list of services
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
%windir%\System32\Wbem\wmic service list config /format:CSV > %FOLDER%\SYSTEM\Services_List.csv

REM Get list of drive information
ECHO     Getting drive information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-PSDrive -PSProvider FileSystem | export-csv -path %FOLDER%\SYSTEM\Drive_List.txt"

REM Get detailed drive list information
ECHO     Getting detailed drive list information
%windir%\System32\Wbem\wmic diskdrive list /format:csv > %FOLDER%\SYSTEM\Drive_List_Detailed.txt

REM Get last boot time
ECHO     Getting last boot time
%windir%\System32\Wbem\wmic os get lastbootuptime > %FOLDER%\SYSTEM\System_LastBootUpTime.txt

REM Get boot configuration
REM ADDED BY MAS
ECHO     Getting boot configuration
%windir%\System32\Wbem\wmic bootconfig list full > %FOLDER%\SYSTEM\System_BootConfig.txt

REM Get list of scheduled tasks
ECHO     Getting list of scheduled tasks
schtasks /query /FO CSV /V > %FOLDER%\SYSTEM\TaskScheduler.csv


REM Gather running processes on the machine
ECHO.
ECHO --Gathering Running Processes Information

REM Get list of the running processes, PID, PPID, Command Line, and Created Date
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
ECHO     Getting list of running processes
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "gwmi win32_process | select Name, ProcessID, ParentProcessID, CommandLine, CreationDate | export-csv -path %FOLDER%\PROCESS\Process_List.csv"

REM Get list of the running processes
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "get-process | Format-List ProcessName, id, path | export-csv -path %FOLDER%\PROCESS\Process_List_Path.txt"

REM Get list of running processes using Windows native WMIC command
%windir%\System32\Wbem\wmic process list status /format:CSV > %FOLDER%\PROCESS\Process_List_Status.txt

REM Getting a list of running processes - could be used to attempt to locate hidden processes.
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
%windir%\System32\Wbem\wmic process list memory /format:CSV > %FOLDER%\PROCESS\Process_List_Memory.csv

REM Getting a list of running processes - could be used to attempt to locate hidden processes.
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
%windir%\System32\Wbem\wmic process list full /format:CSV > %FOLDER%\PROCESS\Process_List_Verbose.csv

REM Using tasklist to display a list of currently running processes
REM The "/V" is for verbose and "/FO" is output as a CSV.
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
tasklist /V /FO CSV > %FOLDER%\PROCESS\Process_TaskList_Verbose.csv

REM Using tasklist display a list of currently running processes
REM The "/M" is for listing the loaded modules and "/FO" is output as a CSV
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
tasklist /M /FO CSV > %FOLDER%\PROCESS\Process_TaskList_Loaded_Modules.csv


REM Gather running services on the machine
ECHO.
ECHO --Gathering Services Information

REM Export out the services information as a CSV
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "get-service | export-csv -path %FOLDER%\SERVICES\Service_list.csv"


REM Gather scheduled processes on the machine
ECHO.
ECHO --Gathering Scheduled Processes Information

REM Export out the scheduled tasks information as a CSV
ECHO     Exporting scheduled tasks information to .csv file
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Command -Module export-ScheduledTask > %FOLDER%\PROCESS\Scheduled_Process.txt"

REM Export out the scheduled jobs
ECHO     Exporting list of scheduled jobs to .txt file
%windir%\System32\Wbem\wmic job list brief /format:CSV > %FOLDER%\PROCESS\Scheduled_Job_List.txt


REM Gather network information
ECHO.
ECHO --Gathering Network Information

REM WMIC command to export out the Network info
ECHO     Exporting NetClient Information
%windir%\System32\Wbem\wmic netclient list brief /format:CSV > %FOLDER%\NETWORK\Network_Client.txt

REM The ETC hosts file exists to perform local DNS translations
REM Altering this file could be part of a MITM attack
ECHO     Copying "C:\Windows\system32\drivers\etc\hosts" file
type %windir%\system32\drivers\etc\hosts > %FOLDER%\NETWORK\etc_hosts_file.txt

REM Similar to the above file, the ETC\ networks file works in the same manner
ECHO     Copying "C:\Windows\system32\drivers\etc\networks" file
type %windir%\system32\drivers\etc\networks > %FOLDER%\NETWORK\etc_networks_file.txt

REM Using Windows net command to get network information
ECHO     Running "net user"
%windir%\system32\net user > %FOLDER%\NETWORK\Net_User.txt

REM Net use command lists shares
ECHO     Running "net use"
%windir%\system32\net use > %FOLDER%\NETWORK\Net_Use.txt

REM The ipconfig displays networking information and all cached DNS requests
ECHO     Running "ipconfig /displaydns"
%windir%\system32\ipconfig /displaydns > %FOLDER%\NETWORK\DNS_Cache.txt

REM The net start command shows which services have been started
ECHO     Running "net start"
%windir%\system32\net start > %FOLDER%\NETWORK\Network_Services.txt

REM The netstat command displays networking information for TCP
REM The "-an" switch lists all connections in numerical output
REM The netstat -s command lists the statistics -- see how much data was transmitted
REM The netstat -anbo is similar to the -an command above
REM The "-b" lists the executable involved in creating the port/connection
REM The "-o" lists the owning process ID associated with each connection
ECHO     Running "netstat" with various switches
%windir%\system32\netstat -an >> %FOLDER%\NETWORK\Network_netstat.txt
%windir%\system32\netstat -s >> %FOLDER%\NETWORK\Network_netstat.txt
%windir%\system32\netstat -anbo >> %FOLDER%\NETWORK\Network_netstat.txt

REM The arp command displays and modifies the IP-to-Physical address translation tables
ECHO     Running "arp -a"
%windir%\system32\arp -a >> %FOLDER%\NETWORK\Network_ARP_info.txt

REM The NBSTAT command is for older version of Windows - lists netbios names over TCP
ECHO     Running "nbtstat" with various parameters
%windir%\system32\nbtstat -s >> %FOLDER%\NETWORK\Network_nbtstat_info.txt
%windir%\system32\nbtstat -c >> %FOLDER%\NETWORK\Network_nbtstat_info.txt
%windir%\system32\nbtstat -rn >> %FOLDER%\NETWORK\Network_nbtstat_info.txt

REM Lists WIFI SSID and passwords
ECHO     Getting list of Wifi SSIDs and passwords
netsh wlan show profiles * | findstr /l :"SSID name" > temp\WLAN_DUMP.txt
    for /F "tokens=4*" %%i in (temp\WLAN_DUMP.txt) do (
        echo [SSID] :: %%i %%j >> %FOLDER%\NETWORK\WLAN_keys.txt
        netsh wlan show profile name=%%i %%j key=clear | findstr "Security " >> %FOLDER%\NETWORK\WLAN_keys.txt
        netsh wlan show profile name=%%i %%j key=clear | findstr /l :"Key Content" >> %FOLDER%\NETWORK\WLAN_keys.txt
        echo ---------------------------------------------------- >> %FOLDER%\NETWORK\WLAN_keys.txt)


REM Gather Firewall information
ECHO.
ECHO --Gathering Firewall Information
netsh advfirewall firewall show rule name=all verbose >> %FOLDER%\FIREWALL\Rules_Firewall.txt


REM Gather Prefetch information
ECHO.
ECHO --Gathering Prefetch Information
dir /b /s %windir%\Prefetch\*.pf > %FOLDER%\PREFETCH\Prefetch_List.txt


REM Gather Wifi information
ECHO.
ECHO --Gathering Wifi History Information
REM Looking for any xml files present in the path and string search them for the keyword <name>
FINDSTR /I /C:"<name>" /S C:\ProgramData\Microsoft\Wlansvc\*.xml >> %FOLDER%\WIRELESS\WiFiHistory.txt

GOTO SKIPPROCESSCAPTURE
REM Gather Processes information
ECHO.
ECHO --Gathering Processes Information

REM This will run the MagnetProcessCapture the /saveall is saving the data in the folder specified
BIN\MagnetProcessCapture\MagnetProcessCapture.exe /saveall "%FOLDER%\PROCESSCAPTURE"
:SKIPPROCESSCAPTURE

REM Get the date and time this script was completed and save info as "stopdate" and "stoptime"
For /F "tokens=*" %%a in ('date /t') do set stopdate=%%a
For /F "tokens=*" %%a in ('time /t') do set stoptime=%%a

ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt

REM Print the stopdate and stoptime variables to the log file
ECHO Stop Date: %stopdate% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO Stop Time: %stoptime% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt


REM Ask the user if they want to image the drive
REM The set /p command is looking for something to set at a variable
REM The /p is pause, it is waiting on the user to enter something
ECHO.
ECHO ***** BASIC INFORMATION COLLECTION COMPLETE *****
ECHO.
set /P DRIVEDUMP=Do you want to image a drive? (yes/no)

REM Review the value entered by the user
REM This is trying to guess what the user will enter
ECHO.
ECHO %LINE%
ECHO.
    if /i {%DRIVEDUMP%}=={y} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={Y} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={yes} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={Yes} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={YES} (goto :IMAGEDRIVE)
goto NOIMAGEDRIVE

CLS
:IMAGEDRIVE
    REM If any of the yes options are selected, then launch MAGNET Acquire
    BIN\MagnetAcquire\Acquire.exe

:NOIMAGEDRIVE

REM Clean up the temp directory
RMDIR /Q /S TEMP

PAUSE
