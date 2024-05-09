@ECHO off
REM ========================================
REM SCRIPT COMBINED FROM THE SAMPLE WINDOWS INCIDENT
REM RESPONSE SCRIPT FROM THE MAGNET FORENSICS AX310 CLASS 
REM AND THE POWERSHELL IR RESPONSE SCRIPT CREATED BY 
REM Author : Sajeev.Nair, Email : Nair.Sajeev@gmail.com
REM Version : 2.0 for PowerShell V2
REM Modified By : Mike Spon
REM DLU : 2021-12-05
REM ========================================

IF NOT EXIST TEMP MKDIR TEMP 
DEL /F /Q TEMP\*.*


ECHO.
ECHO =========================================================================
ECHO.
ECHO Data acquisition started.  Please wait - this may take a hot minute . . .
ECHO.
ECHO =========================================================================
ECHO.


REM Setup the variable for the results folder
ECHO --Setting up variable for the folder

@REM PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$date = Get-Date -format yyyyMMdd_HHmmss; $name = $env:computername; $FQDN = $env:userdnsdomain; $IP = Test-Connection $name -timetolive 2 -count 1; $ip=$ip.ipv4address | Select-Object -ExpandProperty IPAddressToString; $logfile = $date + \"_\"+ $IP + \"_\"+ $name + $FQDN; $logfile > TEMP\temp.txt"
SET DATE = PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$date = Get-Date -format yyyyMMdd_HHmmss"


@REM PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$date = get-date -format yyyyMMdd_HHmmss; $name = $env:computername; $FQDN = $env:userdnsdomain; $IP = test-connection $name -timetolive 2 -count 1; $ip=$ip.ipv4address | select-Object -ExpandProperty IPAddressToString; $logfile = $date + \"_\"+ $IP + \"_\"+ $name + $FQDN; $logfile > temp\temp.txt"

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$ComputerName = (Get-Item env:\Computername).Value > temp\CNtemp.txt"

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$UserName = (Get-Item env:\UserName).value > temp\UNtemp.txt"

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$Date = (Get-Date).ToString('yyyy-MM-dd') > temp\DateTemp.txt"


@REM REM Convert the powershell variable to a batch variable
@REM TYPE temp\temp.txt > temp\temp2.txt
@REM FOR /F %%B in (temp\temp.txt) do SET FOLDER=%%B

@REM TYPE temp\CNTemp.txt > temp\CNTemp2.txt
@REM FOR /F %%B in (temp\CNtemp.txt) do SET ComputerName=%%B
@REM TYPE temp\UNTemp.txt > temp\UNTemp2.txt
@REM FOR /F %%B in (temp\UNtemp.txt) do SET UserName=%%B
@REM TYPE temp\DateTemp.txt > temp\DateTemp2.txt
@REM FOR /F %%B in (temp\Datetemp2.txt) do SET ScanStartDate=%%B


REM Set up the LINE variable to use later in the program
SET LINE==========================================

REM Displaying variables for the script

ECHO.
ECHO %LINE%
ECHO.
ECHO OUTPUT FOLDER NAME  :  %FOLDER%
ECHO ComputerName        :  %ComputerName%
ECHO Username            :  %UserName%
ECHO Start Date          :  %ScanStartDate%
ECHO.
ECHO %LINE%
ECHO.
ECHO Configuring Script Logging

REM Create the output folders to organize the results files
ECHO.
ECHO Creating RAM output directories
MKDIR %FOLDER%\--CONFIG
MKDIR %FOLDER%\--HTMLResults
MKDIR %FOLDER%\--RAM

REM Get the date and time this script was run and save info as "StartDate" and "StartTime"
FOR /F "tokens=*" %%a in ('date /t') do SET StartDate=%%a
FOR /F "tokens=*" %%a in ('time /t') do SET StartTime=%%a


ECHO.
ECHO --Writing the Configuration File

REM Get the value of the %USERPROFILE% variable - the current Windows user
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO The User Profile used: %USERPROFILE% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt

ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt

REM Print the StartDate and StartTime variables to the log file
ECHO Start Date: %ScanStartDate% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO Start Time: %StartTime% >> %FOLDER%\CONFIG\collection_log_file.txt

REM Add formatting to the collection_log_file
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt


REM =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
REM
REM RAM CAPTURE SECTION
REM
REM =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=

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
COPY bin\MagnetRAMCapture.exe %FOLDER%\RAM
START "" "%FOLDER%\bin\MagnetRAMCapture.exe" /accepteula /go /silent

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
ECHO Proceeding without acquiring computer RAM. . .

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
ECHO --Running "msinfo32" for SystemInformationFullReport.txt report
msinfo32 /report %FOLDER%\SYSTEM\SystemInformationFullReport.txt

REM Setting HTML report format
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$head = '<style> BODY { font-family:caibri; background-color:dodgerblue; } TABLE { border-width:1px; border-style:solid; border-color:black; border-collapse:collapse; margin-bottom: 1.5em; } TH { font-size:1.1em; border-width:1px; padding:2px; border-style:solid; border-color:black; background-color:PowderBlue } TD { border-width:1px; padding:2px; border-style:solid; border-color:black; background-color:white } h1, h4 { text-align:center; font-family:Arial; } h2 { margin-bottom:0px; margin-block-start: 0em; margin-block-end: 0em; } h5 {margin-block-start: 0em; margin-block-end: 0em; } </style>'; ConvertTo-Html -Head $head -Title 'Live Response Script for %ComputerName%.%UserName%' -Body '<h1> Live Forensics Script Report </h1> <h4> Computer Name : %ComputerName% </h4> <h4> User ID : %UserName% </h4>'" > %FOLDER%\HTMLResults\Results.html

REM Main Routine
REM Record start time of collection
ECHO --Writing Script Start Date and Time
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Date | Select-Object DateTime | ConvertTo-html -Body '<h2> Script Began Date and Time </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Getting System Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "systeminfo /FO CSV | ConvertFrom-Csv | Select-Object * -ExcludeProperty 'Hotfix(s)', 'Network Card(s)' | ConvertTo-html -Body '<h2> System Information </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Getting User Accounts and Current Login Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_UserProfile | Select-Object LocalPath, SID, @{NAME = 'last used'; EXPRESSION = { $_.ConvertToDateTime($_.lastusetime) } } | ConvertTo-html -Body '<h2> User Accounts and Current Login Information </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Network Configuration Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq 'True' } | Select-Object DHCPEnabled, @{Name = 'IpAddress'; Expression = { $_.IpAddress -join '; ' } }, @{Name = 'DefaultIPgateway'; Expression = { $_.DefaultIPgateway -join ';' } }, DNSDomain | ConvertTo-html -Body '<h2> Network Configuration Information </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Startup Applications
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_StartupCommand | Select-Object command, user, caption | ConvertTo-html -Body '<h2> Startup Applications (1) </h2> <h5> FROM: Get-WmiObject -ea 0 Win32_StartupCommand </h5>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\run' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Startup Applications (2) - Additional For 64 Bit Systems </h2> <h5> FROM: hklm:\software\wow6432node\microsoft\windows\currentversion\run </h5>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Startup Applications (3) - Additional For 64 Bit Systems </h2> <h5> FROM: hklm:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run </h5>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\software\wow6432node\microsoft\windows\currentversion\runonce' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Startup Applications (4) - Additional For 64 Bit Systems (Run Once) </h2> <h5> FROM: hklm:\software\wow6432node\microsoft\windows\currentversion\runonce </h5>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\run' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Startup Applications (5) - Additional For 64 Bit Systems </h2><h5> FROM: hkcu:\software\wow6432node\microsoft\windows\currentversion\run </h5>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Startup Applications (6) - Additional For 64 Bit Systems </h2><h5> FROM: hkcu:\software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run </h5>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Startup Applications (7) - Additional For 64 Bit Systems </h2> <h5> FROM: hkcu:\software\wow6432node\microsoft\windows\currentversion\runonce </h5>'" >> %FOLDER%\HTMLResults\Results.html


ECHO --Gathering Running Processes
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 win32_process | Select-Object processname, @{NAME = 'CreationDate'; EXPRESSION = { $_.ConvertToDateTime($_.CreationDate) } }, ProcessId, ParentProcessId, CommandLine, sessionID | Sort-Object ParentProcessId -desc | ConvertTo-html -Body '<h2> Running Processes Sorted by ParentProcessID </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Running SVCHOST and Associated Process
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 win32_process | Where-Object { $_.name -eq 'svchost.exe' } | Select-Object ProcessId | foreach-object { $P = $_.ProcessID ; Get-WmiObject win32_service | Where-Object { $_.processId -eq $P } | Select-Object processID, name, DisplayName, state, startmode, PathName } | ConvertTo-html -Body '<h2> Running SVCHOST and Associated Processes </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Running Services
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 win32_Service | Select-Object Name, ProcessId, State, DisplayName, PathName | Sort-Object state | ConvertTo-html -Body '<h2> Running Services - Sorted by State </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Running Driver Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "driverquery.exe /v /FO CSV | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', Path | Sort-Object Path | ConvertTo-html -Body '<h2> Drivers Running, Startup Mode and Path - Sorted by Path </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Last 50 .dll Files Created
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -r -ea 0 C:\ -include *.dll | Select-Object Name, CreationTime, LastAccessTime, Directory | Sort-Object CreationTime -desc | Select-Object -first 50 | ConvertTo-html -Body '<h2> Last 50 DLLs Created - Sorted by CreationTime </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of Open Files
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "openfiles /query" > %FOLDER%\%ScanStartDate%_%ComputerName%_%UserName%_OpenFiles.txt

ECHO --Gathering Open Shares
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_Share | Select-Object name, path, description | ConvertTo-html -Body '<h2> Open Shares </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Mapped Drives
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\Software\Microsoft\Windows\CurrentVersion\explorer\Map Network Drive MRU' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Mapped Drives </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of Scheduled Jobs
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_ScheduledJob | ConvertTo-html -Body '<h2> Scheduled Jobs </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Schedule Task Events
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "get-winevent -ea 0 -logname Microsoft-Windows-TaskScheduler\Operational | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Scheduled Task Events </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Applied HotFiles
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-HotFix -ea 0 | Select-Object HotfixID, Description, InstalledBy, InstalledOn | Sort-Object InstalledOn -Descending | ConvertTo-html -Body '<h2> HotFixes Applied - Sorted by Installed Date </h2>'" >> %FOLDER%\HTMLResults\Results.html


REM =+=+=+=+=+=+=+=+=+=+=  ADD OTHER REGISTRY KEYS TO THIS SCRIPT HERE =+=+=+=+=+=+=+=+=+=+=


ECHO --Gathering Installed Applications (Sorted by Installed Date)
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation | Sort-Object InstallDate -Desc | ConvertTo-html -Body '<h2> Installed Applications -Sorted by Installed Date </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Link File Analysis (last 5 days)
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_ShortcutFile | Select-Object FileName, caption, @{NAME = 'CreationDate'; EXPRESSION = { $_.ConvertToDateTime($_.CreationDate) } }, @{NAME = 'LastAccessed'; EXPRESSION = { $_.ConvertToDateTime($_.LastAccessed) } }, @{NAME = 'LastModified'; EXPRESSION = { $_.ConvertToDateTime($_.LastModified) } }, Target | Where-Object { $_.lastModified -gt ((Get-Date).addDays(-5)) } | Sort-Object LastModified -Descending | ConvertTo-html -Body '<h2> Link File Analysis - Last 5 days </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of Compressed Files
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path C:\ -r -Force -ea 0 -include $ExecutableFiles | Where-Object { $_.Attributes -band [IO.FileAttributes]::Compressed } | ConvertTo-html -Body '<h2> Compressed Files </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of Encrypted Files
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path C:\ -r -Force -ea 0 -include $ExecutableFiles | Where-Object { $_.Attributes -band [IO.FileAttributes]::Encrypted } | ConvertTo-html -Body '<h2> Encrypted Files </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of Volume Shadow Copies
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_ShadowCopy | Select-Object DeviceObject, @{NAME = 'CreationDate'; EXPRESSION = { $_.ConvertToDateTime($_.InstallDate) } } | ConvertTo-html -Body '<h2> ShadowCopy List </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Prefetch File Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -path 'C:\windows\prefetch\*.pf' -ea 0 | Select-Object Name, LastAccessTime, CreationTime | Sort-Object LastAccessTime | ConvertTo-html -Body '<h2> Prefetch Files </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Parsing the DNS Cache
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "ipconfig /displaydns | Select-String 'Record Name' | Sort-Object | ConvertTo-html -Body '<h2> DNS Cache </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of Available Log Files
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -ea 0 -ListLog * | Where-Object { $_.IsEnabled } | Sort-Object -Property LastWriteTime -Descending | Select-Object LogName, FileSize, LastWriteTime | ConvertTo-html -Body '<h2> List of Available Logs </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Temporary Internet Files (Last 5 days)
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$la = $env:LOCALAPPDATA ; Get-ChildItem -r -ea 0 $la\Microsoft\Windows\'Temporary Internet Files' | Select-Object Name, LastWriteTime, CreationTime, Directory | Where-Object { $_.lastwritetime -gt ((Get-Date).addDays(-5)) } | Sort-Object creationtime -Desc | ConvertTo-html -Body '<h2> Temporary Internet Files - Last 5 days - Sorted by Creation Time </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Stored Cookie Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$a = $env:APPDATA ; Get-ChildItem -r -ea 0 $a\Microsoft\Windows\cookies | Select-Object Name | foreach-object { $N = $_.Name ; get-content -ea 0 $a\Microsoft\Windows\cookies\$N | Select-String '/' } | ConvertTo-html -Body '<h2> Cookies </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Typed URL Data
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\SOFTWARE\Microsoft\Internet Explorer\TypedUrls' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Typed URLs </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Internet Setting Registry Keys
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Internet Settings </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Trusted Internet Domain Registry Keys
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -ea 0 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains' | Select-Object PSChildName | ConvertTo-html -Body '<h2> Important Registry Keys - Internet Trusted Domains </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering AppInit_DLL Registry Keys
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' | Select-Object AppInit_DLLs | ConvertTo-html -Body '<h2> Important Registry Keys - AppInit_DLLs </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering UAC Group Policy Settings
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - UAC Group Policy Settings </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Active Setup Installs
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Active Setup\Installed Components\*' | Select-Object ComponentID, '(default)', StubPath | ConvertTo-html -Body '<h2> Important Registry Keys - Active Setup Installs </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering App Path Registry Keys
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*' | Select-Object PSChildName, '(default)' | ConvertTo-html -Body '<h2> Important Registry Keys - APP Paths Keys </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of .dll Files Loaded by Explorer.exe Shell
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\microsoft\windows nt\CurrentVersion\winlogon\*\*' | Select-Object '(default)', DllName | ConvertTo-html -Body '<h2> Important Registry keys - DLLs Loaded by Explorer.exe Shell </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Shell and UserInit Values
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\microsoft\windows nt\CurrentVersion\winlogon' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Shell and UserInit Values </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Security Center SVC Values
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\microsoft\security center\svc' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Security Center SVC Values </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Desktop Address Bar History
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Desktop Address Bar History </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering RunMRU Key Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\RunMRU' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - RunMRU Keys </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Start Menu Data
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Startmenu' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Start Menu </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Programs Executed by Session Manager
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Programs Executed By Session Manager </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Shell Folder Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Shell Folders </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering User Startup Shell Folder Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\SOFTWARE\Microsoft\Windows\CurrentVersion\explorer\Shell Folders' | Select-Object startup | ConvertTo-html -Body '<h2> Important Registry Keys - User Shell Folders (Startup) </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Approved Shell Extensions
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - Approved Shell Extentions </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering AppCert DLLs
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - AppCert DLLs </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering EXE File Shell Command Configuration
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Classes\exefile\shell\open\command' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - EXE File Shell Command Configured </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Shell Commands
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Classes\HTTP\shell\open\command' | Select-Object '(default)' | ConvertTo-html -Body '<h2> Important Registry Keys - Shell Commands </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering BCD Related Data
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\BCD00000000\*\*\*\*' | Select-Object Element | Select-String ‘exe’ | Select-Object Line | ConvertTo-html -Body '<h2> Important Registry Keys - BCD Related </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Loaded LSA Packages Data
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SYSTEM\currentcontrolset\control\lsa' | Select-Object * -ExcludeProperty PS* | ConvertTo-html -Body '<h2> Important Registry Keys - LSA Packages Loaded </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Browser Helper Objects
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | Select-Object '(default)' | ConvertTo-html -Body '<h2> Important Registry Keys - Browser Helper Objects </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Browser Helper Objects (64 Bit)
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*' | Select-Object '(default)' | ConvertTo-html -Body '<h2> Important Registry Keys - Browser Helper Objects 64 Bit </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Internet Explorer Extensions Data
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hkcu:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*' | Select-Object ButtonText, Icon | ConvertTo-html -Body '<h2> Important Registry Keys (IE Extensions from HKCU) </h2>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Microsoft\Internet Explorer\Extensions\*' | Select-Object ButtonText, Icon | ConvertTo-html -Body '<h2> Important Registry Keys (IE Extensions from HKLM) </h2>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Extensions\*' | Select-Object ButtonText, Icon | ConvertTo-html -Body '<h2> Important Registry Keys (IE Extensions from Wow6432Node) </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering List of USB Devices
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ItemProperty -ea 0 'hklm:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object FriendlyName, PSChildName, ContainerID | ConvertTo-html -Body '<h2> List of USB Devices </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Timeline of Executable Files (Past 30 Days)
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path C:\ -r -Force -ea 0 -include $ExecutableFiles | Where-Object { -not $_.PSIsContainer -and $_.lastwritetime -gt ((Get-Date).addDays(-30)) } | Select-Object fullname, lastwritetime, @{N = 'Owner'; E = { ($_ | Get-ACL).Owner } } | Sort-Object lastwritetime -desc | ConvertTo-html -Body '<h2> File Timeline Executable Files (Past 30 Days) </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Downloaded Executable Files
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path C:\ -r -Force -ea 0 -include $ExecutableFiles | ForEach-Object { $P = $_.fullname; get-item $P -Stream * } | Where-Object { $_.Stream -match "Zone.Identifier" } | Select-Object filename, stream, @{N = 'LastWriteTime'; E = { (Get-ChildItem $P).LastWriteTime } } | ConvertTo-html -Body '<h2> Downloaded Executable Files </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log Information (Failed DNS Resolution Events)
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'system'; ID = 1014 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [DNS Failed Resolution Events (ID: 1014)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Account Logon History
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4624 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Account Logon (ID: 4624)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Failed Account Logon History
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4625 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [An Account Failed To Log On (ID: 4625)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Changed System Time
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4616 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [The System Time Was Changed (ID: 4616)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Application Crashed
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'application'; ID = 1002 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Application Crashes (ID: 1002)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Process Execution
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4688 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Process Execution (ID: 4688)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - User Account Created
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4720 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [A User Account Was Created (ID: 4720)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Logons Using Explicit Credentials
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4648 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [A Logon Was Attempted Using Explicit Credentials (ID: 4648)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Privlege Use
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4672 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Privilege Use (ID: 4672)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4673 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Privilege Use (ID: 4673)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'security'; ID = 4674 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Privilege Use (ID: 4674)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - Service Control Manager Events
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'system'; ID = 7036 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [Service Control Manager Events (ID: 7036)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Event Log - WFP Events
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WinEvent -max 50 -ea 0 -FilterHashtable @{ Logname = 'system'; ID = 64001 } | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Event Log [WFP Events (ID: 64001)] </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Application Inventory Events
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "get-winevent -ea 0 -logname Microsoft-Windows-Application-Experience/Program-Inventory | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Application Inventory Events </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO --Gathering Terminal Service Events
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "get-winevent -ea 0 -logname Microsoft-Windows-TerminalServices -LocalSessionManager | Select-Object TimeCreated, ID, Message | ConvertTo-html -Body '<h2> Terminal Services Events </h2>'" >> %FOLDER%\HTMLResults\Results.html

ECHO    Record end time of collection
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Date | Select-Object DateTime | ConvertTo-html -Body '<h2> Script Concluded Date and Time </h2>'" >> %FOLDER%\HTMLResults\Results.html

REM Copying network connections
ECHO.
ECHO ===========================================
ECHO.
ECHO Copying Network Connection Information
ECHO     Running "netstat" with various switches
ECHO.
ECHO ===========================================

REM The netstat command displays networking information for TCP
REM The "-an" switch lists all connections in numerical output
REM The netstat -s command lists the statistics -- see how much data was transmitted
REM The netstat -anbo is similar to the -an command above
REM The "-b" lists the executable involved in creating the port/connection
REM The "-o" lists the owning process ID associated with each connection
%windir%\system32\netstat -an >> %FOLDER%\NETWORK\Network_netstat.txt
%windir%\system32\netstat -s >> %FOLDER%\NETWORK\Network_netstat.txt
%windir%\system32\netstat -anbo >> %FOLDER%\NETWORK\Network_netstat.txt


REM Copying Hosts and Network File
ECHO.
ECHO ===========================================
ECHO.
ECHO Copying Host and Network File Information
ECHO.
ECHO ===========================================
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content $env:windir\system32\drivers\etc\hosts" > %FOLDER%\NETWORK\etc_hosts_file.txt
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Content $env:windir\system32\drivers\etc\networks" > %FOLDER%\NETWORK\etc_networks_file.txt

REM Audit Policy
ECHO.
ECHO ===========================================
ECHO.
ECHO Copying Computer Audit Policy
ECHO.
ECHO ===========================================
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "auditpol /get /category:* | Select-String 'No Auditing' -notmatch" > %FOLDER%\%ScanStartDate%_%ComputerName%_%UserName%_AuditPolicy.txt

REM Firewall Config
ECHO.
ECHO ===========================================
ECHO.
ECHO Copying Firewall Configuration Information
ECHO.
ECHO ===========================================
netsh advfirewall firewall show rule name=all verbose >> %FOLDER%\%ScanStartDate%_%ComputerName%_%UserName%_FirewallConfig.txt


REM =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=
REM
REM The below Code is from the original Magnet Forensics .bat scripts
REM
REM =+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=


REM Get the local computer name
ECHO     Getting local computer name
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "\"ComputerName: \" + $env:ComputerName" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get System Manufacturer
ECHO     Getting System Manufacturer
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysInfo = Get-WmiObject -Class Win32_ComputerSystem -namespace root/CIMV2 | Select Manufacturer,Model; $SysManufacturer = $SysInfo.Manufacturer; \"System Manufacturer:\" + $SysManufacturer" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get System Model
ECHO     Getting System Model
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysInfo = Get-WmiObject -Class Win32_ComputerSystem -namespace root/CIMV2 | Select Manufacturer,Model; $SysModel = $SysInfo.Model; \"System Model:\" + $SysModel" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get HDD Serial number
ECHO     Getting HDD Serial Number
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$HardSerial = Get-WMIObject Win32_BIOS -Computer $env:ComputerName | select SerialNumber; $HardSerialNo = $HardSerial.SerialNumber; \"Serial Number:\" + $HardSerialNo" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get OS Information
ECHO     Getting OS information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$OS = (Get-WmiObject Win32_OperatingSystem -computername $env:ComputerName ).caption; \"Operating System:\" + $OS" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get System uptime
ECHO     Getting System uptime
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysBootTime = Get-WmiObject Win32_OperatingSystem; $BootTime = $SysBootTime.ConvertToDateTime ($SysBootTime.LastBootUpTime); \"System Uptime:\" + $BootTime" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get RAM size
ECHO     Getting RAM size
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysRam = Get-WmiObject -Class Win32_OperatingSystem -computername $env:ComputerName | Select TotalVisibleMemorySize; $Ram = [Math]::Round($SysRam.TotalVisibleMemorySize/1024KB); \"System RAM:\" + $Ram +\" GB\"" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get CPU information
ECHO     Getting CPU information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysCpu = Get-WmiObject Win32_Processor | Select Name; $Cpu = $SysCpu.Name; \"Processor:\" + $Cpu" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get OS Serial Number
ECHO     Getting OS Serial Number
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$SysSerialNo = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $env:ComputerName);$SerialNo = $SysSerialNo.SerialNumber; \"OS Serial Number:\" + $SerialNo" >> %FOLDER%\SYSTEM\System_Information.txt

REM Get Username
ECHO     Getting Username
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "\"Username: \" + $env:UserName" >> %FOLDER%\SYSTEM\System_Information.txt

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

REM Getting a list of running processes - could be used to attempt to locate hidden processes
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
%windir%\System32\Wbem\wmic process list memory /format:CSV > %FOLDER%\PROCESS\Process_List_Memory.csv

REM Getting a list of running processes - could be used to attempt to locate hidden processes
REM MAS -- CHANGED FILE TYPE FROM .txt TO .csv
%windir%\System32\Wbem\wmic process list full /format:CSV > %FOLDER%\PROCESS\Process_List_Verbose.csv

REM Using tasklist to display a list of currently running processes
REM The "/V" is for verbose and "/FO" is output as a CSV
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

@REM REM The netstat command displays networking information for TCP
@REM REM The "-an" switch lists all connections in numerical output
@REM REM The netstat -s command lists the statistics -- see how much data was transmitted
@REM REM The netstat -anbo is similar to the -an command above
@REM REM The "-b" lists the executable involved in creating the port/connection
@REM REM The "-o" lists the owning process ID associated with each connection
@REM ECHO     Running "netstat" with various switches
@REM %windir%\system32\netstat -an >> %FOLDER%\NETWORK\Network_netstat.txt
@REM %windir%\system32\netstat -s >> %FOLDER%\NETWORK\Network_netstat.txt
@REM %windir%\system32\netstat -anbo >> %FOLDER%\NETWORK\Network_netstat.txt

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

REM Get the date and time this script was completed and save info as "StopDate" and "StopTime"
For /F "tokens=*" %%a in ('date /t') do set StopDate=%%a
For /F "tokens=*" %%a in ('time /t') do set StopTime=%%a

ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt

REM Print the StopDate and StopTime variables to the log file
ECHO Stop Date: %StopDate% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO Stop Time: %StopTime% >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %FOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %FOLDER%\CONFIG\collection_log_file.txt

GOTO SKIPIMAGEDRIVE

REM Ask the user if they want to image the drive
REM The set /p command is looking for something to set at a variable
REM The /p is pause, it is waiting on the user to enter something
ECHO.
ECHO ***** BASIC INFORMATION COLLECTION COMPLETE *****
ECHO.
set /P DRIVEDUMP=Do you want to image a drive? (enter "y" or "n")

REM Review the value entered by the user.  This is trying to guess what the user will enter
ECHO.
ECHO %LINE%
ECHO.
    if /i {%DRIVEDUMP%}=={y} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={Y} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={yes} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={Yes} (goto :IMAGEDRIVE)
    if /i {%DRIVEDUMP%}=={YES} (goto :IMAGEDRIVE)
goto NOIMAGEDRIVE

:IMAGEDRIVE
    REM If any of the yes options are selected, then launch MAGNET Acquire
    BIN\MagnetAcquire\Acquire.exe

:NOIMAGEDRIVE

:SKIPIMAGEDRIVE

REM Clean up the temp directory
RMDIR /Q /S TEMP

REM Popup message upon completion
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "(New-Object -ComObject wscript.shell).popup('The Script Has Completed Running')"

