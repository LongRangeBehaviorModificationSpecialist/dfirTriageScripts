@ECHO OFF

REM Will create a TEMP folder if it does not already exist
IF NOT EXIST TEMP MKDIR TEMP
REM Will remove all the files in the TEMP folder so new files can be saved
DEL /F /Q TEMP\*.*

SET LINE=============================================

REM Set an variable for the TEMP directory
SET TEMPDIR=.\TEMP

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$date = Get-Date -Format yyyyMMdd_HHmmss ; $CN = (Get-Item env:\Computername).Value; $IP = Test-Connection $CN -timetolive 2 -count 1; $ipv4=$ip.ipv4address | Select-Object -ExpandProperty IPAddressToString; $logfile = $date + \"_\"+ $ipv4 + \"_\"+ $CN; $logfile | Out-File -FilePath %TEMPDIR%\name.txt -Encoding ASCII"
FOR /F %%A in (%TEMPDIR%\name.txt) DO SET OUTFOLDER=%%A

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Item env:\Computername > %TEMPDIR%\CN.txt"
FOR /F %%B in (%TEMPDIR%\CN.txt) DO SET ComputerName=%%B

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Item env:\UserName > %TEMPDIR%\UN.txt"
FOR /F %%C in (%TEMPDIR%\UN.txt) DO SET UserName=%%C

MKDIR .\%OUTFOLDER%

SET TIMESTAMP=%DATE:~4,2%-%DATE:~7,2%-%DATE:~10,4% %TIME:~0,2%:%TIME:~3,2%:%TIME:~6,2%

ECHO.
ECHO   OUTPUT FOLDER NAME  :  %OUTFOLDER%

MKDIR .\%OUTFOLDER%\CONFIG

FOR /F "tokens=*" %%a in ('date /t') DO SET StartDate=%%a
FOR /F "tokens=*" %%a in ('time /t') DO SET StartTime=%%a

ECHO.
ECHO   %TIMESTAMP% -- Writing configuration file

REM Get the value of the %USERPROFILE% variable - the current Windows user
ECHO %LINE% >> %OUTFOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %OUTFOLDER%\CONFIG\collection_log_file.txt
ECHO User Profile: %USERPROFILE% >> %OUTFOLDER%\CONFIG\collection_log_file.txt
ECHO. >> %OUTFOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %OUTFOLDER%\CONFIG\collection_log_file.txt

ECHO. >> %OUTFOLDER%\CONFIG\collection_log_file.txt

REM Print the StartDate and StartTime variables to the log file
ECHO Start Date: %StartDate% >> %OUTFOLDER%\CONFIG\collection_log_file.txt
ECHO Start Time: %StartTime% >> %OUTFOLDER%\CONFIG\collection_log_file.txt

REM Add formatting to the collection_log_file
ECHO. >> %OUTFOLDER%\CONFIG\collection_log_file.txt
ECHO %LINE% >> %OUTFOLDER%\CONFIG\collection_log_file.txt

ECHO   %TIMESTAMP% -- Creating remaining output directories
MKDIR %OUTFOLDER%\FIREWALL
MKDIR %OUTFOLDER%\HTMLResults
MKDIR %OUTFOLDER%\NETWORK
MKDIR %OUTFOLDER%\PREFETCH
MKDIR %OUTFOLDER%\PROCESS
MKDIR %OUTFOLDER%\PROCESSCAPTURE
MKDIR %OUTFOLDER%\SERVICES
MKDIR %OUTFOLDER%\SYSTEM
MKDIR %OUTFOLDER%\WIRELESS

ECHO   %TIMESTAMP% -- Setting up .html file
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "$HEADER = '<title>%ComputerName%.%UserName%</title> <style> * { font-family:Arial, Helvetica, sans-serif; } h1 { color:#e68a00; font-size:28px; } h2 { color:#000099; font-size:1.35em; } table { font-size:1.05em; border:0px; } td { padding:4px; margin:0px; border:0; font-size:1.05em; } th { background:#395870; background:linear-gradient(#49708f, #293f50); color:#fff; font-size:1.05em; text-transform:uppercase; padding:10px 15px; vertical-align:middle; } tbody tr:nth-child(even) { background:#f0f0f2; } .RunningStatus { color:#008000; } .StopStatus { color:#ff0000; } #CreationDate { color:#ff3300; font-size:12px; } .dropbtn { color:#fff; background-color:#007bff; border-color:#007bff; padding:16px; font-size:16px; border:none; width:auto; } .dropdown { position:relative; display:inline-block; width:auto; } .dropdown-content { display:none; width:auto; height:30rem; overflow-y:scroll; position:absolute; background-color:#f1f1f1; box-shadow:0px 8px 16px 0px rgba(0,0,0,0.2); z-index:1; white-space:nowrap; } .dropdown-content a { color:#212529; padding:12px 16px; text-decoration:none; display:block; } .dropdown-content a:hover { color:#fff; background-color:#3492d1; } .dropdown-content a:active { color:#fff; background-color:#007bff; } .dropdown:hover .dropdown-content { display:block; width:auto; } .dropdown:hover .dropbtn { background-color:#03366d; } .dropdown-item { color:#212529; white-space:nowrap; background-color:transparent; border:0px; } .top { display:inline; font-size:12px; color:dodgerblue; } </style>'; ConvertTo-Html -Head $HEADER -Body '<h1> Live Forensics Script Report </h1> <h4> Computer Name : %ComputerName% </h4> <h4> User ID : %UserName% </h4>'" > %OUTFOLDER%\HTMLResults\Results.html

@REM REM Make System Report
@REM ECHO.
@REM ECHO   %TIMESTAMP% -- Gathering Basic System Information
@REM ECHO   %TIMESTAMP% -- Running msinfo32 report
@REM msinfo32 /report %OUTFOLDER%\SYSTEM\System-Information-Full-Report.txt

REM Main Routine
REM Record start time of collection
ECHO   %TIMESTAMP% -- Writing Script Start Date and Time
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-Date | Select-Object DateTime | ConvertTo-Html -Body '<h2> Script Began Date and Time </h2>'" >> %OUTFOLDER%\HTMLResults\Results.html

ECHO   %TIMESTAMP% -- Running systeminfo report
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "systeminfo /FO CSV | ConvertFrom-Csv | Select-Object * -ExcludeProperty 'Hotfix(s)', 'Network Card(s)' | ConvertTo-Html -As List -Fragment -PreContent ""<h2 id='SystemInformation'> System Information <a href='#top' class='top'>(Return to Top)</a> </h2>""" >> %OUTFOLDER%\HTMLResults\Results.html

ECHO   %TIMESTAMP% -- Getting Environment Variables
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -Path env: | ConvertTo-Html -As List -Fragment -PreContent ""<h2 id='EnvVars'> User Environment Variables <a href='#top' class='top'>(Return to Top)</a> </h2>""" >> %OUTFOLDER%\HTMLResults\Results.html

ECHO   %TIMESTAMP% -- Getting User Accounts and Current Login Information
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-WmiObject -ea 0 Win32_UserProfile | Select-Object LocalPath, SID, @{ NAME = 'last used'; EXPRESSION = { $_.ConvertToDateTime( $_.lastusetime ) } } | ConvertTo-Html -Fragment -PreContent ""<h2 id='UserAccounts'> User Accounts and Current Login Information <a href='#top' class='top'>(Return to Top)</a> </h2>""" >> %OUTFOLDER%\HTMLResults\Results.html

ECHO.

@REM ECHO   %TIMESTAMP% -- Deleted temporary directory
@REM REM Will detele the TEMP directory created at the beginning of the script
@REM PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item %TEMPDIR% -Force -Recurse"


