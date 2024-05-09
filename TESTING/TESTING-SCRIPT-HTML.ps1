$header = "
<style>
    h1
    {
        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 28px;
    }
    h2
    {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
    }
    table
    {
        font-size: 12px;
        border: 0px; 
        font-family: Arial, Helvetica, sans-serif;
    }
    td
    {
        padding: 4px;
        margin: 0px;
        border: 0;
        font-szie: 11px;
    }
    th
    {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
    }
    tbody tr:nth-child(even)
    {
        background: #f0f0f2;
    }
    .RunningStatus
    {
        color: #008000;
    }
    .StopStatus
    {
        color: #ff0000;
    }
    #CreationDate
    {
        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;
    }
</style>
"
$date = get-date -format yyyyMMdd_HHmmss
$name = $env:computername
$FQDN = $env:userdnsdomain
$IP = Test-Connection $name -timetolive 2 -count 1
$ip=$ip.ipv4address | select-Object -ExpandProperty IPAddressToString
$FOLDER = $date + "_"+ $IP + "_"+ $name + $FQDN
$cwd = Get-Location

$ResultsFolder = New-Item -Path $cwd -Name $FOLDER -ItemType "directory"

# The command below will get the name of the computer
$ComputerName = "<h1> Computer name: $env:computername </h1>"
$StartTime = Get-Date

Write-Host ""
Write-Host -fore yellow "Script begun at:  $(Get-Date -format 'MM-dd-yyyy hh:mm:ss K')"
Write-Host ""

# The command below will get the Operating System information, convert the result to HTML code as table and store it to a variable
Write-Host -fore red "`t$(Get-Date -format 'MM-dd-yyyy hh:mm:ss') -- Gathering OS Information"
$OSinfo = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -As List -Property Version,Caption,BuildNumber,Manufacturer -Fragment -PreContent "<h2> Operating System Information </h2>"

# The command below will get the Processor information, convert the result to HTML code as table and store it to a variable
Write-Host -fore red "`t$(Get-Date -format 'MM-dd-yyyy hh:mm:ss') -- Gathering Process Information"
$ProcessInfo = Get-CimInstance -ClassName Win32_Processor | ConvertTo-Html -As List -Property DeviceID,Name,Caption,MaxClockSpeed,SocketDesignation,Manufacturer -Fragment -PreContent "<h2> Processor Information </h2>"

#  command below will get the BIOS information, convert the result to HTML code as table and store it to a variable
Write-Host -fore red "`t$(Get-Date -format 'MM-dd-yyyy hh:mm:ss') -- Gathering BIOS Information"
$BiosInfo = Get-CimInstance -ClassName Win32_BIOS | ConvertTo-Html -As List -Property SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber -Fragment -PreContent "<h2> BIOS Information </h2>"

# The command below will get the details of Disk, convert the result to HTML code as table and store it to a variable
Write-Host -fore red "`t$(Get-Date -format 'MM-dd-yyyy hh:mm:ss') -- Gathering Disk Information"
$DiscInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ConvertTo-Html -As List -Property DeviceID,DriveType,ProviderName,VolumeName,Size,FreeSpace -Fragment -PreContent "<h2> Disk Information </h2>"

# The command below will get first 10 services information, convert the result to HTML code as table and store it to a variable (to set only a certain number of replies, add "| Select-Object -First 10 |" before "ConvertTo-Html")
Write-Host -fore red "`t$(Get-Date -format 'MM-dd-yyyy hh:mm:ss') -- Gathering Services Information"
$ServicesInfo = Get-CimInstance -ClassName Win32_Service | ConvertTo-Html -Property Name,DisplayName,State -Fragment -PreContent "<h2> Services Information </h2>"
$ServicesInfo = $ServicesInfo -replace '<td>Running</td>','<td class="RunningStatus">Running</td>' 
$ServicesInfo = $ServicesInfo -replace '<td>Stopped</td>','<td class="StopStatus">Stopped</td>'

# The command below will combine all the information gathered into a single HTML report
Write-Host -fore red "`t$(Get-Date -format 'MM-dd-yyyy hh:mm:ss') -- Writing the Results Report"
$Report = ConvertTo-HTML -Body "$ComputerName $OSinfo $ProcessInfo $BiosInfo $DiscInfo $ServicesInfo" -Title "Computer Information Report" Head $header -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"

# The command below will generate the report to an HTML file
$Report | Out-File $ResultsFolder\Basic-Computer-Information-Report.html

# $EndTime = Get-Date
$Duration = (Get-Date) - $StartTime
$diff = $Duration.ToString("dd' days 'hh' hours 'mm' minutes 'ss' seconds'")


Write-Host ""
Write-Host -fore yellow "Script completed at:  $(Get-Date -format 'MM-dd-yyyy hh:mm:ss K')"
Write-Host -fore yellow "[$diff]"
Write-Host ""
Write-Host -fore green "The results report is available at:  $ResultsFolder\Basic-Computer-Information-Report.html"
Write-Host ""
Write-Host ""
