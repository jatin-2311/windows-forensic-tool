# tool for windows forensic

$outputDir = "C:\ForensicReport_" + (Get-Date -Format "yyyyMMdd_HHmmss")
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

function Collect-Data {
    param([ScriptBlock]$ScriptBlock)
    try { & $ScriptBlock | Out-String -Stream } catch { "Error: $_" }
}

function Get-ChromiumBrowserHistory {
    param(
        [string]$BrowserName,
        [string]$HistoryPath
    )

    $tempHistory = Join-Path -Path ([string]$env:TEMP) -ChildPath "$BrowserName-history-temp.db"
    try {
        Copy-Item -Path $HistoryPath -Destination $tempHistory -Force -ErrorAction Stop
    } catch {
        return "$BrowserName history not found or inaccessible."
    }

    if (-not (Test-Path $tempHistory)) { return "$BrowserName history not found or inaccessible." }

    $query = @"
SELECT url, title, visit_count, datetime((last_visit_time/1000000)-11644473600, 'unixepoch', 'localtime') as LastVisitTime FROM urls ORDER BY last_visit_time DESC LIMIT 20;
"@

    $sqliteExe = "sqlite3.exe"
    if (-not (Get-Command $sqliteExe -ErrorAction SilentlyContinue)) {
        Remove-Item $tempHistory -Force -ErrorAction SilentlyContinue
        return "sqlite3.exe not found in PATH; cannot read $BrowserName history."
    }

    $history = ""
    try {
        $history = & $sqliteExe $tempHistory $query 2>$null
    } catch {
        $history = ""
    } finally {
        Remove-Item $tempHistory -Force -ErrorAction SilentlyContinue
    }

    if ([string]::IsNullOrEmpty($history)) { return "$BrowserName history empty or could not be read." } else { return $history }
}

# Core Data Collection

$processes = Collect-Data { Get-Process | Select-Object Id, ProcessName, CPU, StartTime | Format-Table -AutoSize }
$services = Collect-Data { Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize }
$networkConns = Collect-Data { Get-NetTCPConnection -ErrorAction SilentlyContinue | Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess | Format-Table -AutoSize }
$sessions = Collect-Data { query user 2>&1 }
$scheduledTasksBasic = Collect-Data { Get-ScheduledTask -ErrorAction SilentlyContinue | Select-Object TaskName, State, LastRunTime, NextRunTime | Format-Table -AutoSize }
$installedSoftware = Collect-Data { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table -AutoSize }
$firewallRules = Collect-Data { Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, Enabled, Direction, Action | Format-Table -AutoSize }
$envVariables = Collect-Data { Get-ChildItem Env: | Format-Table Key, Value -AutoSize }
$lastBootTime = try { (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime.ToLocalTime() } catch { "Unavailable" }
$arpCache = Collect-Data { arp -a 2>&1 }
$dnsCache = Collect-Data { ipconfig /displaydns 2>&1 }
$openFiles = Collect-Data { try { Get-SmbOpenFile -ErrorAction SilentlyContinue | Select-Object ClientComputerName, ClientUserName, Path | Format-Table -AutoSize } catch { "Unavailable" } }
$logonEvents = Collect-Data { try { Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; MaxEvents=30} -ErrorAction SilentlyContinue | Format-Table TimeCreated, Message -AutoSize } catch { "Unavailable" } }
$usbHistory = Collect-Data { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*" -ErrorAction SilentlyContinue | Select-Object PSChildName, FriendlyName, VendorId, ProductId | Format-Table -AutoSize }
$eventLogSystem = Collect-Data { Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize }
$eventLogSecurity = Collect-Data { Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -AutoSize }
$networkAdapters = Collect-Data { Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, Status, MacAddress, LinkSpeed | Format-Table -AutoSize }

# Browser History

$chromeHistoryPath = Join-Path -Path ([string]$env:LOCALAPPDATA) -ChildPath "Google\Chrome\User Data\Default\History"
$chromeHistory = if (Test-Path $chromeHistoryPath) { Get-ChromiumBrowserHistory -BrowserName "Chrome" -HistoryPath $chromeHistoryPath } else { "Chrome history not found" }
$edgeHistoryPath = Join-Path -Path ([string]$env:LOCALAPPDATA) -ChildPath "Microsoft\Edge\User Data\Default\History"
$edgeHistory = if (Test-Path $edgeHistoryPath) { Get-ChromiumBrowserHistory -BrowserName "Edge" -HistoryPath $edgeHistoryPath } else { "Edge history not found" }

# Recent Files Last 24 Hours

$dirsToScan = @((Join-Path -Path ([string]$env:SystemDrive) -ChildPath "Users"), (Join-Path -Path ([string]$env:SystemDrive) -ChildPath "ProgramData"), (Join-Path -Path ([string]$env:SystemDrive) -ChildPath "Windows\Temp"))
$recentFilesList = foreach ($dir in $dirsToScan) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -Recurse -ErrorAction SilentlyContinue |
        Where-Object { ($_.LastWriteTime -ge (Get-Date).AddDays(-1)) -or ($_.CreationTime -ge (Get-Date).AddDays(-1)) } |
        Select-Object FullName, CreationTime, LastWriteTime, Attributes
    }
}
$recentFiles = if ($recentFilesList) {
    $recentFilesList | Sort-Object LastWriteTime -Descending | Select-Object -First 50 | Format-Table -AutoSize | Out-String
} else {
    "No recent files found or inaccessible."
}

# Registry Autoruns

$autorunPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

$autorunEntries = @()
foreach ($path in $autorunPaths) {
    try {
        $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        if ($null -ne $items) {
            ,$items | ForEach-Object {
                [PSCustomObject]@{
                    PSPath     = $_.PSPath
                    Properties = $_.PSObject.Properties
                }
            } | ForEach-Object { $autorunEntries += $_ }
        }
    } catch { }
}

if ($autorunEntries.Count -gt 0) {
    $autorunEntriesTransformed = $autorunEntries | ForEach-Object {
        $props = $_.Properties | Where-Object { $_.Name -notmatch "^PS" -and $_.Name -ne "Properties" }
        $valueArray = $props | ForEach-Object { "$($_.Name) = $($_.Value)" } | Where-Object { $_ -ne $null -and $_ -ne "" }
        $valueString = if ($valueArray) { [string]::Join("; ", $valueArray) } else { "" }

        [PSCustomObject]@{
            PSPath     = $_.PSPath
            ValueNames = if ($valueString) { $valueString } else { "<no values>" }
        }
    }
    $autorunText = $autorunEntriesTransformed | Select-Object PSPath, ValueNames | Format-Table -AutoSize | Out-String
} else {
    $autorunText = "No autorun entries found."
}

# Scheduled Task XML Export

$scheduledTaskFolder = Join-Path -Path ([string]$outputDir) -ChildPath "ScheduledTasks_XML"
New-Item -Path $scheduledTaskFolder -ItemType Directory -Force | Out-Null
foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
    try {
        $xml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
        if ($xml) {
            $fileName = ($task.TaskPath + $task.TaskName).Replace("\","_").TrimStart("_") + ".xml"
            $xml | Out-File -FilePath (Join-Path -Path $scheduledTaskFolder -ChildPath $fileName) -Encoding UTF8
        }
    } catch { }
}

# Prefetch Files Listing

$prefetchDir = Join-Path -Path ([string]$env:SystemRoot) -ChildPath "Prefetch"
$prefetchFiles = if (Test-Path $prefetchDir) {
    Get-ChildItem -Path $prefetchDir -Filter *.pf -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object Name, CreationTime, LastWriteTime
} else { @() }

$prefetchText = if ($prefetchFiles -and $prefetchFiles.Count -gt 0) {
    $prefetchFiles | Format-Table -AutoSize | Out-String
} else {
    "Prefetch directory not found or no files."
}

# LNK Shortcut Files (Recent User Folders)

$lnkFiles = @()
foreach ($dir in $recentDirs) {
    if (Test-Path $dir) {
        $lnkFiles += Get-ChildItem -Path $dir -Filter *.lnk -ErrorAction SilentlyContinue
    }
}

$lnkText = if ($lnkFiles -and $lnkFiles.Count -gt 0) {
    $lnkFiles | Select-Object FullName, LastAccessTime, CreationTime | Format-Table -AutoSize | Out-String
} else {
    "No LNK shortcut files found in user's Recent or Desktop folders."
}

# Registry Hive Backup

$registryBackupFolder = Join-Path -Path ([string]$outputDir) -ChildPath "RegistryHives"
New-Item -Path $registryBackupFolder -ItemType Directory -Force | Out-Null

$hivePaths = @{
    "SYSTEM"   = Join-Path -Path ([string]$env:SystemRoot) -ChildPath "System32\config\SYSTEM"
    "SOFTWARE" = Join-Path -Path ([string]$env:SystemRoot) -ChildPath "System32\config\SOFTWARE"
    "SECURITY" = Join-Path -Path ([string]$env:SystemRoot) -ChildPath "System32\config\SECURITY"
    "SAM"      = Join-Path -Path ([string]$env:SystemRoot) -ChildPath "System32\config\SAM"
    "DEFAULT"  = Join-Path -Path ([string]$env:SystemRoot) -ChildPath "System32\config\DEFAULT"
    "NTUSER"   = Join-Path -Path ([string]$env:USERPROFILE) -ChildPath "NTUSER.DAT"
}

foreach ($name in $hivePaths.Keys) {
    $source = $hivePaths[$name]
    $dest = Join-Path -Path $registryBackupFolder -ChildPath "$name.hive"
    try { Copy-Item -Path $source -Destination $dest -Force -ErrorAction SilentlyContinue } catch {}
}

# PowerShell History Extraction

$pwshHistoryPath = Join-Path -Path ([string]$env:USERPROFILE) -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$pwshHistory = if (Test-Path $pwshHistoryPath) {
    Get-Content $pwshHistoryPath -ErrorAction SilentlyContinue | Select-Object -Last 50 | Out-String
} else { "PowerShell history file not found." }

# Compose HTML Report

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8' />
<title>Windows Forensic Report - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</title>
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: rgba(255, 253, 253, 1); color: #5a0202ff; }
h1, h2 { color: #2c3e50; }
pre { background: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
section { margin-bottom: 30px; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
</style>
</head>
<body>
<h1>Windows Forensic Report</h1>
<p>Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

<section><h2>Running Processes</h2><pre>$processes</pre></section>
<section><h2>Services</h2><pre>$services</pre></section>
<section><h2>Network Connections</h2><pre>$networkConns</pre></section>
<section><h2>Logged On Users / Sessions</h2><pre>$sessions</pre></section>
<section><h2>Scheduled Tasks (Summary)</h2><pre>$scheduledTasksBasic</pre><p>Full Scheduled Task XML files saved in folder: ScheduledTasks_XML</p></section>
<section><h2>Installed Software</h2><pre>$installedSoftware</pre></section>
<section><h2>Windows Firewall Rules</h2><pre>$firewallRules</pre></section>
<section><h2>Environment Variables</h2><pre>$envVariables</pre></section>
<section><h2>Last Boot Time</h2><p>$lastBootTime</p></section>
<section><h2>ARP Cache</h2><pre>$arpCache</pre></section>
<section><h2>DNS Client Cache</h2><pre>$dnsCache</pre></section>
<section><h2>Open SMB Files and Shares</h2><pre>$openFiles</pre></section>
<section><h2>Recent Logon Events (Last 30)</h2><pre>$logonEvents</pre></section>
<section><h2>USB Devices History</h2><pre>$usbHistory</pre></section>
<section><h2>System Event Log (Last 50)</h2><pre>$eventLogSystem</pre></section>
<section><h2>Security Event Log (Last 50)</h2><pre>$eventLogSecurity</pre></section>
<section><h2>Network Adapters</h2><pre>$networkAdapters</pre></section>

<section><h2>Browser History</h2><h3>Chrome</h3><pre>$chromeHistory</pre><h3>Edge</h3><pre>$edgeHistory</pre></section>
<section><h2>Recently Added or Modified Files (Last 24 Hours)</h2><pre>$recentFiles</pre></section>
<section><h2>Registry Autoruns and Startup Items</h2><pre>$autorunText</pre></section>
<section><h2>Prefetch Files</h2><pre>$prefetchText</pre></section>
<section><h2>LNK Shortcut Files (Recent User folders)</h2><pre>$lnkText</pre></section>
<section><h2>PowerShell History (Last 50 commands)</h2><pre>$pwshHistory</pre></section>
<section><h2>Registry Hive Backup</h2><p>Registry hive files copied to folder: RegistryHives</p></section>

</body>
</html>
"@

# Save HTML report
$reportPath = Join-Path -Path ([string]$outputDir) -ChildPath "ForensicReport.html"
$html | Out-File -FilePath $reportPath -Encoding UTF8

Write-Output "Extended forensic report generated at: $reportPath"
Write-Output "Scheduled Tasks XML saved in: $scheduledTaskFolder"
Write-Output "Registry hives saved in: $registryBackupFolder"
