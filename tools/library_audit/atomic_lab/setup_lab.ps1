# ORCA attack-simulation lab: one-time setup inside the isolated test VM (run as administrator).
$ErrorActionPreference = 'Continue'
$log = 'C:\Lab\setup.log'
New-Item -ItemType Directory -Force C:\Lab | Out-Null
function Log($m) { "$(Get-Date -Format o) $m" | Tee-Object -FilePath $log -Append }

Log 'Sysmon'
& C:\Lab\prep\Sysmon64.exe -accepteula -i C:\Lab\prep\sysmonconfig.xml 2>&1 | Out-String | Log

Log 'Audit policy (all categories) + command line in 4688'
auditpol /set /category:* /success:enable /failure:enable | Out-Null
reg add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Log 'PowerShell script block + module logging'
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' /v '*' /t REG_SZ /d '*' /f | Out-Null
Log 'Event log sizes'
foreach ($l in 'Security', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-PowerShell/Operational', 'Windows PowerShell', 'System', 'Application') {
    wevtutil sl "$l" /ms:1073741824 2>&1 | Out-Null
}
wevtutil sl 'Microsoft-Windows-TaskScheduler/Operational' /e:true 2>&1 | Out-Null

Log 'Atomic Red Team'
Expand-Archive -Force C:\Lab\prep\atomic-red-team.zip C:\Lab\art
Expand-Archive -Force C:\Lab\prep\invoke-atomicredteam.zip C:\Lab\iart
$atomics = Get-ChildItem C:\Lab\art -Directory | Select-Object -First 1 | ForEach-Object { Join-Path $_.FullName 'atomics' }
$module  = Get-ChildItem C:\Lab\iart -Recurse -Filter Invoke-AtomicRedTeam.psd1 | Select-Object -First 1
New-Item -ItemType Directory -Force C:\AtomicRedTeam | Out-Null
if (Test-Path C:\AtomicRedTeam\atomics) { Remove-Item -Recurse -Force C:\AtomicRedTeam\atomics }
Move-Item $atomics C:\AtomicRedTeam\atomics
"$($module.FullName)" | Set-Content C:\Lab\module_path.txt
Set-ExecutionPolicy -Scope LocalMachine Bypass -Force
Install-PackageProvider -Name NuGet -Force -ErrorAction SilentlyContinue | Out-Null
Log "atomics: $((Get-ChildItem C:\AtomicRedTeam\atomics -Directory).Count) technique folders; module: $($module.FullName)"
Log 'SETUP DONE'
