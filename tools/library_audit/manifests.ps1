# Field names per (provider, event ID) from the providers' own manifests, plus each event's log (channel).
param([string]$Out)
$providers = 'Microsoft-Windows-Security-Auditing','Microsoft-Windows-Sysmon','Microsoft-Windows-PowerShell','PowerShell',
  'Microsoft-Windows-TaskScheduler','Service Control Manager','Microsoft-Windows-WMI-Activity','Microsoft-Windows-Windows Defender',
  'Microsoft-Windows-TerminalServices-LocalSessionManager','Microsoft-Windows-TerminalServices-RemoteConnectionManager',
  'Microsoft-Windows-Bits-Client','Microsoft-Windows-Eventlog','Microsoft-Windows-Kernel-General','Microsoft-Windows-DNS-Client',
  'Microsoft-Windows-SMBServer','Microsoft-Windows-SMBClient','Microsoft-Windows-Windows Firewall With Advanced Security','Microsoft-Windows-CodeIntegrity',
  'Microsoft-Windows-AppLocker','Microsoft-Windows-RemoteDesktopServices-RdpCoreTS','Microsoft-Windows-WinRM',
  'Microsoft-Windows-DriverFrameworks-UserMode','Microsoft-Windows-Kernel-PnP','Microsoft-Windows-Security-Mitigations',
  'Microsoft-Windows-Winlogon','Microsoft-Windows-User Profiles Service','Microsoft-Windows-GroupPolicy','Microsoft-Windows-Shell-Core',
  'Microsoft-Windows-Kernel-Process','Microsoft-Windows-NTLM','Microsoft-Windows-LSA','Microsoft-Windows-DHCP-Client','Microsoft-Windows-OpenSSH'
$res = @{}
foreach ($p in $providers) {
  try { $pm = Get-WinEvent -ListProvider $p -ErrorAction Stop } catch { Write-Host "missing: $p"; continue }
  $ev = @{}
  foreach ($e in $pm.Events) {
    $names = @()
    if ($e.Template) {
      try { $x = [xml]$e.Template; $names = @($x.template.data | ForEach-Object { $_.name }) } catch {}
    }
    $k = [string]$e.Id
    if (-not $ev.ContainsKey($k)) { $ev[$k] = @{ fields = @(); logs = @() } }
    $ev[$k].fields = @($ev[$k].fields + $names | Where-Object { $_ } | Sort-Object -Unique)
    if ($e.LogLink) { $ev[$k].logs = @($ev[$k].logs + $e.LogLink.LogName | Sort-Object -Unique) }
  }
  $res[$p] = $ev
  Write-Host ("{0,-62} {1,5} events" -f $p, $ev.Count)
}
$res | ConvertTo-Json -Depth 6 | Out-File -Encoding utf8 $Out
