# Runs every Windows Atomic Red Team test once, technique by technique, logging UTC start/end per technique
# to C:\Lab\atomic_runs.jsonl (resumable: techniques already logged are skipped).
param([switch]$GetPrereqs, [int]$TimeoutSeconds = 120)
$ErrorActionPreference = 'Continue'
Import-Module (Get-Content C:\Lab\module_path.txt) -Force
$PSDefaultParameterValues = @{ 'Invoke-AtomicTest:PathToAtomicsFolder' = 'C:\AtomicRedTeam\atomics' }
# Tests that would wreck the lab itself (shutdown, wipe, destroy/encrypt data, kill recovery, lock accounts,
# stop services incl. VMware Tools, denial of service).
$skip = 'T1529', 'T1485', 'T1486', 'T1490', 'T1531', 'T1561', 'T1561.001', 'T1561.002', 'T1489', 'T1499', 'T1499.001', 'T1499.002', 'T1499.003', 'T1499.004', 'T1495'
$out = 'C:\Lab\atomic_runs.jsonl'
$done = @{}
if (Test-Path $out) { Get-Content $out | ForEach-Object { try { $done[($_ | ConvertFrom-Json).t] = 1 } catch {} } }
$techs = Get-ChildItem C:\AtomicRedTeam\atomics -Directory | Where-Object { $_.Name -match '^T\d{4}' } | ForEach-Object { $_.Name } | Sort-Object
# Techniques that damage the evidence or the lab (clear/disable logs, unload Sysmon, rename/lock accounts)
# run last, log clearing last of all, so they can't wipe the traces of the techniques before them.
$late = { param($x) $x -match '^T1562' -or $x -match '^T1070' -or $x -match '^T1098' -or $x -match '^T1112$' -or $x -match '^T1222' }
$techs = @($techs | Where-Object { -not (& $late $_) }) +
         @($techs | Where-Object { (& $late $_) -and $_ -notmatch '^T1070(\.001)?$' }) +
         @($techs | Where-Object { $_ -match '^T1070(\.001)?$' })
foreach ($t in $techs) {
    if ($skip -contains $t -or $done.ContainsKey($t)) { continue }
    $yaml = Join-Path "C:\AtomicRedTeam\atomics\$t" "$t.yaml"
    if (-not (Test-Path $yaml)) { continue }
    if (-not (Select-String -Path $yaml -Pattern '^\s*-\s*windows\s*$' -Quiet)) { continue }
    if ($GetPrereqs) {
        $plog = "C:\Lab\prereq_$t.log"
        if (Test-Path $plog) { continue }
        # 4 at a time, 4 minutes each: some prerequisite downloads hang forever
        while (@(Get-Job -State Running).Count -ge 4) {
            foreach ($rj in @(Get-Job -State Running)) {
                if (((Get-Date) - $rj.PSBeginTime).TotalSeconds -gt 240) { Stop-Job $rj; "TIMEOUT after 240 s" | Out-File "C:\Lab\prereq_$($rj.Name).log" }
            }
            foreach ($fj in @(Get-Job | Where-Object { $_.State -ne 'Running' })) {
                $fl = "C:\Lab\prereq_$($fj.Name).log"
                if (-not (Test-Path $fl)) { Receive-Job $fj | Out-File $fl }
                Remove-Job $fj -Force
            }
            Start-Sleep 2
        }
        Start-Job -Name $t -ScriptBlock { param($m, $tt)
            Import-Module $m -Force
            Invoke-AtomicTest $tt -GetPrereqs -PathToAtomicsFolder C:\AtomicRedTeam\atomics *>&1 | Out-String
        } -ArgumentList (Get-Content C:\Lab\module_path.txt), $t | Out-Null
        continue
    }
    $start = (Get-Date).ToUniversalTime().ToString('o')
    $outp = Invoke-AtomicTest $t -TimeoutSeconds $TimeoutSeconds *>&1 | Out-String
    $end = (Get-Date).ToUniversalTime().ToString('o')
    Invoke-AtomicTest $t -Cleanup -TimeoutSeconds 60 *> $null
    $ran = ([regex]::Matches($outp, 'Executing test:')).Count
    $exit = ([regex]::Matches($outp, 'Exit code: (\d+)') | ForEach-Object { $_.Groups[1].Value }) -join ','
    [pscustomobject]@{ t = $t; start = $start; end = $end; tests = $ran; exit_codes = $exit; output = $outp.Substring(0, [Math]::Min(4000, $outp.Length)) } |
        ConvertTo-Json -Compress | Add-Content $out
}
if ($GetPrereqs) {
    $deadline = (Get-Date).AddSeconds(300)
    while (@(Get-Job -State Running).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep 3 }
    foreach ($fj in @(Get-Job)) {
        $fl = "C:\Lab\prereq_$($fj.Name).log"
        if ($fj.State -eq 'Running') { Stop-Job $fj; "TIMEOUT" | Out-File $fl }
        elseif (-not (Test-Path $fl)) { Receive-Job $fj | Out-File $fl }
        Remove-Job $fj -Force
    }
}
if (-not $GetPrereqs) { 'ATOMICS DONE' | Set-Content C:\Lab\atomics_done.txt } else { 'PREREQS DONE' | Set-Content C:\Lab\prereqs_done.txt }
