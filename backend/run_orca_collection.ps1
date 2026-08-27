#Requires -RunAsAdministrator
# ORCA Remote Collection Agent
# Generated per-asset - do not redistribute this script.
# Self-deletes on completion.
param(
    # Set only when this script has recursively re-invoked itself as a
    # parallel worker (see the MaxWorkers branch below) -- a bare top-level
    # run never passes this, so default behavior is untouched.
    [string]$WorkerBatchFile = ""
)

$ErrorActionPreference = "Continue"

{{CERT_BYPASS_BLOCK}}
[System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12

# Config (injected at package build time)
$ORCA_URL    = "{{ORCA_URL}}"
$ASSET_ID    = "{{ASSET_ID}}"
$TOKEN       = "{{PACKAGE_TOKEN}}"
$CASE_NAME   = "{{CASE_NAME}}"
$MaxWorkers  = {{MAX_WORKERS}}
$HOSTNAME_   = $env:COMPUTERNAME

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$VRExe      = Join-Path $ScriptDir "velociraptor.exe"
$TechDir    = Join-Path $ScriptDir "techniques"
$LogFile    = Join-Path $ScriptDir "orca_run.log"
$IngestBase = "$ORCA_URL/api/ingest/remote/$ASSET_ID"

# A spawned worker skips writing $LogFile directly to avoid several
# processes hitting the same file concurrently -- Start-Process already
# redirects this worker's Write-Host output to its own file, which the
# orchestrator appends into the shared log (safely, after the worker has
# already exited) once it collects results below.
$script:IsWorker = [bool]$WorkerBatchFile

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    if (-not $script:IsWorker) { Add-Content -Path $LogFile -Value $line }
    Write-Host $line
}

function Invoke-IngestPost {
    param([string]$TCode, [string]$JsonlContent, [string]$Mode)
    $uri = "$IngestBase/$TCode"
    $headers = @{
        "X-ORCA-Token" = $TOKEN
        "Content-Type" = "application/x-ndjson"
        "X-Asset-Id"   = $ASSET_ID
        "X-Case-Name"  = $CASE_NAME
        "X-Hostname"   = $HOSTNAME_
        "X-Mode"       = $Mode
    }
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $JsonlContent -TimeoutSec 120
        return $resp
    } catch {
        Write-Log "POST failed for $TCode : $_" "ERROR"
        return $null
    }
}

function Invoke-HeartbeatPost {
    param([string]$TCode, [string]$Status, [string]$Detail = "")
    $uri = "$ORCA_URL/api/ingest/remote/$ASSET_ID/status"
    $headers = @{
        "X-ORCA-Token" = $TOKEN
        "Content-Type" = "application/json"
    }
    $body = @{ t_code = $TCode; status = $Status; detail = $Detail; hostname = $HOSTNAME_ } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $body -TimeoutSec 5 | Out-Null
    } catch {
        Write-Log "Heartbeat failed for $TCode : $_" "WARN"
    }
}

function Run-Technique {
    param([string]$TCode, [string]$VqlFile, [string]$YamlFile)

    $tmpOutput = Join-Path $env:TEMP "orca_${TCode}_$(Get-Random).jsonl"
    $ran  = $false

    # Path 1: surgical YAML
    if ($YamlFile -and (Test-Path $YamlFile)) {
        Write-Log "[$TCode] Running surgical YAML"
        Invoke-HeartbeatPost $TCode "RUNNING" "surgical_yaml"
        try {
            & $VRExe artifacts collect --definitions $YamlFile 2>$null |
                Where-Object { $_ -match '^\{' } |
                Set-Content -Path $tmpOutput -Encoding UTF8
            $lineCount = 0
            if (Test-Path $tmpOutput) {
                $lineCount = (Get-Content $tmpOutput | Measure-Object -Line).Lines
            }
            if ($lineCount -gt 0) {
                Write-Log "[$TCode] YAML returned $lineCount rows"
                $content = Get-Content $tmpOutput -Raw
                Invoke-IngestPost $TCode $content "surgical_yaml"
                Invoke-HeartbeatPost $TCode "COMPLETE" "$lineCount rows"
                $ran = $true
            } else {
                Write-Log "[$TCode] YAML returned 0 rows, trying VQL" "WARN"
            }
        } catch {
            Write-Log "[$TCode] YAML execution error: $_" "ERROR"
        }
    }

    # Path 2: custom VQL
    if ((-not $ran) -and $VqlFile -and (Test-Path $VqlFile)) {
        Write-Log "[$TCode] Running custom VQL"
        Invoke-HeartbeatPost $TCode "RUNNING" "custom_vql"
        try {
            $vqlContent = Get-Content $VqlFile -Raw
            & $VRExe query --format jsonl $vqlContent 2>$null |
                Where-Object { $_ -match '^\{' } |
                Set-Content -Path $tmpOutput -Encoding UTF8
            $lineCount = 0
            if (Test-Path $tmpOutput) {
                $lineCount = (Get-Content $tmpOutput | Measure-Object -Line).Lines
            }
            if ($lineCount -gt 0) {
                Write-Log "[$TCode] VQL returned $lineCount rows"
                $content = Get-Content $tmpOutput -Raw
                Invoke-IngestPost $TCode $content "custom_vql"
                Invoke-HeartbeatPost $TCode "COMPLETE" "$lineCount rows"
                $ran = $true
            } else {
                Write-Log "[$TCode] VQL returned 0 rows, trying fallback" "WARN"
            }
        } catch {
            Write-Log "[$TCode] VQL execution error: $_" "ERROR"
        }
    }

    # Path 3: EventID-only fallback — skip for Sysmon-targeting VQL
    # Sysmon EventID absence means the activity didn't occur — broadening the query produces null-field noise
    $vqlForCheck = if ($VqlFile -and (Test-Path $VqlFile)) { Get-Content $VqlFile -Raw } else { '' }
    $isSysmon = $vqlForCheck -match 'Sysmon%4Operational'
    if ((-not $ran) -and $VqlFile -and (Test-Path $VqlFile) -and (-not $isSysmon)) {
        Write-Log "[$TCode] Running fallback VQL"
        Invoke-HeartbeatPost $TCode "FALLBACK_RUNNING"
        try {
            $vql   = Get-Content $VqlFile -Raw
            $fbVql = $vql -replace '(?s)WHERE\s+.+?(?=LIMIT|ORDER BY|$)', ''
            $fbVql = "$fbVql LIMIT 1000"
            & $VRExe query --format jsonl $fbVql 2>$null |
                Where-Object { $_ -match '^\{' } |
                Set-Content -Path $tmpOutput -Encoding UTF8
            $lineCount = 0
            if (Test-Path $tmpOutput) {
                $lineCount = (Get-Content $tmpOutput | Measure-Object -Line).Lines
            }
            if ($lineCount -gt 0) {
                Write-Log "[$TCode] Fallback returned $lineCount rows"
                $content = Get-Content $tmpOutput -Raw
                Invoke-IngestPost $TCode $content "fallback"
                Invoke-HeartbeatPost $TCode "FALLBACK_COMPLETE" "$lineCount rows"
                $ran = $true
            }
        } catch {
            Write-Log "[$TCode] Fallback error: $_" "ERROR"
        }
    }

    if (-not $ran) {
        Write-Log "[$TCode] NO_ARTIFACTS - all paths returned 0" "WARN"
        Invoke-HeartbeatPost $TCode "NO_ARTIFACTS"
        Invoke-IngestPost $TCode "" "no_artifacts"
    }

    if (Test-Path $tmpOutput) {
        Remove-Item $tmpOutput -Force -ErrorAction SilentlyContinue
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────

if (-not (Test-Path $VRExe)) {
    Write-Log "velociraptor.exe not found at $VRExe - aborting" "ERROR"
    exit 1
}

$allTechFiles = Get-ChildItem -Path $TechDir -Filter "*.json" -ErrorAction SilentlyContinue
if (-not $allTechFiles) {
    Write-Log "No technique files found in $TechDir - aborting" "ERROR"
    exit 1
}

# ── Worker mode: process just this batch, report back, exit -- the
# orchestrator invocation below owns start/complete notification and
# self-delete, so a worker never reaches past here. ──────────────────────────
if ($WorkerBatchFile) {
    $batchNames = Get-Content $WorkerBatchFile -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
    $techniques = $allTechFiles | Where-Object { $batchNames -contains $_.Name }
    Write-Log "Worker started - processing $($techniques.Count) techniques"

    $workerCompleted = 0
    foreach ($techFile in $techniques) {
        try {
            $meta     = Get-Content $techFile.FullName | ConvertFrom-Json
            $vqlFile  = $null
            $yamlFile = $null
            if ($meta.vql_file)  { $vqlFile  = Join-Path $TechDir $meta.vql_file }
            if ($meta.yaml_file) { $yamlFile = Join-Path $TechDir $meta.yaml_file }
            Run-Technique -TCode $meta.t_code -VqlFile $vqlFile -YamlFile $yamlFile
            $workerCompleted++
        } catch {
            Write-Log "Unhandled error on $($techFile.Name): $_" "ERROR"
        }
    }
    Write-Log "Worker finished - $workerCompleted/$($techniques.Count) processed"
    # Parsed back out of this process's redirected stdout by the orchestrator
    # -- deliberately not relying on shared state across the process boundary.
    Write-Output "ORCA_WORKER_DONE|$workerCompleted|$($techniques.Count)"
    exit 0
}

# ── Orchestrator (normal top-level run) ───────────────────────────────────────

Write-Log "ORCA collection agent starting - case: $CASE_NAME, asset: $ASSET_ID"
Write-Log "Host: $HOSTNAME_"

$techniques = $allTechFiles
Write-Log "Found $($techniques.Count) techniques to run"

try {
    $headers = @{ "X-ORCA-Token" = $TOKEN; "Content-Type" = "application/json" }
    $body    = @{ hostname = $HOSTNAME_; technique_count = $techniques.Count; case_name = $CASE_NAME } | ConvertTo-Json
    Invoke-RestMethod -Uri "$ORCA_URL/api/ingest/remote/$ASSET_ID/start" `
        -Method POST -Headers $headers -Body $body -TimeoutSec 30 | Out-Null
} catch {
    Write-Log "Could not notify ORCA of start (non-fatal): $_" "WARN"
}

$completed = 0

if ($MaxWorkers -gt 1 -and $techniques.Count -gt 1) {
    # Parallel path: split into up to $MaxWorkers batches, spawn one child
    # powershell.exe per batch re-invoking this same script with
    # -WorkerBatchFile (same Start-Process + redirected-output + Handle-touch
    # pattern already used for the WinRM-push launcher elsewhere in this
    # deploy chain). Each worker's own completed count is parsed back out of
    # its captured stdout rather than shared across the process boundary.
    $workerCount = [Math]::Min($MaxWorkers, $techniques.Count)
    Write-Log "Running in parallel across $workerCount workers"
    $batches = for ($i = 0; $i -lt $workerCount; $i++) { , [System.Collections.ArrayList]::new() }
    for ($i = 0; $i -lt $techniques.Count; $i++) { [void]$batches[$i % $workerCount].Add($techniques[$i]) }

    $workers = @()
    for ($i = 0; $i -lt $batches.Count; $i++) {
        if ($batches[$i].Count -eq 0) { continue }
        $batchFile = Join-Path $env:TEMP "orca_batch_${i}_$(Get-Random).txt"
        $batches[$i] | ForEach-Object { $_.Name } | Set-Content -Path $batchFile -Encoding UTF8
        $outFile = Join-Path $env:TEMP "orca_worker_out_${i}_$(Get-Random).log"
        $errFile = Join-Path $env:TEMP "orca_worker_err_${i}_$(Get-Random).log"
        $proc = Start-Process -FilePath "powershell.exe" `
            -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Path, '-WorkerBatchFile', $batchFile) `
            -WindowStyle Hidden -PassThru -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        $proc.Handle | Out-Null
        $workers += [PSCustomObject]@{ Proc = $proc; BatchFile = $batchFile; OutFile = $outFile; ErrFile = $errFile }
    }

    $workers.Proc | Wait-Process -ErrorAction SilentlyContinue

    foreach ($w in $workers) {
        $w.Proc.Refresh()
        $out = if (Test-Path $w.OutFile) { Get-Content $w.OutFile -Raw -ErrorAction SilentlyContinue } else { '' }
        $err = if (Test-Path $w.ErrFile) { Get-Content $w.ErrFile -Raw -ErrorAction SilentlyContinue } else { '' }
        if ($out) { Add-Content -Path $LogFile -Value $out }
        if ($err) { Write-Log "Worker stderr: $err" "WARN" }
        if ($out -match 'ORCA_WORKER_DONE\|(\d+)\|(\d+)') {
            $completed += [int]$Matches[1]
        } else {
            Write-Log "Worker produced no completion marker (exit code $($w.Proc.ExitCode))" "WARN"
        }
        Remove-Item $w.BatchFile, $w.OutFile, $w.ErrFile -Force -ErrorAction SilentlyContinue
    }
} else {
    foreach ($techFile in $techniques) {
        try {
            $meta     = Get-Content $techFile.FullName | ConvertFrom-Json
            $tCode    = $meta.t_code
            $vqlFile  = $null
            $yamlFile = $null
            if ($meta.vql_file)  { $vqlFile  = Join-Path $TechDir $meta.vql_file }
            if ($meta.yaml_file) { $yamlFile = Join-Path $TechDir $meta.yaml_file }
            Run-Technique -TCode $tCode -VqlFile $vqlFile -YamlFile $yamlFile
            $completed++
        } catch {
            Write-Log "Unhandled error on $($techFile.Name): $_" "ERROR"
        }
    }
}

Write-Log "Collection complete. $completed/$($techniques.Count) techniques processed."

# Revoke token before self-delete
Write-Log "Revoking collection token..."
try {
    $headers = @{ "X-ORCA-Token" = $TOKEN; "Content-Type" = "application/json" }
    Invoke-RestMethod -Uri "$ORCA_URL/api/ingest/remote/$ASSET_ID/complete" `
        -Method POST -Headers $headers -TimeoutSec 10 | Out-Null
    Write-Log "Token revoked."
} catch {
    Write-Log "Token revoke failed (non-fatal - expires automatically in 24hrs): $_" "WARN"
}

Write-Log "Self-deleting package..."
$selfDestructCmd = "timeout /t 3 /nobreak > nul && rmdir /s /q `"$ScriptDir`""
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $selfDestructCmd" -WindowStyle Hidden

exit 0