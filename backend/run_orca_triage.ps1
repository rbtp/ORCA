#Requires -RunAsAdministrator
# ORCA Triage Collection Agent
# Generated per-asset - do not redistribute this script.
# Self-deletes on completion.

$ErrorActionPreference = "Continue"

{{CERT_BYPASS_BLOCK}}
[System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12

# Config (injected at package build time)
$ORCA_URL  = "{{ORCA_URL}}"
$ASSET_ID  = "{{ASSET_ID}}"
$TOKEN     = "{{PACKAGE_TOKEN}}"
$CASE_NAME = "{{CASE_NAME}}"
$HOSTNAME_ = $env:COMPUTERNAME

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$VRExe      = Join-Path $ScriptDir "velociraptor.exe"
$ArtDir     = Join-Path $ScriptDir "artifacts"
$LogFile    = Join-Path $ScriptDir "orca_triage.log"
$IngestBase = "$ORCA_URL/api/ingest/remote/$ASSET_ID"

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    Add-Content -Path $LogFile -Value $line
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
        Invoke-RestMethod -Uri $uri -Method POST -Headers $headers -Body $JsonlContent -TimeoutSec 120
    } catch {
        Write-Log "POST failed for $TCode : $_" "ERROR"
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

function Run-Artifact {
    param([string]$TCode, [string]$VqlFile)

    if (-not (Test-Path $VqlFile)) {
        Write-Log "[$TCode] VQL file not found: $VqlFile" "ERROR"
        Invoke-HeartbeatPost $TCode "ERROR" "vql_file_missing"
        return
    }

    $tmpOutput = Join-Path $env:TEMP "orca_triage_${TCode}_$(Get-Random).jsonl"
    $vqlContent = Get-Content $VqlFile -Raw

    Write-Log "[$TCode] Running triage artifact"
    Invoke-HeartbeatPost $TCode "RUNNING"

    try {
        & $VRExe query --format jsonl $vqlContent 2>$null |
            Where-Object { $_ -match '^\{' } |
            Set-Content -Path $tmpOutput -Encoding UTF8

        $lineCount = 0
        if (Test-Path $tmpOutput) {
            $lineCount = (Get-Content $tmpOutput | Measure-Object -Line).Lines
        }

        if ($lineCount -gt 0) {
            Write-Log "[$TCode] Collected $lineCount rows"
            $content = Get-Content $tmpOutput -Raw
            Invoke-IngestPost $TCode $content "triage"
            Invoke-HeartbeatPost $TCode "COMPLETE" "$lineCount rows"
        } else {
            Write-Log "[$TCode] No artifacts found" "WARN"
            Invoke-HeartbeatPost $TCode "NO_ARTIFACTS"
            Invoke-IngestPost $TCode "" "no_artifacts"
        }
    } catch {
        Write-Log "[$TCode] Execution error: $_" "ERROR"
        Invoke-HeartbeatPost $TCode "ERROR" "$_"
    } finally {
        if (Test-Path $tmpOutput) {
            Remove-Item $tmpOutput -Force -ErrorAction SilentlyContinue
        }
    }
}

# ── Main ──────────────────────────────────────────────────────────────────────

Write-Log "ORCA triage agent starting - case: $CASE_NAME, asset: $ASSET_ID"
Write-Log "Host: $HOSTNAME_"

if (-not (Test-Path $VRExe)) {
    Write-Log "velociraptor.exe not found at $VRExe - aborting" "ERROR"
    exit 1
}

$artifacts = Get-ChildItem -Path $ArtDir -Filter "*.vql" -ErrorAction SilentlyContinue
if (-not $artifacts) {
    Write-Log "No artifact VQL files found in $ArtDir - aborting" "ERROR"
    exit 1
}

Write-Log "Found $($artifacts.Count) artifacts to collect"

try {
    $headers = @{ "X-ORCA-Token" = $TOKEN; "Content-Type" = "application/json" }
    $body    = @{ hostname = $HOSTNAME_; technique_count = $artifacts.Count; case_name = $CASE_NAME } | ConvertTo-Json
    Invoke-RestMethod -Uri "$ORCA_URL/api/ingest/remote/$ASSET_ID/start" `
        -Method POST -Headers $headers -Body $body -TimeoutSec 30 | Out-Null
} catch {
    Write-Log "Could not notify ORCA of start (non-fatal): $_" "WARN"
}

foreach ($artFile in $artifacts) {
    $tCode = [System.IO.Path]::GetFileNameWithoutExtension($artFile.Name)
    Run-Artifact -TCode $tCode -VqlFile $artFile.FullName
}

Write-Log "Triage complete. $($artifacts.Count) artifacts processed."

try {
    $headers = @{ "X-ORCA-Token" = $TOKEN; "Content-Type" = "application/json" }
    Invoke-RestMethod -Uri "$ORCA_URL/api/ingest/remote/$ASSET_ID/complete" `
        -Method POST -Headers $headers -TimeoutSec 10 | Out-Null
    Write-Log "Token revoked."
} catch {
    Write-Log "Token revoke failed (non-fatal): $_" "WARN"
}

Write-Log "Self-deleting package..."
$selfDestructCmd = "timeout /t 3 /nobreak > nul && rmdir /s /q `"$ScriptDir`""
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $selfDestructCmd" -WindowStyle Hidden

exit 0