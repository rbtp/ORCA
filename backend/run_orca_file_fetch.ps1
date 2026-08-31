#Requires -RunAsAdministrator
# ORCA Single-File Fetch Agent
# Generated per-request - do not redistribute this script.
# Self-deletes on completion.

$ErrorActionPreference = "Stop"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Config (injected at build time). No cert-bypass block needed here -- this
# is only ever delivered via push-delivery, whose launcher already imports
# the real ORCA cert (Import-Certificate) before this script ever runs, so
# the HTTPS calls below already trust it for real.
$ORCA_URL  = '{{ORCA_URL}}'
$JOB_ID    = '{{JOB_ID}}'
$TOKEN     = '{{FETCH_TOKEN}}'
$FilePath  = '{{FILE_PATH}}'
$MaxBytes  = {{MAX_BYTES}}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VRExe     = Join-Path $ScriptDir "velociraptor.exe"
$LogFile   = Join-Path $ScriptDir "orca_fetch.log"
$ReportUrl = "$ORCA_URL/api/ingest/file-fetch/$JOB_ID"

function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "[$ts] $Msg"
    Write-Host $Msg
}

function Report-Result {
    param([string]$Status, [string]$Content = "", [string]$ErrorMsg = "", [long]$Size = 0)
    $headers = @{ "X-ORCA-Token" = $TOKEN; "Content-Type" = "application/json" }
    $body = @{ status = $Status; content_b64 = $Content; error = $ErrorMsg; size = $Size } | ConvertTo-Json -Compress
    try {
        Invoke-RestMethod -Uri $ReportUrl -Method POST -Headers $headers -Body $body -TimeoutSec 300 | Out-Null
        return $true
    } catch {
        Write-Log "Report POST failed: $_"
        return $false
    }
}

Write-Log "Fetch job $JOB_ID starting for: $FilePath"

try {
    if (-not (Test-Path -LiteralPath $FilePath)) {
        Write-Log "File not found: $FilePath"
        [void](Report-Result -Status "failed" -ErrorMsg "File not found on target (may have been deleted or moved since the MFT snapshot)")
    } else {
        $item = Get-Item -LiteralPath $FilePath -Force
        if ($item.PSIsContainer) {
            Write-Log "Path is a directory, not a file"
            [void](Report-Result -Status "failed" -ErrorMsg "Path is a directory, not a file")
        } elseif ($item.Length -gt $MaxBytes) {
            $capMb = [Math]::Round($MaxBytes / 1MB)
            $actualMb = [Math]::Round($item.Length / 1MB, 1)
            Write-Log "File too large: $($item.Length) bytes (cap: $MaxBytes)"
            [void](Report-Result -Status "failed" -ErrorMsg "File exceeds the ${capMb}MB fetch limit (actual: ${actualMb}MB)")
        } else {
            Write-Log "Reading $($item.Length) bytes via Velociraptor..."
            $filePathVql = $FilePath.Replace('\', '/').Replace("'", "''")
            $vql = "SELECT base64encode(string=read_file(filename='$filePathVql', length=$MaxBytes)) AS Content FROM scope()"
            $vqlFile = Join-Path $env:TEMP "orca_fetch_$JOB_ID.vql"
            # Set-Content -Encoding UTF8 writes a BOM in Windows PowerShell 5.1 --
            # confirmed live this breaks Velociraptor's VQL parser outright
            # ("invalid token '﻿'"). [System.Text.UTF8Encoding]::new($false)
            # is BOM-less UTF8, matching what every other .vql file this app
            # generates already gets via Python's default UTF-8 writes.
            [System.IO.File]::WriteAllText($vqlFile, $vql, (New-Object System.Text.UTF8Encoding $false))
            $rawOut = & $VRExe query -f $vqlFile --format jsonl 2>$null
            Remove-Item $vqlFile -Force -ErrorAction SilentlyContinue
            $resultLine = $rawOut | Where-Object { $_ -match '^\{' } | Select-Object -First 1
            if (-not $resultLine) {
                Write-Log "Velociraptor read returned no output"
                [void](Report-Result -Status "failed" -ErrorMsg "Velociraptor could not read the file (locked, in use, or access denied)")
            } else {
                $obj = $resultLine | ConvertFrom-Json
                if (-not $obj.Content) {
                    Write-Log "Velociraptor returned an empty result"
                    [void](Report-Result -Status "failed" -ErrorMsg "Velociraptor returned no content for this file")
                } else {
                    Write-Log "Read complete ($($obj.Content.Length) base64 chars) -- posting back to ORCA"
                    if (Report-Result -Status "received" -Content $obj.Content -Size $item.Length) {
                        Write-Log "Reported successfully"
                    }
                }
            }
        }
    }
} catch {
    Write-Log "Unhandled error: $_"
    [void](Report-Result -Status "failed" -ErrorMsg "$_")
}

Write-Log "Self-deleting package..."
$selfDestructCmd = "timeout /t 3 /nobreak > nul && rmdir /s /q `"$ScriptDir`""
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $selfDestructCmd" -WindowStyle Hidden

exit 0
