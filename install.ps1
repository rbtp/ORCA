<#
.SYNOPSIS
    ORCA installer for Windows (Docker Desktop).

.DESCRIPTION
    1. Checks Docker is installed and running
    2. Creates .env from .env.example (random JWT_SECRET / DB_PASSWORD, server address)
    3. Builds the images
    4. Downloads the Grype vulnerability DB if it isn't already present
    5. Starts ORCA and prints the first-boot admin login

    Safe to re-run: an existing .env and an existing Grype DB are kept.

.PARAMETER ServerAddress
    IP or hostname analysts and remote agents will use to reach this machine.
    Defaults to this machine's primary IPv4 address.

.PARAMETER SkipGrypeDb
    Don't download the Grype vulnerability DB (~3 GB on disk). Vulnerability
    scans won't work until it's populated.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1
.EXAMPLE
    .\install.ps1 -ServerAddress 10.0.0.5
#>
param(
    [string]$ServerAddress,
    [switch]$SkipGrypeDb
)

# 'Continue', not 'Stop': on Windows PowerShell 5.1, redirecting a native
# command's stderr (docker logs 2>&1) under 'Stop' throws on the first line.
# Failures are checked explicitly via $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

function Step($msg) { Write-Host "`n[ORCA] $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "[ORCA] ERROR: $msg" -ForegroundColor Red; exit 1 }

function New-Secret {
    # Works on Windows PowerShell 5.1 and PowerShell 7+
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $b = New-Object byte[] 32
    $rng.GetBytes($b)
    ($b | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Get-PrimaryIPv4 {
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                 Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
        $ip = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop |
              Select-Object -First 1
        return $ip.IPAddress
    } catch {
        return 'localhost'
    }
}

# ── 1. Docker ────────────────────────────────────────────────────────────────
Step 'Checking Docker...'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail 'Docker is not installed. Install Docker Desktop (https://www.docker.com/products/docker-desktop/) and re-run.'
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail 'Docker is installed but not running. Start Docker Desktop and re-run.' }
docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Fail "'docker compose' is not available. Update Docker Desktop." }

foreach ($name in 'orca-backend', 'orca-frontend', 'orca-postgres') {
    $proj = docker inspect $name --format '{{index .Config.Labels "com.docker.compose.project"}}' 2>$null
    if ($LASTEXITCODE -eq 0 -and $proj -ne 'orcaweb') {
        Fail "A container named '$name' already exists and isn't part of this ORCA install. Remove or rename it first."
    }
}

# ── 2. .env ──────────────────────────────────────────────────────────────────
if (Test-Path .env) {
    Step '.env already exists, keeping it.'
} else {
    Step 'Creating .env...'
    if (-not $ServerAddress) {
        $detected = Get-PrimaryIPv4
        $answer = Read-Host "Server IP/hostname analysts and agents will use [$detected]"
        $ServerAddress = if ($answer) { $answer.Trim() } else { $detected }
    }
    $envText = Get-Content .env.example -Raw
    $envText = $envText -replace '(?m)^JWT_SECRET=.*$', "JWT_SECRET=$(New-Secret)"
    $envText = $envText -replace '(?m)^DB_PASSWORD=.*$', "DB_PASSWORD=$(New-Secret)"
    $envText = $envText -replace '(?m)^CORS_ORIGINS=.*$', "CORS_ORIGINS=https://$ServerAddress,https://localhost"
    $envText = $envText -replace '(?m)^# ORCA_SERVER_URL=.*$', "ORCA_SERVER_URL=https://$ServerAddress"
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot '.env'), $envText, (New-Object Text.UTF8Encoding $false))
    Write-Host "       Server address: https://$ServerAddress"
}

# ── 3. Build ─────────────────────────────────────────────────────────────────
Step 'Building images (first build takes 10-20 minutes)...'
docker compose build
if ($LASTEXITCODE -ne 0) { Fail 'Image build failed (see output above).' }

# ── 4. Grype DB ──────────────────────────────────────────────────────────────
$grypeDb = 'backend/bin/syftgrype/grype-db/6/vulnerability.db'
if ($SkipGrypeDb) {
    Step 'Skipping Grype DB download (-SkipGrypeDb).'
} elseif (Test-Path $grypeDb) {
    Step 'Grype vulnerability DB already present, keeping it.'
} else {
    Step 'Downloading Grype vulnerability DB (several hundred MB download, ~3 GB on disk)...'
    New-Item -ItemType Directory -Force backend/bin/syftgrype/grype-db | Out-Null
    docker compose run --rm --no-deps --user root `
        -v ./backend/bin/syftgrype/grype-db:/grype-db `
        -e GRYPE_DB_CACHE_DIR=/grype-db `
        --entrypoint grype orca-backend db update
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[ORCA] WARN: Grype DB download failed. ORCA will still run; vulnerability scans will not work until you re-run this installer or populate the DB (see docs/ADMIN_GUIDE.md).' -ForegroundColor Yellow
    }
}

# ── 5. Start ─────────────────────────────────────────────────────────────────
Step 'Starting ORCA...'
docker compose up -d
if ($LASTEXITCODE -ne 0) { Fail "'docker compose up' failed (see output above)." }

Step 'Waiting for the backend to finish starting (first boot loads the database, up to ~5 minutes)...'
$deadline = (Get-Date).AddMinutes(6)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $logs = docker compose logs --no-log-prefix orca-backend 2>&1 | Out-String
    if ($logs -match 'Application startup complete') { $ready = $true; break }
    Start-Sleep -Seconds 5
}
if (-not $ready) { Fail "Backend didn't come up in time. Check: docker compose logs orca-backend" }

$envFile = Get-Content .env -Raw
$url = if ($envFile -match '(?m)^ORCA_SERVER_URL=(\S+)') { $Matches[1] } else { 'https://localhost' }

Write-Host "`n================================================================" -ForegroundColor Green
Write-Host " ORCA is running: $url" -ForegroundColor Green
Write-Host " (accept the self-signed certificate warning on first visit)"
$logs = docker compose logs --no-log-prefix orca-backend 2>&1 | Out-String
if ($logs -match '(?s)FIRST-BOOT ADMIN ACCOUNT CREATED.*?username:\s*(\S+)\s+password:\s*(\S+)') {
    Write-Host ''
    Write-Host " First-boot admin login (shown once; change it under Options > My Account):" -ForegroundColor Yellow
    Write-Host "   username: $($Matches[1])"
    Write-Host "   password: $($Matches[2])"
} else {
    Write-Host ' Log in with your existing admin account.'
}
Write-Host "================================================================`n" -ForegroundColor Green
