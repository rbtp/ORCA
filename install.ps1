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
    # {{json ...}} rather than {{index .Config.Labels "..."}}: Windows
    # PowerShell 5.1 strips the inner double quotes when calling docker,
    # which breaks the template and made this check silently never fire.
    $labelsJson = docker inspect $name --format '{{json .Config.Labels}}' 2>$null
    if ($LASTEXITCODE -ne 0) { continue }
    $labels = $labelsJson | ConvertFrom-Json
    $proj = if ($labels) { $labels.'com.docker.compose.project' } else { $null }
    if ($proj -ne 'orcaweb') {
        Fail "A container named '$name' already exists and isn't managed by this ORCA install (older start.bat-style install?). Run .\uninstall.ps1 first."
    }
}

# ── 2. .env ──────────────────────────────────────────────────────────────────
# .env holds this machine's secrets and address. Installs made by this script
# record the machine in ORCA_INSTALL_HOST, so a .env that arrived with a
# folder copied from another machine can be recognised and not reused.
$thisHost = $env:COMPUTERNAME
$project  = if ($env:COMPOSE_PROJECT_NAME) { $env:COMPOSE_PROJECT_NAME } else { 'orcaweb' }
# Settings that are safe to carry over from another machine's .env.
$portableKeys = 'VT_API_KEY','VT_RECHECK_DAYS','VT_RATE_LIMIT_SECONDS','SMTP_HOST','SMTP_PORT','SMTP_USER',
                'SMTP_PASSWORD','SMTP_FROM','SMTP_USE_TLS','ORCA_BOOTSTRAP_ADMIN_USERNAME',
                'ORCA_BOOTSTRAP_ADMIN_PASSWORD','ORCA_BOOTSTRAP_ADMIN_INITIALS'

function Get-EnvValue($text, $key) {
    if ($text -match "(?m)^$key=(.*)$") { return $Matches[1].Trim() } else { return $null }
}
function Set-EnvValue($text, $key, $value) {
    if ($text -match "(?m)^$key=") { return ($text -replace "(?m)^$key=.*$", "$key=$value") }
    if ($text -match "(?m)^# $key=") { return ($text -replace "(?m)^# $key=.*$", "$key=$value") }
    return ($text.TrimEnd() + "`n$key=$value`n")
}
function Get-LocalAddresses {
    $a = @('localhost', '127.0.0.1', $env:COMPUTERNAME.ToLower())
    try { $a += (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop).IPAddress } catch {}
    return $a
}
function Read-ServerAddress {
    if ($ServerAddress) { return $ServerAddress }
    $detected = Get-PrimaryIPv4
    $answer = Read-Host "Server IP/hostname analysts and agents will use [$detected]"
    if ($answer) { return $answer.Trim() } else { return $detected }
}
function Write-EnvFile($text) {
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot '.env'), $text, (New-Object Text.UTF8Encoding $false))
}

docker volume inspect "${project}_orca-postgres-data" *> $null
$haveDatabase = ($LASTEXITCODE -eq 0)
if (-not $haveDatabase -and -not $env:COMPOSE_PROJECT_NAME) {
    docker inspect orca-postgres *> $null
    $haveDatabase = ($LASTEXITCODE -eq 0)
}

$existing = if (Test-Path .env) { Get-Content .env -Raw } else { $null }
$envHost  = if ($existing) { Get-EnvValue $existing 'ORCA_INSTALL_HOST' } else { $null }

if ($existing -and $envHost -eq $thisHost) {
    Step '.env already exists for this machine, keeping it.'
    if ($ServerAddress) {
        $existing = Set-EnvValue $existing 'ORCA_SERVER_URL' "https://$ServerAddress"
        $existing = Set-EnvValue $existing 'CORS_ORIGINS' "https://$ServerAddress,https://localhost"
        Write-EnvFile $existing
        Write-Host "       Server address set to: https://$ServerAddress"
    }
} elseif ($existing -and $haveDatabase) {
    # Pre-marker .env with an existing ORCA database: the DB password is
    # baked into that database, so the secrets must stay. Only the address
    # may need fixing.
    Step '.env found alongside an existing ORCA database, keeping its secrets.'
    $url = Get-EnvValue $existing 'ORCA_SERVER_URL'
    $urlHost = if ($url) { ([uri]$url).Host.ToLower() } else { '' }
    if ($ServerAddress -or -not $urlHost -or ((Get-LocalAddresses) -notcontains $urlHost)) {
        if (-not $ServerAddress -and $urlHost) {
            Write-Host "       ORCA_SERVER_URL ($url) is not an address of this machine." -ForegroundColor Yellow
        }
        $addr = Read-ServerAddress
        $existing = Set-EnvValue $existing 'ORCA_SERVER_URL' "https://$addr"
        $existing = Set-EnvValue $existing 'CORS_ORIGINS' "https://$addr,https://localhost"
        Write-Host "       Server address: https://$addr"
    }
    Write-EnvFile (Set-EnvValue $existing 'ORCA_INSTALL_HOST' $thisHost)
} else {
    if ($existing) {
        $from = if ($envHost) { $envHost } else { 'another-machine' }
        $backup = ".env.from-$from-$(Get-Date -Format yyyyMMdd-HHmmss)"
        Copy-Item .env $backup
        Step ".env came from another machine (saved as $backup). Creating a new one for this machine..."
    } else {
        Step 'Creating .env...'
    }
    $addr = Read-ServerAddress
    $envText = Get-Content .env.example -Raw
    $envText = Set-EnvValue $envText 'JWT_SECRET' (New-Secret)
    $envText = Set-EnvValue $envText 'DB_PASSWORD' (New-Secret)
    $envText = Set-EnvValue $envText 'CORS_ORIGINS' "https://$addr,https://localhost"
    $envText = Set-EnvValue $envText 'ORCA_SERVER_URL' "https://$addr"
    if ($existing) {
        foreach ($k in $portableKeys) {
            $v = Get-EnvValue $existing $k
            if ($v) { $envText = Set-EnvValue $envText $k $v; Write-Host "       Carried over $k" }
        }
    }
    $envText = Set-EnvValue $envText 'ORCA_INSTALL_HOST' $thisHost
    Write-EnvFile $envText
    Write-Host "       Server address: https://$addr"
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
        --entrypoint sh orca-backend -c 'grype db update && chmod -R a+rX /grype-db'
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[ORCA] WARN: Grype DB download failed. ORCA will still run; vulnerability scans will not work until you re-run this installer or populate the DB (see docs/ADMIN_GUIDE.md).' -ForegroundColor Yellow
    }
}

# ── 5. Start ─────────────────────────────────────────────────────────────────
Step 'Starting the database...'
docker compose up -d orca-postgres
if ($LASTEXITCODE -ne 0) { Fail "Could not start the database container (see output above)." }
# TCP check (-h 127.0.0.1): on a new volume Postgres first runs the schema and
# seed scripts on a socket-only server, which a socket check would report as ready.
$deadline = (Get-Date).AddMinutes(5)
do {
    docker compose exec -T orca-postgres pg_isready -h 127.0.0.1 -U postgres -d orca_db *> $null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)
if ($LASTEXITCODE -ne 0) { Fail "Database didn't become ready. Check: docker compose logs orca-postgres" }

# Make the database password match .env. Postgres only applies
# POSTGRES_PASSWORD when a volume is first created, so a database kept from an
# earlier install (or a .env copied from another machine) could otherwise
# have a different password and the backend couldn't connect. Runs over the
# container's local socket, which needs no password.
$dbPassword = Get-EnvValue (Get-Content .env -Raw) 'DB_PASSWORD'
docker compose exec -T orca-postgres psql -U postgres -d postgres -q -c "ALTER USER postgres WITH PASSWORD '$dbPassword'" *> $null
if ($LASTEXITCODE -ne 0) { Fail "Could not set the database password. Check: docker compose logs orca-postgres" }

Step 'Starting ORCA...'
docker compose up -d
if ($LASTEXITCODE -ne 0) { Fail "'docker compose up' failed (see output above)." }

Step 'Waiting for the backend to finish starting (first boot loads the database, up to ~5 minutes)...'
$deadline = (Get-Date).AddMinutes(6)
$ready = $false
while ((Get-Date) -lt $deadline) {
    $logs = docker compose logs --no-log-prefix orca-backend 2>&1 | Out-String
    if ($logs -match 'Application startup complete') { $ready = $true; break }
    if ($logs -match 'Backend not started') {
        $logs -split "`n" | Where-Object { $_ -match 'FATAL' } | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        Fail 'Database migration failed (see above). Full log: docker compose logs orca-backend'
    }
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
