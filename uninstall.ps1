<#
.SYNOPSIS
    Removes ORCA from this machine's Docker (containers, images and, if you
    choose, all data).

.DESCRIPTION
    Handles both installs made by install.ps1 / docker compose and older
    installs with a standalone 'orca-postgres' container (start.bat era).

    Removes:
      - containers orca-backend, orca-frontend, orca-postgres
      - the ORCA images (orcaweb-orca-backend / orcaweb-orca-frontend)
      - the ORCA Docker network
    With -RemoveData (or answering yes at the prompt), ALSO deletes:
      - the database volume (all cases, evidence records, users)
      - the evidence volume and the TLS certificate volume
    Files in this folder are never touched, except .env with -RemoveEnv.

.PARAMETER RemoveData
    Delete all ORCA data without asking. THIS CANNOT BE UNDONE.

.PARAMETER KeepData
    Keep the data volumes without asking (a later install reuses them).

.PARAMETER RemoveEnv
    Also delete this folder's .env (secrets and server address), so the next
    install generates a new one.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
.EXAMPLE
    .\uninstall.ps1 -RemoveData -RemoveEnv     # complete wipe before a fresh install
#>
param(
    [switch]$RemoveData,
    [switch]$KeepData,
    [switch]$RemoveEnv
)

$ErrorActionPreference = 'Continue'
Set-Location -Path $PSScriptRoot

function Step($msg) { Write-Host "`n[ORCA] $msg" -ForegroundColor Cyan }
function Fail($msg) { Write-Host "[ORCA] ERROR: $msg" -ForegroundColor Red; exit 1 }

if ($RemoveData -and $KeepData) { Fail '-RemoveData and -KeepData cannot be used together.' }

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Fail 'Docker is not installed.' }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail 'Docker is not running. Start Docker Desktop and re-run.' }

$project = if ($env:COMPOSE_PROJECT_NAME) { $env:COMPOSE_PROJECT_NAME } else { 'orcaweb' }

# ── Find everything ORCA owns ────────────────────────────────────────────────
$containers = @(docker ps -a --filter "label=com.docker.compose.project=$project" --format '{{.Names}}')
foreach ($name in 'orca-backend', 'orca-frontend', 'orca-postgres') {
    if ($env:COMPOSE_PROJECT_NAME) { break }   # isolated/test project: compose labels only
    docker inspect $name *> $null
    if ($LASTEXITCODE -eq 0 -and $containers -notcontains $name) { $containers += $name }
}
$containers = @($containers | Where-Object { $_ })

$volumes = @(docker volume ls -q --filter "label=com.docker.compose.project=$project")
foreach ($c in $containers) {
    # No double quotes inside the template: Windows PowerShell 5.1 strips
    # them when calling docker. Filter on Type here instead.
    $mounts = docker inspect $c --format '{{range .Mounts}}{{.Type}}={{.Name}} {{end}}'
    foreach ($m in ($mounts -split ' ')) {
        if ($m -like 'volume=*') {
            $v = $m.Substring(7)
            if ($v -and $volumes -notcontains $v) { $volumes += $v }
        }
    }
}
$volumes = @($volumes | Where-Object { $_ })

$images = @(docker images --format '{{.Repository}}' | Where-Object { $_ -in "$project-orca-backend", "$project-orca-frontend" } | Select-Object -Unique)

if (-not $containers -and -not $volumes -and -not $images) {
    Step 'No ORCA containers, volumes or images found. Nothing to remove.'
} else {
    Write-Host ''
    Write-Host '[ORCA] Found:' -ForegroundColor Cyan
    Write-Host "   containers: $(if ($containers) { $containers -join ', ' } else { '(none)' })"
    Write-Host "   images:     $(if ($images) { $images -join ', ' } else { '(none)' })"
    Write-Host "   data volumes: $(if ($volumes) { $volumes -join ', ' } else { '(none)' })"

    if ($volumes -and -not $RemoveData -and -not $KeepData) {
        Write-Host ''
        Write-Host '   Deleting the data volumes permanently erases the ORCA database (cases, evidence, users)' -ForegroundColor Yellow
        Write-Host '   and stored evidence files. Keep them if you want a reinstall to pick up where you left off.' -ForegroundColor Yellow
        $answer = Read-Host "   Type DELETE to remove all ORCA data, or press Enter to keep it"
        $RemoveData = ($answer -ceq 'DELETE')
    }

    # ── Remove ───────────────────────────────────────────────────────────────
    if (Test-Path docker-compose.yml) {
        Step 'Stopping ORCA (docker compose down)...'
        docker compose down --remove-orphans
    }
    if ($containers) {
        Step "Removing containers: $($containers -join ', ')"
        docker rm -f @containers 2>&1 | Out-Null
    }
    if ($images) {
        Step "Removing images: $($images -join ', ')"
        docker rmi -f @images 2>&1 | Out-Null
    }
    docker network rm "${project}_orca-net" *> $null

    if ($RemoveData -and $volumes) {
        Step "Deleting data volumes: $($volumes -join ', ')"
        docker volume rm -f @volumes
    } elseif ($volumes) {
        Step "Kept data volumes: $($volumes -join ', ') (re-run with -RemoveData to delete them)"
    }
}

if ($RemoveEnv -and (Test-Path .env)) {
    Remove-Item .env -Force
    Step 'Deleted .env'
}

Write-Host "`n[ORCA] Uninstall complete.`n" -ForegroundColor Green
