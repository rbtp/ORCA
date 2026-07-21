#Requires -Version 5.1
# deploy-behavioral.ps1 -- One-shot deployment of behavioral analysis stack (CAPA/FLOSS/Speakeasy)
# Usage: .\deploy-behavioral.ps1
# Run from the ORCAWEB project root.

$ErrorActionPreference = 'Stop'
$env:COMPOSE_PROJECT_NAME = 'orcaweb'

Write-Host "[1/8] Verifying required containers are running..." -ForegroundColor Cyan

$pgStatus = docker inspect -f '{{.State.Running}}' orca-postgres 2>$null
if ($pgStatus -ne 'true') {
    Write-Host "ERROR: orca-postgres is not running. Start it before deploying." -ForegroundColor Red
    exit 1
}
Write-Host "  orca-postgres: OK" -ForegroundColor Green

$beStatus = $null
$backendName = $null
foreach ($name in @('orcaweb-orca-backend-1', 'orca-backend')) {
    try {
        $s = & docker inspect -f '{{.State.Running}}' $name 2>$null
        if ($s -eq 'true') { $beStatus = 'true'; $backendName = $name; break }
    } catch {}
}
if ($beStatus -ne 'true') {
    Write-Host "WARNING: orca-backend container not found or not running. Will start it after rebuild." -ForegroundColor Yellow
    $backendName = 'orcaweb-orca-backend-1'
} else {
    Write-Host "  orca-backend ($backendName): OK" -ForegroundColor Green
}


Write-Host "[2/8] Writing behavioral analysis migration SQL to temp file..." -ForegroundColor Cyan

$migrationSql = @'
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS behavioral_jobs (
    job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id INTEGER NOT NULL,
    submitted_file TEXT,
    file_path TEXT,
    file_md5 TEXT,
    file_sha256 TEXT,
    file_type TEXT,
    file_size_bytes BIGINT,
    submitted_by TEXT,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    overall_status TEXT DEFAULT 'pending',
    capa_status TEXT DEFAULT 'pending',
    capa_started_at TIMESTAMP WITH TIME ZONE,
    capa_completed_at TIMESTAMP WITH TIME ZONE,
    capa_error TEXT,
    floss_status TEXT DEFAULT 'pending',
    floss_started_at TIMESTAMP WITH TIME ZONE,
    floss_completed_at TIMESTAMP WITH TIME ZONE,
    floss_error TEXT,
    speakeasy_status TEXT DEFAULT 'pending',
    speakeasy_started_at TIMESTAMP WITH TIME ZONE,
    speakeasy_completed_at TIMESTAMP WITH TIME ZONE,
    speakeasy_error TEXT
);

CREATE TABLE IF NOT EXISTS capa_results (
    id SERIAL PRIMARY KEY,
    job_id UUID REFERENCES behavioral_jobs(job_id) ON DELETE CASCADE,
    technique_id TEXT,
    technique_name TEXT,
    tactic_name TEXT,
    namespace TEXT,
    severity TEXT,
    raw_result JSONB
);

CREATE TABLE IF NOT EXISTS floss_results (
    id SERIAL PRIMARY KEY,
    job_id UUID REFERENCES behavioral_jobs(job_id) ON DELETE CASCADE,
    string_value TEXT NOT NULL,
    string_type TEXT,
    is_ioc BOOLEAN DEFAULT FALSE,
    ioc_type TEXT,
    string_offset BIGINT
);

CREATE TABLE IF NOT EXISTS speakeasy_results (
    id SERIAL PRIMARY KEY,
    job_id UUID REFERENCES behavioral_jobs(job_id) ON DELETE CASCADE,
    result_type TEXT NOT NULL,
    func_name TEXT,
    args JSONB,
    ret_val TEXT,
    pc BIGINT,
    entry_point TEXT,
    protocol TEXT,
    host TEXT,
    port INTEGER,
    url TEXT
);
'@

$tmpSqlPath = Join-Path $env:TEMP 'orca_behavioral_migration.sql'
$migrationSql | Out-File -FilePath $tmpSqlPath -Encoding utf8 -NoNewline

Write-Host "  SQL written to $tmpSqlPath" -ForegroundColor Green


Write-Host "[3/8] Copying migration SQL into orca-postgres container and running it..." -ForegroundColor Cyan

docker cp $tmpSqlPath orca-postgres:/tmp/behavioral_migration.sql
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: docker cp failed" -ForegroundColor Red; exit 1 }

docker exec orca-postgres psql -U postgres -d orca_db -f /tmp/behavioral_migration.sql
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: migration SQL failed" -ForegroundColor Red; exit 1 }

Remove-Item $tmpSqlPath -ErrorAction SilentlyContinue
Write-Host "  Migration complete" -ForegroundColor Green


Write-Host "[4/8] Verifying tables were created..." -ForegroundColor Cyan

$tables = @('behavioral_jobs', 'capa_results', 'floss_results', 'speakeasy_results')
foreach ($tbl in $tables) {
    $result = docker exec orca-postgres psql -U postgres -d orca_db -tAc "SELECT to_regclass('public.$tbl');" 2>$null
    if ($result -notmatch $tbl) {
        Write-Host "ERROR: table $tbl not found after migration" -ForegroundColor Red
        exit 1
    }
    Write-Host "  ${tbl}: OK" -ForegroundColor Green
}


Write-Host "[5/8] Rebuilding orca-backend image (installs capa, flare-floss, speakeasy-emulator)..." -ForegroundColor Cyan

docker compose build orca-backend
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: docker compose build failed" -ForegroundColor Red; exit 1 }
Write-Host "  Build complete" -ForegroundColor Green


Write-Host "[6/8] Restarting orca-backend container (--no-deps to avoid touching orca-postgres)..." -ForegroundColor Cyan

docker compose up -d --no-deps orca-backend
if ($LASTEXITCODE -ne 0) { Write-Host "ERROR: docker compose up failed" -ForegroundColor Red; exit 1 }

Write-Host "  Waiting 10s for container to start..." -ForegroundColor Gray
Start-Sleep -Seconds 10
Write-Host "  orca-backend restarted" -ForegroundColor Green


Write-Host "[7/8] Verifying pip packages installed in container..." -ForegroundColor Cyan

$packages = @('capa', 'floss', 'speakeasy')
foreach ($pkg in $packages) {
    $check = $null
    try { $check = & docker exec $backendName python -c "import $pkg; print('ok')" 2>$null } catch {}
    if (-not $check) {
        try { $check = & docker exec orca-backend python -c "import $pkg; print('ok')" 2>$null } catch {}
    }
    if ($check -match 'ok') {
        Write-Host "  $pkg : OK" -ForegroundColor Green
    } else {
        Write-Host "  WARNING: $pkg import failed (may be expected if package uses different import name)" -ForegroundColor Yellow
    }
}


Write-Host "[8/8] Smoke testing /api/behavioral/asset/0/jobs endpoint..." -ForegroundColor Cyan

Start-Sleep -Seconds 3

# Try to get a token for smoke test using default admin credentials
$tokenResp = $null
try {
    $body = '{"username":"admin","password":"admin"}'
    $tokenResp = Invoke-RestMethod -Method Post -Uri 'https://localhost/api/auth/login' `
        -Body $body -ContentType 'application/json' -SkipCertificateCheck -TimeoutSec 10 -ErrorAction Stop
} catch {
    Write-Host "  INFO: Could not auto-login for smoke test (adjust credentials if needed)" -ForegroundColor Gray
}

if ($tokenResp -and $tokenResp.access_token) {
    try {
        $headers = @{ Authorization = "Bearer $($tokenResp.access_token)" }
        $resp = Invoke-RestMethod -Method Get -Uri 'https://localhost/api/behavioral/asset/0/jobs' `
            -Headers $headers -SkipCertificateCheck -TimeoutSec 10 -ErrorAction Stop
        Write-Host "  /api/behavioral/asset/0/jobs: OK (returned $($resp.Count) records)" -ForegroundColor Green
    } catch {
        Write-Host "  WARNING: smoke test request failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Skipping authenticated smoke test (no token). Check manually:" -ForegroundColor Gray
    Write-Host "    GET https://localhost/api/behavioral/asset/0/jobs" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== deploy-behavioral.ps1 complete ===" -ForegroundColor Green
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open ORCA in browser and navigate to any asset's BEHAVIORAL ANALYSIS tab" -ForegroundColor White
Write-Host "  2. Submit a PE or ELF binary and watch the SSE stream" -ForegroundColor White
Write-Host "  3. If CAPA/FLOSS packages fail to import, check container logs:" -ForegroundColor White
Write-Host "     docker logs orcaweb-orca-backend-1 --tail 50" -ForegroundColor Gray
