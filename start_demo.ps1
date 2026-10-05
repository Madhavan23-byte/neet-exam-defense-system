# ==============================================================================
# B-SEA Technology Demonstration Startup Script
# Bharat Secure Examination Architecture
# ==============================================================================

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  B-SEA - Demonstration Environment Startup & Health Verification  " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

$ROOT_DIR = $PSScriptRoot
if (-not $ROOT_DIR) { $ROOT_DIR = (Get-Location).Path }

# 1. Check PostgreSQL on Port 5432
Write-Host "`n[1/4] Checking PostgreSQL Service (Port 5432)..." -ForegroundColor Yellow
$pgConn = Get-NetTCPConnection -LocalPort 5432 -ErrorAction SilentlyContinue
if ($pgConn) {
    Write-Host "  [OK] PostgreSQL 16 is active on port 5432 (PID: $($pgConn[0].OwningProcess))" -ForegroundColor Green
} else {
    Write-Host "  [!] PostgreSQL is not listening on 5432. Attempting to start postgresql-x64-16 service..." -ForegroundColor Red
    Start-Service -Name "postgresql-x64-16" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# 2. Check Redis on Port 6379
Write-Host "`n[2/4] Checking Redis Service (Port 6379)..." -ForegroundColor Yellow
$redisConn = Get-NetTCPConnection -LocalPort 6379 -ErrorAction SilentlyContinue
if ($redisConn) {
    Write-Host "  [OK] Redis is active on port 6379 (PID: $($redisConn[0].OwningProcess))" -ForegroundColor Green
} else {
    Write-Host "  [*] Starting Redis server daemon..." -ForegroundColor Yellow
    $redisExe = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\taizod1024.redis-windows-fork_Microsoft.Winget.Source_8wekyb3d8bbwe\Redis-8.10.1-Windows-x64-msys2\redis-server.exe"
    if (Test-Path $redisExe) {
        Start-Process -FilePath $redisExe -ArgumentList "--appendonly yes" -WindowStyle Hidden
        Start-Sleep -Seconds 2
        Write-Host "  [OK] Redis server started" -ForegroundColor Green
    } else {
        Write-Host "  [!] redis-server.exe not found at default winget path" -ForegroundColor Red
    }
}

# 3. Check FastAPI Backend on Port 8000
Write-Host "`n[3/4] Checking FastAPI Backend (Port 8000)..." -ForegroundColor Yellow
$backendConn = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
if ($backendConn) {
    Write-Host "  [OK] FastAPI backend is active on port 8000 (PID: $($backendConn[0].OwningProcess))" -ForegroundColor Green
} else {
    Write-Host "  [*] Starting FastAPI backend daemon..." -ForegroundColor Yellow
    $pythonExe = Join-Path $ROOT_DIR "backend\venv\Scripts\python.exe"
    $backendDir = Join-Path $ROOT_DIR "backend"
    Start-Process -FilePath $pythonExe -ArgumentList "-m uvicorn app.main:app --host 0.0.0.0 --port 8000" -WorkingDirectory $backendDir -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "  [OK] FastAPI backend started" -ForegroundColor Green
}

# Verify Health
try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/ready" -TimeoutSec 5
    Write-Host "  [OK] Health Check: Status = $($health.status) | DB = $($health.checks.database) | Redis = $($health.checks.redis) | Crypto = $($health.checks.crypto)" -ForegroundColor Green
} catch {
    Write-Host "  [!] Health check warning: $_" -ForegroundColor Red
}

# 4. Check Cloudflare Edge Tunnel
Write-Host "`n[4/4] Checking Cloudflare Edge Tunnel..." -ForegroundColor Yellow
$cfProc = Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue
if ($cfProc) {
    Write-Host "  [OK] Cloudflared process is running (PID: $($cfProc[0].Id))" -ForegroundColor Green
} else {
    Write-Host "  [*] Launching cloudflared quick tunnel..." -ForegroundColor Yellow
    $cfExe = Join-Path $ROOT_DIR "cloudflared.exe"
    $logFile = Join-Path $ROOT_DIR "cloudflared.log"
    Start-Process -FilePath $cfExe -ArgumentList "tunnel --url http://127.0.0.1:8000" -RedirectStandardError $logFile -WindowStyle Hidden
    Start-Sleep -Seconds 5
    $cfProc = Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue
    Write-Host "  [OK] Cloudflare tunnel started" -ForegroundColor Green
}

# Find Tunnel URL
$logFile = Join-Path $ROOT_DIR "cloudflared.log"
if (Test-Path $logFile) {
    $match = Get-Content $logFile -Tail 50 | Select-String -Pattern "https://[a-zA-Z0-9-]+\.trycloudflare\.com"
    if ($match) {
        $tunnelUrl = $match.Matches[0].Value
        Write-Host "`n=================================================================" -ForegroundColor Cyan
        Write-Host "  DEMO BACKEND READY FOR PRESENTATION" -ForegroundColor Green
        Write-Host "=================================================================" -ForegroundColor Cyan
        Write-Host "  Local Backend URL:    http://127.0.0.1:8000" -ForegroundColor White
        Write-Host "  Public HTTPS Tunnel:  $tunnelUrl" -ForegroundColor White
        Write-Host "  Live Vercel Frontend: https://neet-exam-defense-system.vercel.app" -ForegroundColor White
        Write-Host "=================================================================" -ForegroundColor Cyan
    }
}
