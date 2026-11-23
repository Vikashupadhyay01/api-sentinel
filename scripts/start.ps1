# ==============================================================================
# API-Sentinel: One-Command Startup Script (Windows PowerShell)
#
# Frees ports, starts all services in the proper dependency order,
# redirects logs to logs\*.log, and shuts down cleanly on Ctrl+C.
#
# Usage:
#   .\scripts\start.ps1             # Passive Audit mode
#   $env:ENFORCE="1"; .\scripts\start.ps1  # Active Enforcement mode
# ==============================================================================

[CmdletBinding()]
param()

$RepoDir = Split-Path -Parent $PSScriptRoot
Set-Location $RepoDir

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "          🛡️   API-SENTINEL: FULL STACK STARTUP RUNNER (WINDOWS)        " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

# 1. Detect Python executable
$PythonExe = $null
foreach ($cmd in @("python", "py", "python3")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $PythonExe = $cmd
        break
    }
}

if (-not $PythonExe) {
    Write-Host "[X] Error: Python is not installed or not in PATH." -ForegroundColor Red
    Write-Host "    Fix: Install Python 3.8+ from python.org or Microsoft Store." -ForegroundColor Yellow
    exit 1
}

# 2. Detect npm
if (-not (Get-Command "npm" -ErrorAction SilentlyContinue)) {
    Write-Host "[X] Error: npm is not installed or not in PATH." -ForegroundColor Red
    Write-Host "    Fix: Install Node.js (LTS) from nodejs.org." -ForegroundColor Yellow
    exit 1
}

# 3. Create logs directory
$LogsDir = Join-Path $RepoDir "logs"
if (-not (Test-Path $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir | Out-Null
}

# 4. Free ports 8000, 9000, 8080, 5173
Write-Host "[*] Freeing ports 8000, 9000, 8080, 5173..." -ForegroundColor Yellow
$ports = @(8000, 9000, 8080, 5173)
foreach ($port in $ports) {
    try {
        $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        if ($connections) {
            $procIds = $connections | Select-Object -ExpandProperty OwningProcess -Unique
            foreach ($p in $procIds) {
                if ($p -gt 0) {
                    Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {}
}
Start-Sleep -Milliseconds 600

# Helper function to poll URL
function Wait-ForUrl {
    param([string]$Url, [string]$Name, [int]$Retries = 25)
    while ($Retries -gt 0) {
        try {
            $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) { return $true }
        } catch {
            Start-Sleep -Milliseconds 400
            $Retries--
        }
    }
    Write-Host "[X] Timed out waiting for $Name at $Url" -ForegroundColor Red
    return $false
}

$processes = @()

function Stop-SentinelServices {
    Write-Host "`n[*] Stopping all API-Sentinel services..." -ForegroundColor Yellow
    foreach ($p in $processes) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($port in $ports) {
        try {
            $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
            if ($connections) {
                $connections | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
                    if ($_ -gt 0) { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }
                }
            }
        } catch {}
    }
    Write-Host "[✓] All services stopped cleanly." -ForegroundColor Green
}

try {
    # 5. Start Mock API (:8000)
    Write-Host "[1/4] Starting Mock Target API on :8000..." -ForegroundColor Cyan
    $pMock = Start-Process -FilePath $PythonExe -ArgumentList "mock-api\flask_app.py" `
        -RedirectStandardOutput "$LogsDir\mock-api.log" -RedirectStandardError "$LogsDir\mock-api.log" `
        -NoNewWindow -PassThru
    $processes += $pMock

    if (-not (Wait-ForUrl "http://127.0.0.1:8000/api/v1/users/me" "Mock API")) {
        throw "Failed to start Mock API"
    }
    Write-Host "[✓] Mock API is healthy (:8000)" -ForegroundColor Green

    # 6. Start Detection Engine API (:9000)
    Write-Host "[2/4] Starting Detection API on :9000..." -ForegroundColor Cyan
    $pDetection = Start-Process -FilePath $PythonExe -ArgumentList "backend\api.py" `
        -RedirectStandardOutput "$LogsDir\detection-api.log" -RedirectStandardError "$LogsDir\detection-api.log" `
        -NoNewWindow -PassThru
    $processes += $pDetection

    if (-not (Wait-ForUrl "http://127.0.0.1:9000/api/health" "Detection API")) {
        throw "Failed to start Detection API"
    }
    Write-Host "[✓] Detection API is healthy (:9000)" -ForegroundColor Green

    # 7. Start Capture Proxy (:8080)
    $enforce = if ($env:ENFORCE) { $env:ENFORCE } else { "0" }
    $env:UPSTREAM_URL = "http://127.0.0.1:8000"
    $env:DETECTION_API = "http://127.0.0.1:9000"
    if ($enforce -eq "1") {
        Write-Host "[3/4] Starting Capture Proxy on :8080 (ENFORCE=1 ACTIVE)..." -ForegroundColor Cyan
    } else {
        Write-Host "[3/4] Starting Capture Proxy on :8080 (PASSIVE mode)..." -ForegroundColor Cyan
    }
    $pProxy = Start-Process -FilePath $PythonExe -ArgumentList "capture\proxy.py" `
        -RedirectStandardOutput "$LogsDir\proxy.log" -RedirectStandardError "$LogsDir\proxy.log" `
        -NoNewWindow -PassThru
    $processes += $pProxy

    if (-not (Wait-ForUrl "http://127.0.0.1:8080/api/v1/users/me" "Capture Proxy")) {
        throw "Failed to start Capture Proxy"
    }
    Write-Host "[✓] Capture Proxy is healthy (:8080)" -ForegroundColor Green

    # 8. Start Dashboard (:5173)
    Write-Host "[4/4] Starting React Dashboard on :5173..." -ForegroundColor Cyan
    $pDashboard = Start-Process -FilePath "cmd.exe" -ArgumentList "/c cd dashboard && npm run dev -- --host 0.0.0.0 --port 5173" `
        -RedirectStandardOutput "$LogsDir\dashboard.log" -RedirectStandardError "$LogsDir\dashboard.log" `
        -NoNewWindow -PassThru
    $processes += $pDashboard

    if (-not (Wait-ForUrl "http://127.0.0.1:5173" "Dashboard")) {
        throw "Failed to start Dashboard"
    }
    Write-Host "[✓] Dashboard is live (:5173)" -ForegroundColor Green

    Write-Host "`n========================================================================" -ForegroundColor Green
    Write-Host "      ✨  API-SENTINEL STACK IS RUNNING SUCCESSFULLY!                 " -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host "  💻  Dashboard UI     : http://localhost:5173" -ForegroundColor Cyan
    Write-Host "  🛡️   Detection API    : http://127.0.0.1:9000/api/health" -ForegroundColor Cyan
    Write-Host "  🔍  Capture Proxy    : http://127.0.0.1:8080 (ENFORCE=$enforce)" -ForegroundColor Cyan
    Write-Host "  🎯  Target Mock API  : http://127.0.0.1:8000" -ForegroundColor Cyan
    Write-Host "  📁  Log Files        : $LogsDir\*.log" -ForegroundColor Yellow
    Write-Host "========================================================================" -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop all services cleanly.`n" -ForegroundColor Yellow

    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Stop-SentinelServices
}

