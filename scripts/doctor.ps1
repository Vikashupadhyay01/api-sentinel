# ==============================================================================
# API-Sentinel: Environment & Dependency Diagnostic Script (doctor.ps1)
#
# Inspects Python, Node.js, required libraries, code syntax, port conflicts,
# and Detection API health on Windows PowerShell.
#
# Usage:
#   .\scripts\doctor.ps1
# ==============================================================================

[CmdletBinding()]
param()

$RepoDir = Split-Path -Parent $PSScriptRoot
Set-Location $RepoDir

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "          🩺  API-SENTINEL: SYSTEM DIAGNOSTIC (DOCTOR - WINDOWS)        " -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan

$Errors = 0
$Warnings = 0

# 1. Check Python Version
Write-Host -NoNewline "[1/7] Checking Python version... "
$PythonCmd = $null
foreach ($cmd in @("python", "py", "python3")) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $PythonCmd = $cmd
        break
    }
}

if (-not $PythonCmd) {
    Write-Host "[FAIL]" -ForegroundColor Red
    Write-Host "      Error: Python not found in PATH." -ForegroundColor Red
    Write-Host "      Fix: Install Python 3.8+ from python.org and check 'Add to PATH'." -ForegroundColor Yellow
    $Errors++
} else {
    try {
        $verStr = & $PythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
        $major = [int](& $PythonCmd -c "import sys; print(sys.version_info.major)")
        $minor = [int](& $PythonCmd -c "import sys; print(sys.version_info.minor)")
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 8)) {
            Write-Host "[FAIL] (Found Python $verStr, required >= 3.8)" -ForegroundColor Red
            Write-Host "      Fix: Upgrade to Python 3.8 or higher." -ForegroundColor Yellow
            $Errors++
        } else {
            Write-Host "[OK] ($PythonCmd $verStr)" -ForegroundColor Green
        }
    } catch {
        Write-Host "[FAIL] (Could not query Python version)" -ForegroundColor Red
        $Errors++
    }
}

# 2. Check Node.js and npm
Write-Host -NoNewline "[2/7] Checking Node.js and npm... "
$nodeOk = (Get-Command "node" -ErrorAction SilentlyContinue) -and (Get-Command "npm" -ErrorAction SilentlyContinue)
if (-not $nodeOk) {
    Write-Host "[FAIL]" -ForegroundColor Red
    Write-Host "      Error: Node.js or npm is missing." -ForegroundColor Red
    Write-Host "      Fix: Install Node.js LTS from https://nodejs.org/" -ForegroundColor Yellow
    $Errors++
} else {
    $nodeVer = & node -v
    $npmVer = & npm -v
    Write-Host "[OK] (Node $nodeVer, npm $npmVer)" -ForegroundColor Green
}

# 3. Check Required Python Packages
Write-Host -NoNewline "[3/7] Checking Python dependencies... "
if ($PythonCmd) {
    $missingPkgs = @()
    $checks = @(
        @{ Mod="flask"; Pip="flask" },
        @{ Mod="reportlab"; Pip="reportlab" },
        @{ Mod="yaml"; Pip="pyyaml" },
        @{ Mod="requests"; Pip="requests" },
        @{ Mod="pytest"; Pip="pytest" }
    )
    foreach ($chk in $checks) {
        $m = $chk.Mod
        $p = $chk.Pip
        $res = & $PythonCmd -c "import $m" 2>$null
        if ($LASTEXITCODE -ne 0) {
            $missingPkgs += $p
        }
    }

    if ($missingPkgs.Count -gt 0) {
        Write-Host "[FAIL]" -ForegroundColor Red
        Write-Host "      Missing Python packages: $($missingPkgs -join ' ')" -ForegroundColor Red
        Write-Host "      Fix: pip install $($missingPkgs -join ' ') (or: pip install -r requirements.txt)" -ForegroundColor Yellow
        $Errors++
    } else {
        Write-Host "[OK] (Flask, reportlab, pyyaml, requests, pytest installed)" -ForegroundColor Green
    }
} else {
    Write-Host "[SKIPPED] (Python missing)" -ForegroundColor Yellow
}

# 4. Check Python Syntax Integrity (py_compile)
Write-Host -NoNewline "[4/7] Checking Python syntax in codebase... "
if ($PythonCmd) {
    $syntaxErrors = 0
    $pyFiles = Get-ChildItem -Path @("backend", "capture", "mock-api", "attack-sim") -Filter "*.py" -Recurse -File -ErrorAction SilentlyContinue
    foreach ($file in $pyFiles) {
        $res = & $PythonCmd -m py_compile $file.FullName 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "`n      Syntax error in $($file.FullName)" -ForegroundColor Red
            $syntaxErrors++
        }
    }

    if ($syntaxErrors -gt 0) {
        Write-Host "[FAIL] ($syntaxErrors syntax errors found)" -ForegroundColor Red
        Write-Host "      Fix: Correct syntax in reported files, then run: python -m py_compile <file>" -ForegroundColor Yellow
        $Errors++
    } else {
        Write-Host "[OK] (All .py files compile cleanly)" -ForegroundColor Green
    }
} else {
    Write-Host "[SKIPPED]" -ForegroundColor Yellow
}

# 5. Check Dashboard node_modules
Write-Host -NoNewline "[5/7] Checking Dashboard dependencies... "
if (Test-Path "dashboard\node_modules") {
    Write-Host "[OK] (dashboard\node_modules present)" -ForegroundColor Green
} else {
    Write-Host "[WARN] (node_modules not found in dashboard\)" -ForegroundColor Yellow
    Write-Host "      Fix: cd dashboard; npm install" -ForegroundColor Yellow
    $Warnings++
}

# 6. Check Port Status (8000, 9000, 8080, 5173)
Write-Host "[6/7] Checking port status (8000, 9000, 8080, 5173)..."
$portList = @(8000, 9000, 8080, 5173)
$portNames = @{ 8000="Mock API"; 9000="Detection API"; 8080="Capture Proxy"; 5173="Vite Dashboard" }
$conflicts = 0

foreach ($p in $portList) {
    $name = $portNames[$p]
    $conns = Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue
    if ($conns) {
        $pids = ($conns | Select-Object -ExpandProperty OwningProcess -Unique) -join ', '
        Write-Host "      - Port $p ($name): IN USE (PID: $pids)" -ForegroundColor Yellow
        $conflicts++
    } else {
        Write-Host "      - Port $p ($name): FREE" -ForegroundColor Green
    }
}

if ($conflicts -gt 0) {
    Write-Host "      Note: Some ports are currently in use. Run .\scripts\stop.ps1 before starting." -ForegroundColor Yellow
}

# 7. Detection API Health Check
Write-Host -NoNewline "[7/7] Probing Detection API health (:9000/api/health)... "
try {
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:9000/api/health" -Method Get -TimeoutSec 2 -ErrorAction Stop
    if ($resp.status -eq "ok") {
        Write-Host "[ONLINE] (status: ok)" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] (Responded but unexpected payload)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[OFFLINE] (Not currently running - run .\scripts\start.ps1 to start)" -ForegroundColor Cyan
}

Write-Host "`n========================================================================" -ForegroundColor Cyan
if ($Errors -eq 0) {
    Write-Host "  ✓ DIAGNOSTIC PASSED! Ready to run: .\scripts\start.ps1" -ForegroundColor Green
    Write-Host "========================================================================" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "  ✗ DIAGNOSTIC FOUND $Errors ERROR(S). See fixes above." -ForegroundColor Red
    Write-Host "========================================================================" -ForegroundColor Cyan
    exit 1
}

