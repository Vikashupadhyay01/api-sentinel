#!/usr/bin/env bash
# ==============================================================================
# API-Sentinel: Environment & Dependency Diagnostic Script (doctor.sh)
#
# Inspects Python, Node.js, required libraries, code syntax, port conflicts,
# and Detection API health, providing actionable fixes for any issues found.
#
# Usage:
#   ./scripts/doctor.sh
# ==============================================================================

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR"

# ANSI Colors
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}"
echo "========================================================================"
echo "          🩺  API-SENTINEL: SYSTEM DIAGNOSTIC (DOCTOR)                  "
echo "========================================================================"
echo -e "${NC}"

ERRORS=0
WARNINGS=0

# 1. Check Python Version
echo -n "[1/7] Checking Python version... "
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
fi

if [ -z "$PYTHON_CMD" ]; then
    echo -e "${RED}[FAIL]${NC}"
    echo -e "      ${RED}Error: Python 3 not found in PATH.${NC}"
    echo -e "      ${YELLOW}Fix: sudo apt update && sudo apt install -y python3 python3-pip${NC}"
    ERRORS=$((ERRORS + 1))
else
    PY_VER=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')" 2>/dev/null || echo "0.0.0")
    PY_MAJOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
    PY_MINOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo "0")
    if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]); then
        echo -e "${RED}[FAIL] (Found Python $PY_VER, required >= 3.8)${NC}"
        echo -e "      ${YELLOW}Fix: Upgrade to Python 3.8 or higher.${NC}"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}[OK] ($PYTHON_CMD $PY_VER)${NC}"
    fi
fi

# 2. Check Node.js and npm
echo -n "[2/7] Checking Node.js and npm... "
NODE_OK=1
if ! command -v node >/dev/null 2>&1; then
    NODE_OK=0
fi
if ! command -v npm >/dev/null 2>&1; then
    NODE_OK=0
fi

if [ $NODE_OK -eq 0 ]; then
    echo -e "${RED}[FAIL]${NC}"
    echo -e "      ${RED}Error: Node.js or npm is missing.${NC}"
    echo -e "      ${YELLOW}Fix: sudo apt install -y nodejs npm (or install Node LTS via nvm / nodejs.org)${NC}"
    ERRORS=$((ERRORS + 1))
else
    NODE_VER=$(node -v 2>/dev/null || echo "unknown")
    NPM_VER=$(npm -v 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[OK] (Node $NODE_VER, npm $NPM_VER)${NC}"
fi

# 3. Check Required Python Packages
echo -n "[3/7] Checking Python dependencies... "
if [ -n "$PYTHON_CMD" ]; then
    MISSING_PKGS=()
    for pkg in "flask" "reportlab" "yaml:pyyaml" "requests" "pytest"; do
        mod="${pkg%%:*}"
        pip_name="${pkg##*:}"
        if ! $PYTHON_CMD -c "import $mod" >/dev/null 2>&1; then
            MISSING_PKGS+=("$pip_name")
        fi
    done

    if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
        echo -e "${RED}[FAIL]${NC}"
        echo -e "      ${RED}Missing Python packages: ${MISSING_PKGS[*]}${NC}"
        echo -e "      ${YELLOW}Fix: pip install ${MISSING_PKGS[*]} (or: pip install -r requirements.txt)${NC}"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}[OK] (Flask, reportlab, pyyaml, requests, pytest installed)${NC}"
    fi
else
    echo -e "${YELLOW}[SKIPPED] (Python missing)${NC}"
fi

# 4. Check Python Syntax Integrity (py_compile)
echo -n "[4/7] Checking Python syntax in codebase... "
if [ -n "$PYTHON_CMD" ]; then
    SYNTAX_ERRORS=0
    while IFS= read -r pyfile; do
        if ! $PYTHON_CMD -m py_compile "$pyfile" 2>/dev/null; then
            echo -e "\n      ${RED}Syntax error in $pyfile${NC}"
            SYNTAX_ERRORS=$((SYNTAX_ERRORS + 1))
        fi
    done < <(find backend capture mock-api attack-sim -type f -name "*.py" 2>/dev/null)

    if [ $SYNTAX_ERRORS -gt 0 ]; then
        echo -e "${RED}[FAIL] ($SYNTAX_ERRORS syntax errors found)${NC}"
        echo -e "      ${YELLOW}Fix: Correct syntax in the reported files, then run: python3 -m py_compile <file>${NC}"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}[OK] (All .py files compile cleanly)${NC}"
    fi
else
    echo -e "${YELLOW}[SKIPPED]${NC}"
fi

# 5. Check Dashboard node_modules
echo -n "[5/7] Checking Dashboard dependencies... "
if [ -d "dashboard/node_modules" ]; then
    echo -e "${GREEN}[OK] (dashboard/node_modules present)${NC}"
else
    echo -e "${YELLOW}[WARN] (node_modules not found in dashboard/)${NC}"
    echo -e "      ${YELLOW}Fix: cd dashboard && npm install${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

# 6. Check Port Status (8000, 9000, 8080, 5173)
echo -e "[6/7] Checking port status (8000, 9000, 8080, 5173)..."
PORTS=(8000 9000 8080 5173)
PORT_NAMES=("Mock API" "Detection API" "Capture Proxy" "Vite Dashboard")
CONFLICTS=0

for i in "${!PORTS[@]}"; do
    port="${PORTS[$i]}"
    name="${PORT_NAMES[$i]}"
    OCCUPIED=0
    PID_INFO=""

    if command -v lsof >/dev/null 2>&1; then
        PID_INFO=$(lsof -ti "tcp:$port" 2>/dev/null | tr '\n' ' ' || true)
        if [ -n "$PID_INFO" ]; then OCCUPIED=1; fi
    elif command -v fuser >/dev/null 2>&1; then
        if fuser "$port/tcp" >/dev/null 2>&1; then OCCUPIED=1; fi
    elif command -v ss >/dev/null 2>&1; then
        if ss -tln | grep -q ":$port "; then OCCUPIED=1; fi
    fi

    if [ $OCCUPIED -eq 1 ]; then
        echo -e "      - Port $port ($name): ${YELLOW}IN USE${NC} (PID: ${PID_INFO:-unknown})"
        CONFLICTS=$((CONFLICTS + 1))
    else
        echo -e "      - Port $port ($name): ${GREEN}FREE${NC}"
    fi
done

if [ $CONFLICTS -gt 0 ]; then
    echo -e "      ${YELLOW}Note: Some ports are currently in use. If starting fresh, run ./scripts/stop.sh${NC}"
fi

# 7. Detection API Health Check
echo -n "[7/7] Probing Detection API health (:9000/api/health)... "
HEALTH_RESP=$(curl -s -m 2 http://127.0.0.1:9000/api/health 2>/dev/null || echo "")
if echo "$HEALTH_RESP" | grep -q '"status":\s*"ok"'; then
    echo -e "${GREEN}[ONLINE] (status: ok)${NC}"
elif [ -n "$HEALTH_RESP" ]; then
    echo -e "${YELLOW}[WARNING] (Responded but unexpected payload: $HEALTH_RESP)${NC}"
else
    echo -e "${CYAN}[OFFLINE] (Not currently running - run ./scripts/start.sh to start)${NC}"
fi

echo -e "\n========================================================================"
if [ $ERRORS -eq 0 ]; then
    echo -e "${BOLD}${GREEN}  ✓ DIAGNOSTIC PASSED! Ready to run: ./scripts/start.sh${NC}"
    echo -e "========================================================================"
    exit 0
else
    echo -e "${BOLD}${RED}  ✗ DIAGNOSTIC FOUND $ERRORS ERROR(S). See fixes above.${NC}"
    echo -e "========================================================================"
    exit 1
fi

