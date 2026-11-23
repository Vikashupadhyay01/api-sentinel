#!/usr/bin/env bash
# ==============================================================================
# API-Sentinel: One-Command Startup Script (Linux / macOS)
#
# Frees ports, starts all services in the proper dependency order,
# redirects logs to logs/*.log, and shuts down cleanly on Ctrl+C.
#
# Usage:
#   ./scripts/start.sh             # Passive Audit mode
#   ENFORCE=1 ./scripts/start.sh   # Active Enforcement mode (blocks violations)
# ==============================================================================

set -e

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
echo "          🛡️   API-SENTINEL: FULL STACK STARTUP RUNNER                  "
echo "========================================================================"
echo -e "${NC}"

# 1. Detect Python interpreter
if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
elif command -v python >/dev/null 2>&1; then
    PYTHON=python
else
    echo -e "${RED}[✗] Error: Python 3 is not installed or not in PATH.${NC}"
    echo -e "    Fix: sudo apt install python3 (or install Python 3.8+)${NC}"
    exit 1
fi

# 2. Detect Node & npm
if ! command -v npm >/dev/null 2>&1; then
    echo -e "${RED}[✗] Error: npm is not installed or not in PATH.${NC}"
    echo -e "    Fix: sudo apt install npm nodejs (or install Node.js 18+)${NC}"
    exit 1
fi

# 3. Create logs directory
LOGS_DIR="$REPO_DIR/logs"
mkdir -p "$LOGS_DIR"

# 4. Free ports 8000, 9000, 8080, 5173
echo -e "${YELLOW}[*] Freeing ports 8000, 9000, 8080, 5173...${NC}"
for port in 8000 9000 8080 5173; do
    if command -v fuser >/dev/null 2>&1; then
        fuser -k "${port}/tcp" >/dev/null 2>&1 || true
    elif command -v lsof >/dev/null 2>&1; then
        pids=$(lsof -ti "tcp:${port}" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            kill -9 $pids 2>/dev/null || true
        fi
    fi
done
sleep 0.5

# 5. Trap cleanup on Ctrl+C (SIGINT) or SIGTERM
cleanup() {
    echo -e "\n${YELLOW}[*] Shutting down all API-Sentinel services...${NC}"
    kill $PID_MOCK $PID_DETECTION $PID_PROXY $PID_DASHBOARD 2>/dev/null || true
    for port in 8000 9000 8080 5173; do
        if command -v fuser >/dev/null 2>&1; then
            fuser -k "${port}/tcp" >/dev/null 2>&1 || true
        fi
    done
    echo -e "${GREEN}[✓] All services stopped cleanly.${NC}"
    exit 0
}
trap cleanup INT TERM

# Helper function to wait for a URL
wait_for_url() {
    local url=$1
    local name=$2
    local retries=30
    while [ $retries -gt 0 ]; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        if [ "$code" != "000" ] && [ -n "$code" ]; then
            return 0
        fi
        sleep 0.4
        retries=$((retries - 1))
    done
    echo -e "${RED}[✗] Timed out waiting for $name at $url${NC}"
    return 1
}

# 6. Start Mock API (:8000)
echo -e "${CYAN}[1/4] Starting Mock Target API on :8000...${NC}"
$PYTHON mock-api/flask_app.py > "$LOGS_DIR/mock-api.log" 2>&1 &
PID_MOCK=$!
if ! wait_for_url "http://127.0.0.1:8000/api/v1/users/me" "Mock API"; then
    echo -e "${RED}Check $LOGS_DIR/mock-api.log for details.${NC}"
    cleanup
fi
echo -e "${GREEN}[✓] Mock API is healthy (:8000)${NC}"

# 7. Start Detection Engine API (:9000)
echo -e "${CYAN}[2/4] Starting Detection API on :9000...${NC}"
$PYTHON backend/api.py > "$LOGS_DIR/detection-api.log" 2>&1 &
PID_DETECTION=$!

ready=0
for i in $(seq 1 30); do
    if curl -s http://127.0.0.1:9000/api/health 2>/dev/null | grep -q '"status":\s*"ok"'; then
        ready=1
        break
    fi
    sleep 0.4
done
if [ $ready -ne 1 ]; then
    echo -e "${RED}[✗] Timed out waiting for Detection API /api/health${NC}"
    echo -e "${RED}Check $LOGS_DIR/detection-api.log for details.${NC}"
    cleanup
fi
echo -e "${GREEN}[✓] Detection API is healthy (:9000)${NC}"

# 8. Start Capture Proxy (:8080) - only after Detection API /api/health is ok
ENFORCE_MODE=${ENFORCE:-0}
if [ "$ENFORCE_MODE" = "1" ]; then
    echo -e "${CYAN}[3/4] Starting Capture Proxy on :8080 (ENFORCE=1 ACTIVE)...${NC}"
else
    echo -e "${CYAN}[3/4] Starting Capture Proxy on :8080 (PASSIVE mode)...${NC}"
fi
ENFORCE=$ENFORCE_MODE UPSTREAM_URL="http://127.0.0.1:8000" DETECTION_API="http://127.0.0.1:9000" $PYTHON capture/proxy.py > "$LOGS_DIR/proxy.log" 2>&1 &
PID_PROXY=$!
if ! wait_for_url "http://127.0.0.1:8080/api/v1/users/me" "Capture Proxy"; then
    echo -e "${RED}Check $LOGS_DIR/proxy.log for details.${NC}"
    cleanup
fi
echo -e "${GREEN}[✓] Capture Proxy is healthy (:8080)${NC}"

# 9. Start Dashboard (:5173)
echo -e "${CYAN}[4/4] Starting React Dashboard on :5173...${NC}"
(cd dashboard && npm run dev -- --host 0.0.0.0 --port 5173) > "$LOGS_DIR/dashboard.log" 2>&1 &
PID_DASHBOARD=$!
if ! wait_for_url "http://127.0.0.1:5173" "Dashboard"; then
    echo -e "${RED}Check $LOGS_DIR/dashboard.log for details.${NC}"
    cleanup
fi
echo -e "${GREEN}[✓] Dashboard is live (:5173)${NC}"

echo -e "\n${BOLD}${GREEN}========================================================================${NC}"
echo -e "${BOLD}${GREEN}      ✨  API-SENTINEL STACK IS RUNNING SUCCESSFULLY!                 ${NC}"
echo -e "${BOLD}${GREEN}========================================================================${NC}"
echo -e "  💻  ${BOLD}Dashboard UI${NC}     : ${CYAN}http://localhost:5173${NC}"
echo -e "  🛡️   ${BOLD}Detection API${NC}    : ${CYAN}http://127.0.0.1:9000/api/health${NC}"
echo -e "  🔍  ${BOLD}Capture Proxy${NC}    : ${CYAN}http://127.0.0.1:8080${NC} (ENFORCE=${ENFORCE_MODE})"
echo -e "  🎯  ${BOLD}Target Mock API${NC}  : ${CYAN}http://127.0.0.1:8000${NC}"
echo -e "  📁  ${BOLD}Log Files${NC}        : ${YELLOW}$LOGS_DIR/*.log${NC}"
echo -e "========================================================================"
echo -e "${YELLOW}Press Ctrl+C to stop all services cleanly.${NC}\n"

# Keep running and wait for background processes
wait
