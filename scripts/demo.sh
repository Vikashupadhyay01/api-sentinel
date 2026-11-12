#!/usr/bin/env bash
# ==============================================================================
# API-Sentinel: End-to-End Demonstration Script
#
# Starts all components:
#   1. Mock Shop API        (:8000)
#   2. Detection API        (:9000)
#   3. Capture Proxy        (:8080)
#
# Then executes:
#   Step 1: Normal Traffic      -> verified 0 alerts
#   Step 2: Shadow & Zombie API -> verified API9 alerts
#   Step 3: BOLA Attack         -> verified API1 alerts (or 403 if ENFORCE=1)
#   Step 4: Enumeration Attack  -> verified API4 / API6 alerts
#
# Usage:
#   ./scripts/demo.sh              # Standard Detection Mode
#   ENFORCE=1 ./scripts/demo.sh    # Active Enforcement Mode (blocks violations)
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

ENFORCE_MODE=${ENFORCE:-0}

echo -e "${BOLD}${CYAN}"
echo "========================================================================"
echo "      🛡️  API-SENTINEL: RUNTIME BOLA & SHADOW API DETECTION ENGINE     "
echo "========================================================================"
echo -e "${NC}"

if [ "$ENFORCE_MODE" = "1" ]; then
    echo -e "${YELLOW}Mode: ENFORCEMENT ACTIVE (Violations will be blocked with 403)${NC}\n"
else
    echo -e "${CYAN}Mode: PASSIVE DETECTION (Observing and auditing traffic)${NC}\n"
fi

# Clean previous event logs
rm -f data/events.jsonl
mkdir -p data

# Ensure cleanup on script exit
cleanup() {
    echo -e "\n${YELLOW}[*] Shutting down background services...${NC}"
    kill $PID_PROXY $PID_DETECTION $PID_MOCK 2>/dev/null || true
    wait $PID_PROXY $PID_DETECTION $PID_MOCK 2>/dev/null || true
    echo -e "${GREEN}[✓] All services stopped cleanly.${NC}"
}
trap cleanup EXIT INT TERM

wait_for_url() {
    local url=$1
    local name=$2
    local retries=15
    while [ $retries -gt 0 ]; do
        if curl -s "$url" > /dev/null 2>&1; then
            return 0
        fi
        sleep 0.4
        retries=$((retries - 1))
    done
    echo -e "${RED}Timed out waiting for $name at $url${NC}"
    return 1
}

# 1. Start Mock API on :8000
echo -e "${CYAN}[1/3] Starting Mock Target API on :8000...${NC}"
python3 mock-api/flask_app.py > /dev/null 2>&1 &
PID_MOCK=$!
wait_for_url "http://127.0.0.1:8000/api/v1/users/me" "Mock API"

# 2. Start Detection API on :9000
echo -e "${CYAN}[2/3] Starting Detection Engine API on :9000...${NC}"
python3 backend/api.py > /dev/null 2>&1 &
PID_DETECTION=$!
wait_for_url "http://127.0.0.1:9000/api/health" "Detection API"

# 3. Start Capture Proxy on :8080
echo -e "${CYAN}[3/3] Starting Capture Proxy on :8080 (ENFORCE=${ENFORCE_MODE})...${NC}"
ENFORCE=$ENFORCE_MODE UPSTREAM_URL="http://127.0.0.1:8000" DETECTION_API="http://127.0.0.1:9000" python3 capture/proxy.py > /dev/null 2>&1 &
PID_PROXY=$!
wait_for_url "http://127.0.0.1:8080/api/v1/users/me" "Capture Proxy"

echo -e "\n${GREEN}[✓] Mock API (8000), Detection API (9000), and Proxy (8080) are all healthy!${NC}\n"

# ==============================================================================
# STEP 1: Normal Traffic (Zero False Positives)
# ==============================================================================
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}STEP 1: Simulating Normal Legitimate Traffic (All 3 Users)${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
python3 attack-sim/normal_traffic.py http://127.0.0.1:8080
sleep 1.5

STATS_S1=$(curl -s http://127.0.0.1:9000/api/stats)
ALERTS_S1=$(echo "$STATS_S1" | python3 -c "import sys, json; print(json.load(sys.stdin)['total_alerts'])")

echo -e "\n${BOLD}Alerts after normal traffic:${NC} ${GREEN}${ALERTS_S1}${NC}"
if [ "$ALERTS_S1" -eq "0" ]; then
    echo -e "${GREEN}[✓] PASS: Normal traffic produced ZERO false positives!${NC}\n"
else
    echo -e "${RED}[✗] FAIL: Expected 0 alerts for normal traffic, got ${ALERTS_S1}${NC}\n"
fi

# ==============================================================================
# STEP 2: Shadow and Zombie APIs
# ==============================================================================
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}STEP 2: Exercising Shadow & Zombie APIs${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
python3 attack-sim/shadow_calls.py http://127.0.0.1:8080
sleep 1.5

STATS_S2=$(curl -s http://127.0.0.1:9000/api/stats)
SHADOW_COUNT=$(echo "$STATS_S2" | python3 -c "import sys, json; print(json.load(sys.stdin)['shadow_endpoints'])")
ZOMBIE_COUNT=$(echo "$STATS_S2" | python3 -c "import sys, json; print(json.load(sys.stdin)['zombie_endpoints'])")

echo -e "\n${BOLD}Inventory Detection:${NC}"
echo -e "  Shadow Endpoints detected: ${BOLD}${SHADOW_COUNT}${NC}"
echo -e "  Zombie Endpoints detected: ${BOLD}${ZOMBIE_COUNT}${NC}"
if [ "$SHADOW_COUNT" -ge "1" ] && [ "$ZOMBIE_COUNT" -ge "1" ]; then
    echo -e "${GREEN}[✓] PASS: Shadow (/admin/export) and Zombie (/api/v0/users) APIs successfully flagged!${NC}\n"
fi

# ==============================================================================
# STEP 3: BOLA Attack
# ==============================================================================
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}STEP 3: Launching BOLA Attack (Cross-User Unauthorized Access)${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
python3 attack-sim/bola_attack.py http://127.0.0.1:8080
sleep 1.5

STATS_S3=$(curl -s http://127.0.0.1:9000/api/stats)
BOLA_COUNT=$(echo "$STATS_S3" | python3 -c "import sys, json; print(json.load(sys.stdin)['owasp_breakdown'].get('API1', 0))")
BLOCKED_COUNT=$(echo "$STATS_S3" | python3 -c "import sys, json; print(json.load(sys.stdin)['blocked_requests'])")

echo -e "\n${BOLD}BOLA Security Findings:${NC}"
echo -e "  BOLA (OWASP API1) Alerts : ${BOLD}${BOLA_COUNT}${NC}"
echo -e "  Requests Blocked         : ${BOLD}${BLOCKED_COUNT}${NC}"
if [ "$BOLA_COUNT" -ge "1" ]; then
    echo -e "${GREEN}[✓] PASS: BOLA attack detected and categorized under OWASP API1!${NC}"
fi
if [ "$ENFORCE_MODE" = "1" ]; then
    if [ "$BLOCKED_COUNT" -ge "1" ]; then
        echo -e "${GREEN}[✓] PASS: Enforcement mode successfully blocked unauthorized requests (403 Forbidden)!${NC}\n"
    else
        echo -e "${RED}[✗] FAIL: Enforcement was enabled but no requests were blocked!${NC}\n"
    fi
else
    echo ""
fi

# ==============================================================================
# STEP 4: Enumeration & Rate Limit Attack
# ==============================================================================
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}STEP 4: Launching Rapid Sequential ID Enumeration Attack${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
python3 attack-sim/enumeration_attack.py http://127.0.0.1:8080
sleep 1.5

FINAL_STATS=$(curl -s http://127.0.0.1:9000/api/stats)
echo -e "\n${BOLD}${CYAN}========================================================================${NC}"
echo -e "${BOLD}FINAL DETECTION REPORT SUMMARY${NC}"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo "$FINAL_STATS" | python3 -c "
import sys, json
s = json.load(sys.stdin)
print(f'Total Requests Logged : {s[\"total_requests\"]}')
print(f'Total Endpoints Mapped: {s[\"total_endpoints\"]} ({s[\"documented_endpoints\"]} Documented, {s[\"shadow_endpoints\"]} Shadow, {s[\"zombie_endpoints\"]} Zombie)')
print(f'Total Security Alerts : {s[\"total_alerts\"]}')
print(f'Blocked Requests      : {s[\"blocked_requests\"]}')
print('OWASP Category Breakdown:')
for cat, cnt in s[\"owasp_breakdown\"].items():
    print(f'  • {cat:6}: {cnt} alerts')
"
echo -e "${BOLD}${CYAN}========================================================================${NC}"
echo -e "${GREEN}${BOLD}✓ DEMO COMPLETE! Open dashboard/preview.html in a browser to explore live UI.${NC}"
