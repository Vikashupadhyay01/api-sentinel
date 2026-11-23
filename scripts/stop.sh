#!/usr/bin/env bash
# ==============================================================================
# API-Sentinel: Shutdown Script (Linux / macOS)
#
# Frees all ports used by API-Sentinel (8000, 9000, 8080, 5173).
# ==============================================================================

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${CYAN}[*] Stopping API-Sentinel stack & freeing ports (8000, 9000, 8080, 5173)...${NC}"

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

echo -e "${GREEN}[✓] Ports freed and services stopped successfully.${NC}"

