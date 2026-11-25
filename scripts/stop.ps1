# ==============================================================================
# API-Sentinel: Shutdown Script (Windows PowerShell)
#
# Frees all ports used by API-Sentinel (8000, 9000, 8080, 5173).
# ==============================================================================

Write-Host "[*] Stopping API-Sentinel stack & freeing ports (8000, 9000, 8080, 5173)..." -ForegroundColor Cyan

$ports = @(8000, 9000, 8080, 5173)
foreach ($port in $ports) {
    try {
        $connections = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
        if ($connections) {
            $connections | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
                if ($_ -gt 0) {
                    Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {}
}

Write-Host "[✓] Ports freed and services stopped successfully." -ForegroundColor Green

