export const fmt = {
  time: (ts) => ts ? new Date(ts).toLocaleTimeString() : '—',
  date: (ts) => ts ? new Date(ts).toLocaleDateString() : '—',
  pct: (n, d) => d > 0 ? Math.round((n / d) * 100) : 0,
  clamp: (v, min, max) => Math.min(max, Math.max(min, v)),
  severity: (s) => ({ HIGH: { color: '#ef4444', icon: '🔴', label: 'HIGH' }, MEDIUM: { color: '#f59e0b', icon: '🟡', label: 'MED' }, LOW: { color: '#10b981', icon: '🟢', label: 'LOW' }, CRITICAL: { color: '#dc2626', icon: '💀', label: 'CRIT' } }[s] || { color: '#6b7280', icon: '⚪', label: s }),
  owaspColor: (code) => ({ API1: '#ef4444', API4: '#f59e0b', API6: '#a855f7', API9: '#0eb3d8' }[code] || '#6b7280'),
  owaspLabel: (code) => ({ API1: 'BOLA (API1)', API4: 'Rate Limit (API4)', API6: 'ID Enumeration (API6)', API9: 'Inventory (API9)' }[code] || code),
};
