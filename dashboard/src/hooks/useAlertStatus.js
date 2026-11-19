import { useState, useCallback } from 'react';
const LS_KEY = 'sentinel-alert-status';
function load() { try { return JSON.parse(localStorage.getItem(LS_KEY) || '{}'); } catch { return {}; } }
export function useAlertStatus() {
  const [statuses, setStatuses] = useState(load);
  const setStatus = useCallback((alertId, status) => {
    setStatuses(prev => {
      const next = { ...prev, [alertId]: status };
      try { localStorage.setItem(LS_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
  }, []);
  const getStatus = useCallback((alertId) => statuses[alertId] || 'new', [statuses]);
  return { statuses, setStatus, getStatus };
}
