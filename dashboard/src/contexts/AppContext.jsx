import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react';
import { api } from '../lib/api';
import { useLocalStorage } from '../hooks/useLocalStorage';
import { usePolling } from '../hooks/usePolling';
import { useAlertStatus } from '../hooks/useAlertStatus';

const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

const DEFAULT_STATS = {
  mode: 'passive', total_requests: 0, total_endpoints: 0, documented_endpoints: 0,
  shadow_endpoints: 0, zombie_endpoints: 0, total_alerts: 0, blocked_requests: 0,
  owasp_breakdown: {}, risk_score: 0, risk_level: 'LOW', risk_color: '#10b981',
  risk_breakdown: {}, top_users: []
};

export function AppProvider({ children }) {
  const [theme, setTheme] = useLocalStorage('sentinel-theme', 'light');
  const [refreshInterval, setRefreshInterval] = useLocalStorage('sentinel-interval', 2000);
  const [livePolling, setLivePolling] = useLocalStorage('sentinel-live', true);
  const [dateRange, setDateRange] = useLocalStorage('sentinel-range', '15m');
  const [activeTab, setActiveTab] = useState('overview');
  const [stats, setStats] = useState(DEFAULT_STATS);
  const [endpoints, setEndpoints] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [blockedRequests, setBlockedRequests] = useState([]);
  const [timelineBuckets, setTimelineBuckets] = useState([]);
  const [topUsers, setTopUsers] = useState([]);
  const [connected, setConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [currentMode, setCurrentMode] = useState('passive');
  const [toasts, setToasts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const knownAlertIdsRef = useRef(new Set());
  const { statuses: alertStatuses, setStatus: setAlertStatus, getStatus: getAlertStatus } = useAlertStatus();

  // Apply theme to document
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  const addToast = useCallback((message, type = 'info', alertObj = null) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev.slice(-3), { id, message, type, alertObj }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4500);
  }, []);

  const removeToast = useCallback((id) => setToasts(prev => prev.filter(t => t.id !== id)), []);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, endpointsRes, alertsRes, blockedRes, timelineRes, topUsersRes] = await Promise.all([
        api.stats(), api.endpoints(), api.alerts(), api.blocked(), api.timeline(), api.topUsers()
      ]);
      if (statsRes.mode) setCurrentMode(statsRes.mode);
      setStats(statsRes);
      setEndpoints(endpointsRes);
      if (knownAlertIdsRef.current.size > 0 && alertsRes.length > 0) {
        const newFindings = alertsRes.filter(a => !knownAlertIdsRef.current.has(a.id));
        if (newFindings.length > 0) {
          if (activeTab !== 'alerts') setUnreadCount(prev => prev + newFindings.length);
          const highThreat = newFindings.find(a => a.severity === 'HIGH' || a.severity === 'CRITICAL');
          if (highThreat) addToast(`🚨 ${highThreat.type}: ${highThreat.explanation?.slice(0, 65)}…`, 'danger', highThreat);
        }
      }
      alertsRes.forEach(a => knownAlertIdsRef.current.add(a.id));
      setAlerts(alertsRes);
      setBlockedRequests(blockedRes || []);
      setTimelineBuckets(timelineRes.buckets || []);
      setTopUsers(topUsersRes || []);
      setConnected(true);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch {
      setConnected(false);
    }
  }, [activeTab, addToast]);

  useEffect(() => { if (activeTab === 'alerts') setUnreadCount(0); }, [activeTab]);

  usePolling(fetchData, refreshInterval, livePolling);

  const toggleMode = useCallback(async () => {
    const nextMode = currentMode === 'enforce' ? 'passive' : 'enforce';
    try {
      const res = await api.setMode(nextMode);
      if (res.mode) {
        setCurrentMode(res.mode);
        addToast(`Switched to ${res.mode === 'enforce' ? 'ENFORCEMENT (403)' : 'PASSIVE AUDIT'} mode`, res.mode === 'enforce' ? 'warning' : 'success');
      }
    } catch { addToast('Failed to toggle mode', 'danger'); }
  }, [currentMode, addToast]);

  const triggerAttack = useCallback(async (type) => {
    try {
      addToast(`Launching ${type.toUpperCase()} attack…`, 'warning');
      const res = await api.attack(type);
      if (res.status === 'completed') { addToast(`Simulation done (${res.probes_sent} probes)`, 'success'); fetchData(); }
      else if (res.error) addToast(`Error: ${res.error}`, 'danger');
    } catch { addToast('Attack request failed', 'danger'); }
  }, [addToast, fetchData]);

  const triggerReset = useCallback(async () => {
    if (!window.confirm('Reset all detection state, inventory, and event logs?')) return;
    try {
      const res = await api.reset();
      if (res.status === 'ok') {
        knownAlertIdsRef.current.clear();
        setUnreadCount(0);
        addToast('State reset cleanly.', 'success');
        fetchData();
      }
    } catch { addToast('Reset failed', 'danger'); }
  }, [addToast, fetchData]);

  return (
    <AppContext.Provider value={{
      theme, setTheme,
      refreshInterval, setRefreshInterval,
      livePolling, setLivePolling,
      dateRange, setDateRange,
      activeTab, setActiveTab,
      stats, endpoints, alerts, blockedRequests, timelineBuckets, topUsers,
      connected, lastUpdated, currentMode,
      toasts, addToast, removeToast,
      unreadCount, setUnreadCount,
      alertStatuses, setAlertStatus, getAlertStatus,
      toggleMode, triggerAttack, triggerReset,
      fetchData,
    }}>
      {children}
    </AppContext.Provider>
  );
}
