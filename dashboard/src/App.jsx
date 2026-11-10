import React, { useState, useEffect, useMemo, useRef } from 'react';

const API_BASE = 'http://localhost:9000/api';

const OWASP_CATEGORIES = [
  { code: 'API1', name: 'Broken Object Level Auth (BOLA)', desc: 'Unauthorized cross-user object access', color: 'var(--danger)' },
  { code: 'API4', name: 'Unrestricted Resource Consumption', desc: 'Rate limit exceedance', color: 'var(--warning)' },
  { code: 'API6', name: 'Unrestricted Business Flows', desc: 'Sequential ID enumeration / scraping bots', color: 'var(--purple)' },
  { code: 'API9', name: 'Improper Inventory Management', desc: 'Shadow and Zombie unmanaged APIs', color: 'var(--info)' },
];

export default function App() {
  const [stats, setStats] = useState({
    mode: 'passive',
    total_requests: 0,
    total_endpoints: 0,
    documented_endpoints: 0,
    shadow_endpoints: 0,
    zombie_endpoints: 0,
    total_alerts: 0,
    blocked_requests: 0,
    owasp_breakdown: {},
    risk_score: 0,
    risk_level: 'LOW',
    risk_color: '#10b981',
    risk_breakdown: {},
    top_users: []
  });
  const [endpoints, setEndpoints] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [blockedRequests, setBlockedRequests] = useState([]);
  const [timelineBuckets, setTimelineBuckets] = useState([]);
  const [connected, setConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [activeTab, setActiveTab] = useState('overview'); // overview, endpoints, alerts, blocked
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showAttackMenu, setShowAttackMenu] = useState(false);

  // Runtime Mode State
  const [currentMode, setCurrentMode] = useState('passive');

  // Toasts & Unread state
  const [toasts, setToasts] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const knownAlertIdsRef = useRef(new Set());

  // Drawer state
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Filters: Endpoints
  const [endpointClass, setEndpointClass] = useState('ALL');
  const [endpointMethod, setEndpointMethod] = useState('ALL');
  const [endpointSearch, setEndpointSearch] = useState('');

  // Filters: Alerts
  const [alertSeverity, setAlertSeverity] = useState('ALL');
  const [alertOwasp, setAlertOwasp] = useState('ALL');
  const [alertUser, setAlertUser] = useState('ALL');
  const [alertTimeRange, setAlertTimeRange] = useState('ALL'); // ALL, 1H, 5M
  const [alertSearch, setAlertSearch] = useState('');

  // Filters: Blocked
  const [blockedUser, setBlockedUser] = useState('ALL');
  const [blockedOwasp, setBlockedOwasp] = useState('ALL');
  const [blockedTimeRange, setBlockedTimeRange] = useState('ALL');
  const [blockedSearch, setBlockedSearch] = useState('');

  // Timeline tooltip
  const [hoveredBucket, setHoveredBucket] = useState(null);

  // Toast dispatch helper
  const addToast = (message, type = 'info', alertObj = null) => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev.slice(-3), { id, message, type, alertObj }]);
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id));
    }, 4500);
  };

  const removeToast = (id) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  };

  const fetchData = async () => {
    try {
      const [statsRes, endpointsRes, alertsRes, blockedRes, timelineRes] = await Promise.all([
        fetch(`${API_BASE}/stats`).then(r => r.json()),
        fetch(`${API_BASE}/endpoints`).then(r => r.json()),
        fetch(`${API_BASE}/alerts`).then(r => r.json()),
        fetch(`${API_BASE}/blocked`).then(r => r.json()).catch(() => []),
        fetch(`${API_BASE}/timeline`).then(r => r.json()).catch(() => ({ buckets: [] }))
      ]);

      if (statsRes.mode) {
        setCurrentMode(statsRes.mode);
      }
      setStats(statsRes);
      setEndpoints(endpointsRes);

      // Check for newly arrived alerts to trigger toast notifications
      if (knownAlertIdsRef.current.size > 0 && alertsRes.length > 0) {
        const newFindings = alertsRes.filter(a => !knownAlertIdsRef.current.has(a.id));
        if (newFindings.length > 0) {
          if (activeTab !== 'alerts') {
            setUnreadCount(prev => prev + newFindings.length);
          }
          // Notify on high severity
          const highThreat = newFindings.find(a => a.severity === 'HIGH' || a.severity === 'CRITICAL');
          if (highThreat) {
            addToast(`🚨 ${highThreat.type} Alert: ${highThreat.explanation.slice(0, 65)}…`, 'danger', highThreat);
          }
        }
      }
      alertsRes.forEach(a => knownAlertIdsRef.current.add(a.id));

      setAlerts(alertsRes);
      setBlockedRequests(blockedRes || []);
      setTimelineBuckets(timelineRes.buckets || []);
      setConnected(true);
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      setConnected(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, [activeTab]);

  // Clear unread counter when opening Alerts tab
  useEffect(() => {
    if (activeTab === 'alerts') {
      setUnreadCount(0);
    }
  }, [activeTab]);

  // Listen for Escape key to close drawer
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') setSelectedAlert(null);
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Mode Toggle
  const toggleMode = async () => {
    const nextMode = currentMode === 'enforce' ? 'passive' : 'enforce';
    try {
      const res = await fetch(`${API_BASE}/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: nextMode })
      }).then(r => r.json());

      if (res.mode) {
        setCurrentMode(res.mode);
        addToast(
          `API-Sentinel switched to ${res.mode === 'enforce' ? 'ENFORCEMENT (403 BLOCKING)' : 'PASSIVE AUDIT'} mode`,
          res.mode === 'enforce' ? 'warning' : 'success'
        );
      }
    } catch (e) {
      addToast('Failed to toggle detection mode', 'danger');
    }
  };

  // Demo Attack Simulation
  const triggerAttack = async (type) => {
    setShowAttackMenu(false);
    try {
      addToast(`Launching ${type.toUpperCase()} traffic against 127.0.0.1:8080…`, 'warning');
      const res = await fetch(`${API_BASE}/demo/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type })
      }).then(r => r.json());

      if (res.status === 'completed') {
        addToast(`Simulation completed (${res.probes_sent} probes sent)`, 'success');
        fetchData();
      } else if (res.error) {
        addToast(`Simulation error: ${res.error}`, 'danger');
      }
    } catch (e) {
      addToast('Attack simulation request failed', 'danger');
    }
  };

  // Demo Reset State
  const triggerReset = async () => {
    if (!window.confirm('Reset all detection state, inventory, and event logs?')) return;
    try {
      const res = await fetch(`${API_BASE}/demo/reset`, { method: 'POST' }).then(r => r.json());
      if (res.status === 'ok') {
        knownAlertIdsRef.current.clear();
        setUnreadCount(0);
        addToast('State and event log reset cleanly.', 'success');
        fetchData();
      }
    } catch (e) {
      addToast('Failed to reset state', 'danger');
    }
  };

  // Filtered Endpoints
  const filteredEndpoints = useMemo(() => {
    return endpoints.filter(ep => {
      const matchesClass = endpointClass === 'ALL' || ep.classification.toUpperCase() === endpointClass;
      const matchesMethod = endpointMethod === 'ALL' || ep.method.toUpperCase() === endpointMethod;
      const q = endpointSearch.toLowerCase().trim();
      const matchesSearch = !q || ep.norm_path.toLowerCase().includes(q) || ep.method.toLowerCase().includes(q);
      return matchesClass && matchesMethod && matchesSearch;
    });
  }, [endpoints, endpointClass, endpointMethod, endpointSearch]);

  // Unique users list for dropdowns
  const detectedUsers = useMemo(() => {
    const set = new Set();
    alerts.forEach(a => a.user && set.add(a.user));
    blockedRequests.forEach(b => b.user && set.add(b.user));
    return Array.from(set).sort();
  }, [alerts, blockedRequests]);

  // Time filter helper
  const filterByTime = (ts, range) => {
    if (range === 'ALL' || !ts) return true;
    const itemEpoch = new Date(ts).getTime();
    const now = Date.now();
    const diffSec = (now - itemEpoch) / 1000;
    if (range === '5M') return diffSec <= 300;
    if (range === '1H') return diffSec <= 3600;
    return true;
  };

  // Filtered Alerts
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const matchesSev = alertSeverity === 'ALL' || a.severity.toUpperCase() === alertSeverity;
      const matchesOwasp = alertOwasp === 'ALL' || a.owasp_category.toUpperCase() === alertOwasp;
      const matchesUser = alertUser === 'ALL' || (a.user || 'anonymous') === alertUser;
      const matchesTime = filterByTime(a.ts, alertTimeRange);
      const q = alertSearch.toLowerCase().trim();
      const matchesSearch = !q ||
        (a.endpoint && a.endpoint.toLowerCase().includes(q)) ||
        (a.raw_path && a.raw_path.toLowerCase().includes(q)) ||
        (a.explanation && a.explanation.toLowerCase().includes(q)) ||
        (a.user && a.user.toLowerCase().includes(q)) ||
        (a.object_id && String(a.object_id).includes(q));
      return matchesSev && matchesOwasp && matchesUser && matchesTime && matchesSearch;
    });
  }, [alerts, alertSeverity, alertOwasp, alertUser, alertTimeRange, alertSearch]);

  // Filtered Blocked Requests
  const filteredBlocked = useMemo(() => {
    return blockedRequests.filter(b => {
      const matchesUser = blockedUser === 'ALL' || (b.user || 'anonymous') === blockedUser;
      const matchesOwasp = blockedOwasp === 'ALL' || (b.owasp_category || 'API1').toUpperCase() === blockedOwasp;
      const matchesTime = filterByTime(b.time || b.ts, blockedTimeRange);
      const q = blockedSearch.toLowerCase().trim();
      const matchesSearch = !q ||
        (b.path && b.path.toLowerCase().includes(q)) ||
        (b.reason && b.reason.toLowerCase().includes(q)) ||
        (b.user && b.user.toLowerCase().includes(q)) ||
        (b.object_id && String(b.object_id).includes(q));
      return matchesUser && matchesOwasp && matchesTime && matchesSearch;
    });
  }, [blockedRequests, blockedUser, blockedOwasp, blockedTimeRange, blockedSearch]);

  const maxAlertsCount = Math.max(1, ...Object.values(stats.owasp_breakdown || {}));

  // Timeline max bucket height
  const maxBucketTotal = useMemo(() => {
    return Math.max(1, ...timelineBuckets.map(b => (b.requests || 0) + (b.alerts || 0) + (b.blocked || 0)));
  }, [timelineBuckets]);

  // Risk Gauge Math (semicircle arc: circumference = pi * r = 3.14159 * 75 ~= 235.6)
  const radius = 75;
  const circumference = Math.PI * radius;
  const riskScore = Math.min(100, Math.max(0, stats.risk_score || 0));
  const strokeDashoffset = circumference - (circumference * riskScore) / 100;

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '1.5rem 2rem' }}>
      
      {/* Toast Notification Container */}
      <div className="toast-container">
        {toasts.map(t => (
          <div key={t.id} className={`toast ${t.type === 'danger' ? '' : t.type === 'warning' ? 'toast-warning' : 'toast-success'}`}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', fontWeight: 700, color: '#fff' }}>
                <span>{t.type === 'danger' ? '🚨' : t.type === 'warning' ? '⚠️' : '✅'}</span>
                <span>Notification</span>
              </div>
              <button
                onClick={() => removeToast(t.id)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '0.9rem' }}
              >
                ✕
              </button>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-main)', lineHeight: 1.35 }}>
              {t.message}
            </p>
            {t.alertObj && (
              <button
                onClick={() => {
                  setSelectedAlert(t.alertObj);
                  removeToast(t.id);
                }}
                style={{
                  alignSelf: 'flex-start',
                  background: 'rgba(99,102,241,0.15)',
                  border: '1px solid rgba(99,102,241,0.3)',
                  color: '#818cf8',
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  fontSize: '0.72rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  marginTop: '0.2rem'
                }}
              >
                Inspect Details →
              </button>
            )}
          </div>
        ))}
      </div>

      {/* Top Header */}
      <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem', borderBottom: '1px solid var(--border)', paddingBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <div style={{ background: 'linear-gradient(135deg, #4f46e5, #06b6d4)', width: '42px', height: '42px', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 20px var(--accent-glow)' }}>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 800, letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              API-SENTINEL
              <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'var(--border)', color: 'var(--text-muted)', fontWeight: 600 }}>v1.1 LAB</span>
            </h1>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>Runtime BOLA & Shadow API Detection Engine</p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.8rem', flexWrap: 'wrap' }}>
          
          {/* Runtime Mode Toggle Pill */}
          <button
            onClick={toggleMode}
            className={`mode-toggle-btn ${currentMode === 'enforce' ? 'mode-enforce' : 'mode-passive'}`}
            title="Click to toggle between Passive Auditing and Active Enforcement Mode"
          >
            <span>{currentMode === 'enforce' ? '🛡️' : '👁️'}</span>
            <span>MODE: {currentMode === 'enforce' ? 'ENFORCEMENT (403)' : 'PASSIVE (AUDIT)'}</span>
            <span style={{ fontSize: '0.65rem', opacity: 0.7, border: '1px solid currentColor', borderRadius: '3px', padding: '1px 3px' }}>TOGGLE</span>
          </button>

          {/* Interactive Demo Simulation Dropdown */}
          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setShowAttackMenu(!showAttackMenu)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                color: 'var(--text-main)',
                padding: '0.42rem 0.8rem',
                borderRadius: '8px',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              <span>⚡</span> Demo Attacks ▾
            </button>
            {showAttackMenu && (
              <div
                style={{
                  position: 'absolute',
                  right: 0,
                  top: '115%',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                  zIndex: 50,
                  minWidth: '220px',
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column'
                }}
                onMouseLeave={() => setShowAttackMenu(false)}
              >
                <button
                  onClick={() => triggerAttack('bola')}
                  style={{ background: 'transparent', border: 'none', borderBottom: '1px solid var(--border)', padding: '0.6rem 0.9rem', color: 'var(--danger)', fontSize: '0.78rem', textAlign: 'left', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  <span>🎯</span> BOLA Cross-User Attack
                </button>
                <button
                  onClick={() => triggerAttack('enumeration')}
                  style={{ background: 'transparent', border: 'none', borderBottom: '1px solid var(--border)', padding: '0.6rem 0.9rem', color: 'var(--purple)', fontSize: '0.78rem', textAlign: 'left', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  <span>🤖</span> Rapid ID Enumeration Scan
                </button>
                <button
                  onClick={() => triggerAttack('shadow')}
                  style={{ background: 'transparent', border: 'none', borderBottom: '1px solid var(--border)', padding: '0.6rem 0.9rem', color: 'var(--info)', fontSize: '0.78rem', textAlign: 'left', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  <span>👻</span> Shadow & Zombie Calls
                </button>
                <button
                  onClick={() => triggerAttack('normal')}
                  style={{ background: 'transparent', border: 'none', borderBottom: '1px solid var(--border)', padding: '0.6rem 0.9rem', color: 'var(--success)', fontSize: '0.78rem', textAlign: 'left', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
                >
                  <span>✅</span> Benign Normal Traffic
                </button>
                <button
                  onClick={() => triggerAttack('all')}
                  style={{ background: 'transparent', border: 'none', padding: '0.6rem 0.9rem', color: '#fff', fontSize: '0.78rem', textAlign: 'left', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 700 }}
                >
                  <span>💥</span> Run Full Attack Suite
                </button>
              </div>
            )}
          </div>

          {/* Reset Demo Button */}
          <button
            onClick={triggerReset}
            title="Reset detection state, clear memory, and truncate data/events.jsonl"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              color: 'var(--text-muted)',
              padding: '0.42rem 0.75rem',
              borderRadius: '8px',
              fontSize: '0.8rem',
              cursor: 'pointer'
            }}
          >
            <span>🔄</span> Reset
          </button>

          {/* Export Action Buttons */}
          <a
            href={`${API_BASE}/report.pdf`}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              background: 'linear-gradient(135deg, #4f46e5, #06b6d4)',
              color: '#ffffff',
              textDecoration: 'none',
              padding: '0.42rem 0.85rem',
              borderRadius: '8px',
              fontSize: '0.8rem',
              fontWeight: 700,
              boxShadow: '0 0 14px var(--accent-glow)',
              transition: 'opacity 0.15s ease'
            }}
          >
            <span>📄</span> Export PDF
          </a>

          <div style={{ position: 'relative' }}>
            <button
              onClick={() => setShowExportMenu(!showExportMenu)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                color: 'var(--text-main)',
                padding: '0.42rem 0.8rem',
                borderRadius: '8px',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              <span>💾</span> Export ▾
            </button>
            {showExportMenu && (
              <div
                style={{
                  position: 'absolute',
                  right: 0,
                  top: '115%',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                  zIndex: 50,
                  minWidth: '200px',
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column'
                }}
                onMouseLeave={() => setShowExportMenu(false)}
              >
                <a
                  href={`${API_BASE}/export/alerts.csv`}
                  download
                  onClick={() => setShowExportMenu(false)}
                  style={{ padding: '0.6rem 0.9rem', color: 'var(--text-main)', fontSize: '0.78rem', textDecoration: 'none', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <span>🚨</span> Alerts (CSV)
                </a>
                <a
                  href={`${API_BASE}/export/alerts.json`}
                  download
                  onClick={() => setShowExportMenu(false)}
                  style={{ padding: '0.6rem 0.9rem', color: 'var(--text-main)', fontSize: '0.78rem', textDecoration: 'none', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <span>📋</span> Alerts (JSON)
                </a>
                <a
                  href={`${API_BASE}/export/blocked.csv`}
                  download
                  onClick={() => setShowExportMenu(false)}
                  style={{ padding: '0.6rem 0.9rem', color: 'var(--text-main)', fontSize: '0.78rem', textDecoration: 'none', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <span>🛡️</span> Blocked Requests (CSV)
                </a>
                <a
                  href={`${API_BASE}/export/openapi.yaml`}
                  download
                  onClick={() => setShowExportMenu(false)}
                  style={{ padding: '0.6rem 0.9rem', color: 'var(--text-main)', fontSize: '0.78rem', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                >
                  <span>🗺️</span> Discovered OpenAPI (YAML)
                </a>
              </div>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--bg-surface)', padding: '0.4rem 0.8rem', borderRadius: '8px', border: '1px solid var(--border)', fontSize: '0.8rem' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: connected ? 'var(--success)' : 'var(--danger)', boxShadow: connected ? '0 0 8px var(--success)' : 'none' }}></span>
            <span style={{ color: connected ? 'var(--text-main)' : 'var(--danger)', fontWeight: 600 }}>
              {connected ? 'ENGINE ACTIVE' : 'OFFLINE'}
            </span>
            {lastUpdated && <span style={{ color: 'var(--text-dim)', marginLeft: '0.4rem' }}>• {lastUpdated}</span>}
          </div>

          <div style={{ display: 'flex', background: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)', padding: '3px' }}>
            {['overview', 'endpoints', 'alerts', 'blocked'].map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                style={{
                  background: activeTab === tab ? 'var(--bg-card)' : 'transparent',
                  color: activeTab === tab ? 'var(--text-main)' : 'var(--text-muted)',
                  border: 'none',
                  padding: '0.4rem 0.9rem',
                  borderRadius: '6px',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  textTransform: 'capitalize',
                  transition: 'all 0.15s ease',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.3rem'
                }}
              >
                <span>{tab}</span>
                {tab === 'alerts' && unreadCount > 0 && (
                  <span style={{ background: 'var(--danger)', color: '#fff', borderRadius: '9999px', padding: '0.1rem 0.4rem', fontSize: '0.7rem', fontWeight: 800 }}>
                    {unreadCount} new
                  </span>
                )}
                {tab === 'alerts' && unreadCount === 0 && stats.total_alerts > 0 && (
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>({stats.total_alerts})</span>
                )}
                {tab === 'blocked' && stats.blocked_requests > 0 && (
                  <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>({stats.blocked_requests})</span>
                )}
              </button>
            ))}
          </div>
        </div>
      </header>

      {!connected && (
        <div style={{ background: 'var(--danger-bg)', border: '1px solid var(--danger)', borderRadius: '8px', padding: '0.9rem 1.25rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.8rem', color: '#fca5a5', fontSize: '0.88rem' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
          <div>
            <strong>Cannot connect to Detection API on port 9000.</strong> Ensure <code className="mono">python backend/api.py</code> is running. Retrying every 2s…
          </div>
        </div>
      )}

      {/* Primary Stat Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem', marginBottom: '2rem' }}>
        <div className="stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)' }}>TOTAL HTTP REQUESTS</span>
            <span style={{ color: 'var(--accent)' }}>📊</span>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, marginTop: '0.5rem', letterSpacing: '-0.02em' }}>
            {stats.total_requests}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.3rem' }}>
            Captured by :8080 proxy
          </div>
        </div>

        <div className="stat-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-muted)' }}>DISCOVERED ENDPOINTS</span>
            <span style={{ color: 'var(--info)' }}>🔍</span>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, marginTop: '0.5rem', letterSpacing: '-0.02em' }}>
            {stats.total_endpoints}
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.3rem', fontSize: '0.72rem' }}>
            <span style={{ color: 'var(--success)' }}>{stats.documented_endpoints} Doc</span>
            <span style={{ color: 'var(--text-dim)' }}>•</span>
            <span style={{ color: 'var(--purple)' }}>{stats.shadow_endpoints} Shadow</span>
            <span style={{ color: 'var(--text-dim)' }}>•</span>
            <span style={{ color: 'var(--danger)' }}>{stats.zombie_endpoints} Zombie</span>
          </div>
        </div>

        <div className="stat-card alert-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--danger)' }}>SECURITY ALERTS</span>
            <span style={{ color: 'var(--danger)' }}>🚨</span>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, marginTop: '0.5rem', color: 'var(--danger)', letterSpacing: '-0.02em' }}>
            {stats.total_alerts}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.3rem' }}>
            OWASP API Security Violations
          </div>
        </div>

        <div className="stat-card blocked-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--warning)' }}>BLOCKED REQUESTS</span>
            <span style={{ color: 'var(--warning)' }}>🛡️</span>
          </div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, marginTop: '0.5rem', color: 'var(--warning)', letterSpacing: '-0.02em' }}>
            {stats.blocked_requests}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.3rem' }}>
            Mode: {currentMode === 'enforce' ? 'Active Blocking (403)' : 'Passive (Not Blocking)'}
          </div>
        </div>
      </div>

      {/* OVERVIEW TAB CONTENT */}
      {activeTab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', marginBottom: '2rem' }}>
          
          {/* Top Row: Risk Posture Gauge + OWASP Breakdown */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(320px, 1fr) 2fr', gap: '1.5rem', alignItems: 'stretch' }}>
            
            {/* Risk Posture Gauge Card */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', textAlign: 'center', position: 'relative' }}>
              <div style={{ width: '100%', display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span>🎯</span> Security Risk Score
                </h2>
                <span className="badge" style={{ background: `${stats.risk_color}22`, color: stats.risk_color, borderColor: `${stats.risk_color}55` }}>
                  {stats.risk_level} RISK
                </span>
              </div>

              {/* Semicircle SVG Gauge */}
              <div style={{ position: 'relative', width: '220px', height: '125px', margin: '0.5rem auto 0' }}>
                <svg width="220" height="125" viewBox="0 0 220 125" style={{ overflow: 'visible' }}>
                  {/* Background Track */}
                  <path
                    d="M 35 110 A 75 75 0 0 1 185 110"
                    fill="none"
                    stroke="#1e293b"
                    strokeWidth="16"
                    strokeLinecap="round"
                  />
                  {/* Value Colored Arc */}
                  <path
                    d="M 35 110 A 75 75 0 0 1 185 110"
                    fill="none"
                    stroke={stats.risk_color || '#10b981'}
                    strokeWidth="16"
                    strokeLinecap="round"
                    strokeDasharray={circumference}
                    strokeDashoffset={strokeDashoffset}
                    style={{ transition: 'stroke-dashoffset 0.8s ease, stroke 0.5s ease' }}
                  />
                </svg>
                {/* Score Number in Center */}
                <div style={{ position: 'absolute', bottom: '0', left: '0', right: '0', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <span style={{ fontSize: '2.4rem', fontWeight: 800, letterSpacing: '-0.03em', color: stats.risk_color }}>
                    {riskScore}
                  </span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '-4px' }}>out of 100</span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.8rem', marginTop: '1.25rem', fontSize: '0.75rem', flexWrap: 'wrap', justifyContent: 'center' }}>
                <div style={{ background: 'var(--bg-primary)', padding: '0.3rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>High: </span>
                  <strong style={{ color: 'var(--danger)' }}>{stats.risk_breakdown?.severity_counts?.HIGH || 0}</strong>
                </div>
                <div style={{ background: 'var(--bg-primary)', padding: '0.3rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Med: </span>
                  <strong style={{ color: 'var(--warning)' }}>{stats.risk_breakdown?.severity_counts?.MEDIUM || 0}</strong>
                </div>
                <div style={{ background: 'var(--bg-primary)', padding: '0.3rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Shadow: </span>
                  <strong style={{ color: 'var(--purple)' }}>{stats.shadow_endpoints || 0}</strong>
                </div>
                <div style={{ background: 'var(--bg-primary)', padding: '0.3rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Zombie: </span>
                  <strong style={{ color: 'var(--danger)' }}>{stats.zombie_endpoints || 0}</strong>
                </div>
              </div>
            </div>

            {/* OWASP Top 10 Breakdown Bar Chart */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>🛡️</span> OWASP API Security Top 10 Mapping
                </h2>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Live Threat Distribution</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {OWASP_CATEGORIES.map(cat => {
                  const count = stats.owasp_breakdown[cat.code] || 0;
                  const pct = Math.round((count / maxAlertsCount) * 100);

                  return (
                    <div key={cat.code} style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                        <span>
                          <strong style={{ color: cat.color }}>{cat.code}:</strong> {cat.name}
                        </span>
                        <span className="mono" style={{ fontWeight: 700, color: count > 0 ? cat.color : 'var(--text-dim)' }}>
                          {count} {count === 1 ? 'alert' : 'alerts'}
                        </span>
                      </div>
                      <div style={{ height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '4px', overflow: 'hidden' }}>
                        <div style={{
                          height: '100%',
                          width: `${pct}%`,
                          background: cat.color,
                          borderRadius: '4px',
                          transition: 'width 0.4s ease'
                        }}/>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Activity Timeline Chart (15-min requests/alerts, 10s buckets) */}
          <div className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div>
                <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>📈</span> Traffic & Threat Timeline (15 Minutes)
                </h2>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                  Rolling 10-second activity buckets showing requests, alerts, and enforcement blocks.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: '#6366f1' }}></span>
                  <span style={{ color: 'var(--text-muted)' }}>Requests</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: 'var(--warning)' }}></span>
                  <span style={{ color: 'var(--text-muted)' }}>Blocked</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: 'var(--danger)' }}></span>
                  <span style={{ color: 'var(--text-muted)' }}>Alerts</span>
                </div>
              </div>
            </div>

            {/* Timeline Bars Grid */}
            <div style={{ position: 'relative', marginTop: '1rem' }}>
              <div style={{ height: '90px', display: 'flex', alignItems: 'flex-end', gap: '2px', borderBottom: '1px solid var(--border)', paddingBottom: '2px' }}>
                {timelineBuckets.map((bucket, idx) => {
                  const reqH = Math.min(80, Math.round(((bucket.requests || 0) / maxBucketTotal) * 75));
                  const altH = Math.min(80, Math.round(((bucket.alerts || 0) / maxBucketTotal) * 75));
                  const blkH = Math.min(80, Math.round(((bucket.blocked || 0) / maxBucketTotal) * 75));
                  const totalH = Math.max(reqH > 0 || altH > 0 || blkH > 0 ? 4 : 2, reqH + altH + blkH);

                  return (
                    <div
                      key={idx}
                      onMouseEnter={() => setHoveredBucket(bucket)}
                      onMouseLeave={() => setHoveredBucket(null)}
                      style={{
                        flex: 1,
                        height: '100%',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'flex-end',
                        cursor: 'pointer',
                        padding: '0 1px'
                      }}
                    >
                      <div
                        style={{
                          width: '100%',
                          height: `${totalH}px`,
                          borderRadius: '2px 2px 0 0',
                          background: altH > 0 ? 'var(--danger)' : blkH > 0 ? 'var(--warning)' : reqH > 0 ? '#6366f1' : '#1e293b',
                          opacity: hoveredBucket === bucket ? 1 : reqH > 0 || altH > 0 || blkH > 0 ? 0.9 : 0.25,
                          transition: 'all 0.15s ease'
                        }}
                      />
                    </div>
                  );
                })}
              </div>

              {/* Bucket Hover Detail Bar */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                <span>{timelineBuckets[0]?.label || '-15m'}</span>
                {hoveredBucket ? (
                  <span className="mono" style={{ color: 'var(--text-main)', background: 'var(--bg-primary)', padding: '0.2rem 0.6rem', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    ⏱️ <strong>{hoveredBucket.label}</strong>: {hoveredBucket.requests} requests • <span style={{ color: 'var(--danger)' }}>{hoveredBucket.alerts} alerts</span> • <span style={{ color: 'var(--warning)' }}>{hoveredBucket.blocked} blocked</span>
                  </span>
                ) : (
                  <span>Hover over any bar to view 10s slice metrics</span>
                )}
                <span>{timelineBuckets[timelineBuckets.length - 1]?.label || 'Now'}</span>
              </div>
            </div>
          </div>

          {/* Bottom Grid: Top Users Table + Live Alerts Feed */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr', gap: '1.5rem', alignItems: 'start' }}>
            
            {/* Top Threat Actors Card */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>👤</span> Top Users by Threat Score
                </h2>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Ranked by Alerts</span>
              </div>

              {(!stats.top_users || stats.top_users.length === 0) ? (
                <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.82rem' }}>
                  No high-risk user behavior recorded yet.
                </div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                        <th style={{ padding: '0.5rem 0.4rem' }}>USER</th>
                        <th style={{ padding: '0.5rem 0.4rem', textAlign: 'center' }}>ALERTS</th>
                        <th style={{ padding: '0.5rem 0.4rem', textAlign: 'center' }}>BLOCKED</th>
                        <th style={{ padding: '0.5rem 0.4rem' }}>PRIMARY THREAT</th>
                      </tr>
                    </thead>
                    <tbody>
                      {stats.top_users.map((u, i) => (
                        <tr
                          key={u.user || i}
                          onClick={() => {
                            setAlertUser(u.user);
                            setActiveTab('alerts');
                          }}
                          style={{
                            borderBottom: '1px solid rgba(255,255,255,0.03)',
                            cursor: 'pointer',
                            transition: 'background 0.15s'
                          }}
                          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                          onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                        >
                          <td style={{ padding: '0.6rem 0.4rem' }}>
                            <strong style={{ color: 'var(--text-main)' }}>{u.user}</strong>
                          </td>
                          <td style={{ padding: '0.6rem 0.4rem', textAlign: 'center' }}>
                            <span className="badge badge-high" style={{ padding: '0.15rem 0.45rem' }}>{u.alert_count}</span>
                          </td>
                          <td style={{ padding: '0.6rem 0.4rem', textAlign: 'center' }}>
                            {u.blocked_count > 0 ? (
                              <span className="badge badge-medium" style={{ padding: '0.15rem 0.45rem' }}>{u.blocked_count}</span>
                            ) : (
                              <span style={{ color: 'var(--text-dim)' }}>0</span>
                            )}
                          </td>
                          <td style={{ padding: '0.6rem 0.4rem', color: 'var(--text-muted)' }}>
                            <span style={{ color: u.top_threat.includes('BOLA') ? 'var(--danger)' : 'var(--warning)', fontWeight: 600 }}>
                              {u.top_threat}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Live Alerts Feed (Click to inspect in Drawer) */}
            <div className="card" style={{ display: 'flex', flexDirection: 'column', maxHeight: '520px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h2 style={{ fontSize: '1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>⚡</span> Live Alerts Feed
                </h2>
                <span className="animate-pulse" style={{ fontSize: '0.72rem', color: 'var(--danger)', fontWeight: 700 }}>
                  ● REALTIME (CLICK FOR DETAILS)
                </span>
              </div>

              <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.75rem', paddingRight: '0.25rem' }}>
                {alerts.length === 0 ? (
                  <div style={{ padding: '3rem 1rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
                    No security alerts raised.<br/>
                    <span style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Normal traffic generates zero false positives.</span>
                  </div>
                ) : (
                  alerts.slice(0, 15).map(a => {
                    const isHigh = a.severity === 'HIGH' || a.severity === 'CRITICAL';
                    const isMedium = a.severity === 'MEDIUM';
                    const badgeClass = isHigh ? 'badge-high' : isMedium ? 'badge-medium' : 'badge-low';

                    return (
                      <div
                        key={a.id}
                        onClick={() => setSelectedAlert(a)}
                        style={{
                          background: 'var(--bg-primary)',
                          borderLeft: `4px solid ${isHigh ? 'var(--danger)' : isMedium ? 'var(--warning)' : 'var(--info)'}`,
                          borderRadius: '0 8px 8px 0',
                          padding: '0.75rem 1rem',
                          borderTop: '1px solid var(--border)',
                          borderRight: '1px solid var(--border)',
                          borderBottom: '1px solid var(--border)',
                          cursor: 'pointer',
                          transition: 'transform 0.15s ease, background 0.15s ease'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.background = '#131c31';
                          e.currentTarget.style.transform = 'translateX(2px)';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.background = 'var(--bg-primary)';
                          e.currentTarget.style.transform = 'none';
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                          <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                            <span className={`badge ${badgeClass}`}>{a.type}</span>
                            <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)' }}>{a.owasp_category}</span>
                          </div>
                          <span className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-dim)' }}>
                            {a.ts ? new Date(a.ts).toLocaleTimeString() : ''}
                          </span>
                        </div>

                        <p style={{ fontSize: '0.8rem', color: 'var(--text-main)', marginTop: '0.35rem', lineHeight: 1.4 }}>
                          {a.explanation}
                        </p>

                        <div style={{ display: 'flex', gap: '0.75rem', marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--text-dim)' }} className="mono">
                          <span>user: <strong style={{ color: 'var(--text-muted)' }}>{a.user || 'None'}</strong></span>
                          {a.object_id && <span>obj: <strong style={{ color: 'var(--text-muted)' }}>{a.object_id}</strong></span>}
                          <span style={{ marginLeft: 'auto', color: 'var(--accent)', fontWeight: 600 }}>Inspect ↗</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ENDPOINTS TAB CONTENT */}
      {activeTab === 'endpoints' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.8rem' }}>
            <div>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🗺️</span> Endpoint Inventory ({filteredEndpoints.length} of {endpoints.length})
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                Catalog of observed endpoints classified as Documented, Shadow, or Zombie APIs.
              </p>
            </div>

            {/* Endpoints Filters Bar */}
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Search paths..."
                value={endpointSearch}
                onChange={e => setEndpointSearch(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none',
                  minWidth: '180px'
                }}
              />

              <select
                value={endpointClass}
                onChange={e => setEndpointClass(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Types</option>
                <option value="DOCUMENTED">Documented</option>
                <option value="SHADOW">Shadow APIs</option>
                <option value="ZOMBIE">Zombie APIs</option>
              </select>

              <select
                value={endpointMethod}
                onChange={e => setEndpointMethod(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Methods</option>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.6rem 0.5rem' }}>METHOD</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>NORMALIZED PATH</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>STATUS</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>OWASP CATEGORY</th>
                  <th style={{ padding: '0.6rem 0.5rem', textAlign: 'right' }}>HITS</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>SEEN USERS</th>
                </tr>
              </thead>
              <tbody>
                {filteredEndpoints.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-dim)' }}>
                      No matching endpoints found. Try clearing filters or send traffic through :8080 proxy.
                    </td>
                  </tr>
                ) : (
                  filteredEndpoints.map((ep, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '0.6rem 0.5rem' }}>
                        <span className={`badge-method method-${ep.method.toLowerCase()}`}>{ep.method}</span>
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }} className="mono">
                        {ep.norm_path}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }}>
                        <span className={`badge badge-${ep.classification.toLowerCase()}`}>
                          {ep.classification}
                        </span>
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }}>
                        {ep.owasp_category ? (
                          <span style={{ color: 'var(--warning)', fontWeight: 600 }}>{ep.owasp_category}</span>
                        ) : (
                          <span style={{ color: 'var(--text-dim)' }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem', textAlign: 'right' }} className="mono font-bold">
                        {ep.hit_count}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-muted)' }}>
                        {ep.users_seen.length > 0 ? ep.users_seen.join(', ') : 'anonymous'}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ALERTS TAB CONTENT (Full filterable table + click to inspect) */}
      {activeTab === 'alerts' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.8rem' }}>
            <div>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🚨</span> Security Alerts Inventory ({filteredAlerts.length} of {alerts.length})
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                Click any row to open the complete remediation drawer with raw payloads and recommended fixes.
              </p>
            </div>

            {/* Alerts Filters Bar */}
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Search alerts / paths / text..."
                value={alertSearch}
                onChange={e => setAlertSearch(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none',
                  minWidth: '200px'
                }}
              />

              <select
                value={alertSeverity}
                onChange={e => setAlertSeverity(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select
                value={alertOwasp}
                onChange={e => setAlertOwasp(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All OWASP</option>
                <option value="API1">API1 (BOLA)</option>
                <option value="API4">API4 (Rate Limit)</option>
                <option value="API6">API6 (Enumeration)</option>
                <option value="API9">API9 (Inventory)</option>
              </select>

              <select
                value={alertUser}
                onChange={e => setAlertUser(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Users</option>
                {detectedUsers.map(u => (
                  <option key={u} value={u}>{u}</option>
                ))}
              </select>

              <select
                value={alertTimeRange}
                onChange={e => setAlertTimeRange(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Time</option>
                <option value="1H">Last 1 Hour</option>
                <option value="5M">Last 5 Minutes</option>
              </select>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.6rem 0.5rem' }}>TIME</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>SEVERITY</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>OWASP</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>USER</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>ENDPOINT</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>OBJECT</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>EXPLANATION</th>
                  <th style={{ padding: '0.6rem 0.5rem', textAlign: 'right' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan="8" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-dim)' }}>
                      No alerts match the selected filters.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map(a => {
                    const isHigh = a.severity === 'HIGH' || a.severity === 'CRITICAL';
                    const isMedium = a.severity === 'MEDIUM';
                    const badgeClass = isHigh ? 'badge-high' : isMedium ? 'badge-medium' : 'badge-low';

                    return (
                      <tr
                        key={a.id}
                        onClick={() => setSelectedAlert(a)}
                        style={{
                          borderBottom: '1px solid rgba(255,255,255,0.03)',
                          cursor: 'pointer',
                          transition: 'background 0.15s ease'
                        }}
                        onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,255,255,0.03)'}
                        onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
                      >
                        <td style={{ padding: '0.6rem 0.5rem', whiteSpace: 'nowrap' }} className="mono">
                          {a.ts ? new Date(a.ts).toLocaleTimeString() : ''}
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem' }}>
                          <span className={`badge ${badgeClass}`}>{a.severity}</span>
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem' }}>
                          <span style={{ fontWeight: 700, color: 'var(--warning)' }}>{a.owasp_category}</span>
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem' }}>
                          <strong style={{ color: 'var(--text-muted)' }}>{a.user || 'None'}</strong>
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem' }} className="mono">
                          {a.endpoint}
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem' }} className="mono">
                          {a.object_id ? <span className="badge badge-high">{a.object_id}</span> : '—'}
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem', color: 'var(--text-main)', maxWidth: '380px' }}>
                          <span style={{ display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                            {a.explanation}
                          </span>
                        </td>
                        <td style={{ padding: '0.6rem 0.5rem', textAlign: 'right' }}>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedAlert(a);
                            }}
                            style={{
                              background: 'var(--bg-primary)',
                              border: '1px solid var(--border)',
                              borderRadius: '6px',
                              padding: '0.25rem 0.6rem',
                              color: 'var(--accent)',
                              fontSize: '0.75rem',
                              fontWeight: 600,
                              cursor: 'pointer'
                            }}
                          >
                            Details →
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* BLOCKED REQUESTS TAB CONTENT */}
      {activeTab === 'blocked' && (
        <div className="card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.8rem' }}>
            <div>
              <h2 style={{ fontSize: '1.1rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span>🛡️</span> Blocked Requests Log ({filteredBlocked.length} of {blockedRequests.length})
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '2px' }}>
                Requests intercepted and dropped by API-Sentinel active enforcement (HTTP 403).
              </p>
            </div>

            {/* Blocked Filters Bar */}
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
              <input
                type="text"
                placeholder="Search blocked paths / reason..."
                value={blockedSearch}
                onChange={e => setBlockedSearch(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none',
                  minWidth: '200px'
                }}
              />

              <select
                value={blockedUser}
                onChange={e => setBlockedUser(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Users</option>
                {detectedUsers.map(u => (
                  <option key={u} value={u}>{u}</option>
                ))}
              </select>

              <select
                value={blockedOwasp}
                onChange={e => setBlockedOwasp(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All OWASP</option>
                <option value="API1">API1 (BOLA)</option>
                <option value="API4">API4 (Rate Limit)</option>
                <option value="API6">API6 (Enumeration)</option>
              </select>

              <select
                value={blockedTimeRange}
                onChange={e => setBlockedTimeRange(e.target.value)}
                style={{
                  background: 'var(--bg-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.8rem',
                  color: 'var(--text-main)',
                  fontSize: '0.8rem',
                  outline: 'none'
                }}
              >
                <option value="ALL">All Time</option>
                <option value="1H">Last 1 Hour</option>
                <option value="5M">Last 5 Minutes</option>
              </select>
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '0.6rem 0.5rem' }}>TIME</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>USER</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>METHOD</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>PATH</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>OBJECT ID</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>REASON</th>
                  <th style={{ padding: '0.6rem 0.5rem' }}>OWASP</th>
                </tr>
              </thead>
              <tbody>
                {filteredBlocked.length === 0 ? (
                  <tr>
                    <td colSpan="7" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-dim)' }}>
                      No blocked requests match filters. Toggle mode to ENFORCEMENT or run demo with ENFORCE=1.
                    </td>
                  </tr>
                ) : (
                  filteredBlocked.map((b, idx) => (
                    <tr key={b.id || idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                      <td style={{ padding: '0.6rem 0.5rem', whiteSpace: 'nowrap' }} className="mono">
                        {b.time ? new Date(b.time).toLocaleTimeString() : b.ts}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }}>
                        <strong style={{ color: 'var(--text-muted)' }}>{b.user || 'anonymous'}</strong>
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }}>
                        <span className={`badge-method method-${(b.method || 'GET').toLowerCase()}`}>{b.method}</span>
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }} className="mono">
                        {b.path}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }} className="mono">
                        {b.object_id ? <span className="badge badge-high">{b.object_id}</span> : '—'}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem', color: '#f87171' }}>
                        {b.reason}
                      </td>
                      <td style={{ padding: '0.6rem 0.5rem' }}>
                        <span className="badge badge-high">{b.owasp_category || 'API1'}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ALERT DETAILS DRAWER (Slide-over panel) */}
      {selectedAlert && (
        <>
          <div className="drawer-backdrop" onClick={() => setSelectedAlert(null)} />
          <div className="drawer-panel">
            <div className="drawer-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                <span className={`badge ${selectedAlert.severity === 'HIGH' || selectedAlert.severity === 'CRITICAL' ? 'badge-high' : 'badge-medium'}`}>
                  {selectedAlert.severity}
                </span>
                <span style={{ fontSize: '1.05rem', fontWeight: 800, color: 'var(--text-main)' }}>
                  {selectedAlert.type} Finding
                </span>
                <span className="badge" style={{ background: 'rgba(99,102,241,0.2)', color: '#818cf8', borderColor: 'rgba(99,102,241,0.3)' }}>
                  {selectedAlert.owasp_category}
                </span>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '1.25rem',
                  cursor: 'pointer',
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px'
                }}
              >
                ✕
              </button>
            </div>

            <div className="drawer-body">
              {/* Finding Overview */}
              <div className="drawer-section">
                <div className="drawer-section-title"><span>📌</span> Alert Overview</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.82rem' }}>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Timestamp:</span><br/>
                    <strong className="mono" style={{ color: 'var(--text-main)' }}>
                      {selectedAlert.ts ? new Date(selectedAlert.ts).toLocaleString() : 'N/A'}
                    </strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Target Actor:</span><br/>
                    <strong style={{ color: 'var(--text-main)' }}>{selectedAlert.user || 'anonymous'}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Endpoint:</span><br/>
                    <strong className="mono" style={{ color: 'var(--accent)' }}>{selectedAlert.endpoint}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-dim)' }}>Object ID:</span><br/>
                    <strong className="mono" style={{ color: selectedAlert.object_id ? 'var(--danger)' : 'var(--text-muted)' }}>
                      {selectedAlert.object_id || 'None'}
                    </strong>
                  </div>
                </div>
              </div>

              {/* Full Explanation */}
              <div className="drawer-section">
                <div className="drawer-section-title"><span>⚠️</span> Threat Explanation</div>
                <p style={{ fontSize: '0.86rem', lineHeight: 1.5, color: 'var(--text-main)' }}>
                  {selectedAlert.explanation}
                </p>
              </div>

              {/* OWASP Classification */}
              <div className="drawer-section">
                <div className="drawer-section-title"><span>🛡️</span> OWASP Classification</div>
                <div style={{ fontSize: '0.84rem', color: 'var(--warning)', fontWeight: 700, marginBottom: '0.3rem' }}>
                  {selectedAlert.owasp_category}: {OWASP_CATEGORIES.find(c => c.code === selectedAlert.owasp_category)?.name || 'API Vulnerability'}
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
                  {selectedAlert.owasp_description || OWASP_CATEGORIES.find(c => c.code === selectedAlert.owasp_category)?.desc || 'Violation of API Security Best Practices.'}
                </p>
              </div>

              {/* Raw Request & Response Inspect */}
              <div className="drawer-section">
                <div className="drawer-section-title"><span>🔍</span> Raw Request / Response (PII-Masked)</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}>HTTP REQUEST:</div>
                    <div className="code-block">
                      {`${selectedAlert.method || 'GET'} ${selectedAlert.raw_path || selectedAlert.endpoint} HTTP/1.1\nHost: localhost:8080\nAuthorization: Bearer token-***`}
                      {selectedAlert.req_body ? `\n\n${selectedAlert.req_body}` : ''}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', marginBottom: '0.25rem' }}>HTTP RESPONSE:</div>
                    <div className="code-block" style={{ color: '#a7f3d0' }}>
                      {`HTTP/1.1 ${selectedAlert.status || 200} OK\nContent-Type: application/json\n\n${selectedAlert.resp_body || '{"status": "ok"}'}`}
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommended Fix / Remediation */}
              <div className="drawer-section" style={{ borderLeft: '4px solid var(--success)', background: 'rgba(16, 185, 129, 0.05)' }}>
                <div className="drawer-section-title" style={{ color: 'var(--success)' }}><span>💡</span> Recommended Remediation</div>
                <p style={{ fontSize: '0.84rem', lineHeight: 1.5, color: 'var(--text-main)' }}>
                  {selectedAlert.remediation || 'Enforce strict object-level authorization checks at the service layer.'}
                </p>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Footer Info */}
      <footer style={{ borderTop: '1px solid var(--border)', paddingTop: '1rem', marginTop: '2rem', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
        <div>API-Sentinel • Runtime BOLA & Shadow API Detection Engine • University / Internship Lab</div>
        <div>All payloads PII-masked • Polling detection API on :9000</div>
      </footer>
    </div>
  );
}
