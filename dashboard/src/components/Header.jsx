import React, { useState } from 'react';
import { useApp } from '../contexts/AppContext';

const DATE_RANGES = [
  { value: '5m', label: '5 min' },
  { value: '15m', label: '15 min' },
  { value: '1h', label: '1 hour' },
  { value: 'all', label: 'All' },
];

export function Header({ onSearchOpen, sidebarCollapsed, setSidebarCollapsed }) {
  const {
    connected, lastUpdated, currentMode, toggleMode,
    theme, setTheme, livePolling, setLivePolling,
    refreshInterval, setRefreshInterval, dateRange, setDateRange,
    triggerAttack, triggerReset,
    stats
  } = useApp();

  const [showAttackMenu, setShowAttackMenu] = useState(false);
  const [showExportMenu, setShowExportMenu] = useState(false);

  const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000/api';

  return (
    <header className="app-header" role="banner">
      {/* Left: Logo + Title */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <button
          className="btn btn-ghost btn-icon"
          onClick={() => setSidebarCollapsed(c => !c)}
          aria-label="Toggle sidebar"
          title="Toggle sidebar"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>
          </svg>
        </button>
        <div className="header-left">
          <div className="header-title">API-Sentinel <span style={{ fontSize: '0.65rem', background: 'var(--border)', padding: '2px 6px', borderRadius: '4px', color: 'var(--text-muted)', fontWeight: 600, verticalAlign: 'middle' }}>v1.1 LAB</span></div>
          <div className="header-subtitle">Runtime BOLA & Shadow API Detection Engine</div>
        </div>
      </div>

      {/* Right controls */}
      <div className="header-right">

        {/* Search shortcut */}
        <button className="btn btn-secondary btn-sm" onClick={onSearchOpen} aria-label="Open global search (Ctrl+K)" title="Search (Ctrl+K)">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <span>Search</span>
          <kbd style={{ background: 'var(--border)', borderRadius: '3px', padding: '1px 4px', fontSize: '0.65rem', fontFamily: 'monospace' }}>Ctrl+K</kbd>
        </button>

        {/* Date range */}
        <div style={{ display: 'flex', gap: '2px', background: 'var(--card-bg-alt)', border: '1px solid var(--border)', borderRadius: '7px', padding: '2px' }}>
          {DATE_RANGES.map(r => (
            <button
              key={r.value}
              className="btn btn-sm"
              style={{
                padding: '3px 8px',
                fontSize: '0.72rem',
                background: dateRange === r.value ? 'var(--teal)' : 'transparent',
                color: dateRange === r.value ? 'white' : 'var(--text-secondary)',
                border: 'none',
                borderRadius: '5px',
              }}
              onClick={() => setDateRange(r.value)}
              aria-pressed={dateRange === r.value}
            >
              {r.label}
            </button>
          ))}
        </div>

        {/* Live / Pause */}
        <button
          className={`btn btn-sm ${livePolling ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setLivePolling(!livePolling)}
          aria-label={livePolling ? 'Pause live polling' : 'Resume live polling'}
          title={livePolling ? 'Pause updates' : 'Resume updates'}
        >
          {livePolling ? (
            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
          ) : (
            <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          )}
          {livePolling ? 'Live' : 'Paused'}
        </button>

        {/* Mode toggle */}
        <button
          className={`btn btn-sm ${currentMode === 'enforce' ? 'mode-btn-enforce' : 'mode-btn-passive'}`}
          onClick={toggleMode}
          aria-label={`Detection mode: ${currentMode}. Click to toggle.`}
          title="Toggle detection mode"
        >
          <span aria-hidden="true">{currentMode === 'enforce' ? '🛡️' : '👁️'}</span>
          {currentMode === 'enforce' ? 'ENFORCE' : 'PASSIVE'}
        </button>

        {/* Demo attacks */}
        <div className="dropdown">
          <button className="btn btn-secondary btn-sm" onClick={() => setShowAttackMenu(m => !m)} aria-haspopup="true" aria-expanded={showAttackMenu} aria-label="Demo attacks menu">
            <span aria-hidden="true">⚡</span> Attacks ▾
          </button>
          {showAttackMenu && (
            <div className="dropdown-menu" onMouseLeave={() => setShowAttackMenu(false)}>
              {[
                { type: 'bola', label: '🎯 BOLA Cross-User', color: 'var(--danger-text)' },
                { type: 'enumeration', label: '🤖 ID Enumeration', color: 'var(--purple)' },
                { type: 'shadow', label: '👻 Shadow & Zombie', color: 'var(--info-text)' },
                { type: 'normal', label: '✅ Normal Traffic', color: 'var(--success-text)' },
                { type: 'all', label: '💥 Full Suite', color: 'var(--text-primary)', fontWeight: 700 },
              ].map(a => (
                <button key={a.type} className="dropdown-item" style={{ color: a.color, fontWeight: a.fontWeight }}
                  onClick={() => { setShowAttackMenu(false); triggerAttack(a.type); }}>
                  {a.label}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Reset */}
        <button className="btn btn-secondary btn-sm" onClick={triggerReset} aria-label="Reset all detection state" title="Reset state">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.73"/></svg>
          Reset
        </button>

        {/* Export dropdown */}
        <div className="dropdown">
          <button className="btn btn-secondary btn-sm" onClick={() => setShowExportMenu(m => !m)} aria-haspopup="true" aria-expanded={showExportMenu} aria-label="Export data menu">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export ▾
          </button>
          {showExportMenu && (
            <div className="dropdown-menu" onMouseLeave={() => setShowExportMenu(false)}>
              <a className="dropdown-item" href={`${API_BASE}/report.pdf`} target="_blank" rel="noopener noreferrer">📄 PDF Report</a>
              <a className="dropdown-item" href={`${API_BASE}/export/alerts.csv`} download>🚨 Alerts (CSV)</a>
              <a className="dropdown-item" href={`${API_BASE}/export/alerts.json`} download>📋 Alerts (JSON)</a>
              <a className="dropdown-item" href={`${API_BASE}/export/blocked.csv`} download>🛡️ Blocked (CSV)</a>
              <a className="dropdown-item" href={`${API_BASE}/export/openapi.yaml`} download>🗺️ OpenAPI (YAML)</a>
              <button className="dropdown-item" onClick={() => { setShowExportMenu(false); window.print(); }}>🖨️ Print View</button>
            </div>
          )}
        </div>

        {/* Theme toggle */}
        <button
          className="btn btn-ghost btn-icon"
          onClick={() => setTheme(t => t === 'light' ? 'dark' : 'light')}
          aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} theme`}
          title="Toggle theme"
        >
          {theme === 'light' ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>
          )}
        </button>

        {/* Status + date */}
        <div className="header-date" style={{ marginLeft: '4px' }}>
          <div className="header-date-label">Last Updated</div>
          <div className="header-date-value" style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
            <span className={`status-dot ${connected ? 'online' : 'offline'}`} aria-hidden="true" />
            {lastUpdated || '—'}
          </div>
        </div>
      </div>
    </header>
  );
}
