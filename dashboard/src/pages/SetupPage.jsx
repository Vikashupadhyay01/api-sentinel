import React from 'react';
import { useApp } from '../contexts/AppContext';

const INTERVALS = [
  { value: 1000, label: '1 second' },
  { value: 2000, label: '2 seconds' },
  { value: 5000, label: '5 seconds' },
  { value: 10000, label: '10 seconds' },
];

export function SetupPage() {
  const { theme, setTheme, refreshInterval, setRefreshInterval, livePolling, setLivePolling, currentMode, toggleMode, connected } = useApp();
  const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000/api';

  return (
    <div className="fade-up" style={{ maxWidth: '640px' }}>
      <div style={{ marginBottom: '16px' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Setup & Configuration</h2>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Customize dashboard appearance and polling settings</p>
      </div>

      {/* Connection status */}
      <div className="card" style={{ marginBottom: '12px' }}>
        <div className="card-title">Connection Status</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className={`status-dot ${connected ? 'online' : 'offline'}`} aria-hidden="true" />
          <span style={{ fontWeight: 600, color: connected ? 'var(--success)' : 'var(--danger)' }}>
            {connected ? 'Detection Engine Online' : 'Engine Offline'}
          </span>
        </div>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '6px' }}>API Base: <code style={{ fontFamily: 'monospace', background: 'var(--card-bg-alt)', padding: '1px 6px', borderRadius: '3px' }}>{API_BASE}</code></p>
      </div>

      {/* Theme */}
      <div className="card" style={{ marginBottom: '12px' }}>
        <div className="card-title">Appearance</div>
        <div style={{ display: 'flex', gap: '8px' }}>
          {['light', 'dark'].map(t => (
            <button
              key={t}
              className={`btn ${theme === t ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setTheme(t)}
              aria-pressed={theme === t}
            >
              {t === 'light' ? '☀️ Light Theme' : '🌙 Dark Theme'}
            </button>
          ))}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>Preference is saved in localStorage.</p>
      </div>

      {/* Polling */}
      <div className="card" style={{ marginBottom: '12px' }}>
        <div className="card-title">Live Polling</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '12px' }}>
          <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>Live updates:</span>
          <button
            className={`btn ${livePolling ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setLivePolling(!livePolling)}
            aria-pressed={livePolling}
          >
            {livePolling ? '⏸ Pause' : '▶ Resume'}
          </button>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          {INTERVALS.map(iv => (
            <button
              key={iv.value}
              className={`btn btn-sm ${refreshInterval === iv.value ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setRefreshInterval(iv.value)}
              aria-pressed={refreshInterval === iv.value}
            >
              {iv.label}
            </button>
          ))}
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>Interval saved in localStorage.</p>
      </div>

      {/* Detection mode */}
      <div className="card" style={{ marginBottom: '12px' }}>
        <div className="card-title">Detection Mode</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            className={`btn ${currentMode === 'enforce' ? 'mode-btn-enforce' : 'mode-btn-passive'}`}
            onClick={toggleMode}
          >
            <span aria-hidden="true">{currentMode === 'enforce' ? '🛡️' : '👁️'}</span>
            {currentMode === 'enforce' ? 'ENFORCEMENT ACTIVE (403 Blocking)' : 'PASSIVE AUDIT (Observe only)'}
          </button>
        </div>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '8px' }}>
          In enforcement mode, the proxy blocks BOLA violations and rate-limit breaches before they reach the target API.
        </p>
      </div>

      {/* Keyboard shortcuts */}
      <div className="card">
        <div className="card-title">Keyboard Shortcuts</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '8px 16px', fontSize: '0.82rem', alignItems: 'center' }}>
          {[
            ['Ctrl+K or /', 'Open global search'],
            ['Escape', 'Close drawers / search'],
            ['Enter', 'Activate focused item'],
          ].map(([key, desc]) => (
            <React.Fragment key={key}>
              <kbd style={{ background: 'var(--card-bg-alt)', border: '1px solid var(--border)', borderRadius: '4px', padding: '2px 8px', fontFamily: 'monospace', fontSize: '0.75rem', whiteSpace: 'nowrap' }}>{key}</kbd>
              <span style={{ color: 'var(--text-secondary)' }}>{desc}</span>
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  );
}

