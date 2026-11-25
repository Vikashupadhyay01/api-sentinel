import React, { useEffect, useRef, useState } from 'react';
import { useApp } from '../contexts/AppContext';

export function GlobalSearch({ open, query, setQuery, onClose }) {
  const { endpoints, alerts, topUsers, setActiveTab } = useApp();
  const inputRef = useRef(null);
  const [focused, setFocused] = useState(0);

  useEffect(() => {
    if (open) { inputRef.current?.focus(); setFocused(0); }
  }, [open]);

  useEffect(() => {
    const handler = (e) => {
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowDown') setFocused(f => f + 1);
      if (e.key === 'ArrowUp') setFocused(f => Math.max(0, f - 1));
    };
    if (open) window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onClose]);

  if (!open) return null;

  const q = query.toLowerCase().trim();

  const results = [];
  if (q) {
    endpoints.filter(e => e.norm_path?.toLowerCase().includes(q)).slice(0, 4).forEach(e => {
      results.push({ type: 'Endpoint', label: `${e.method} ${e.norm_path}`, sub: e.classification, action: () => { setActiveTab('endpoints'); onClose(); } });
    });
    alerts.filter(a => a.endpoint?.toLowerCase().includes(q) || a.user?.toLowerCase().includes(q) || a.explanation?.toLowerCase().includes(q) || String(a.object_id || '').includes(q)).slice(0, 4).forEach(a => {
      results.push({ type: 'Alert', label: `${a.type}: ${a.endpoint}`, sub: `${a.user || 'anon'} · ${a.owasp_category}`, action: () => { setActiveTab('alerts'); onClose(); } });
    });
    topUsers.filter(u => u.user?.toLowerCase().includes(q)).slice(0, 3).forEach(u => {
      results.push({ type: 'User', label: u.user, sub: `${u.alert_count} alerts · ${u.top_threat}`, action: () => { setActiveTab('users'); onClose(); } });
    });
  }

  return (
    <div className="search-modal-overlay" onClick={onClose} role="dialog" aria-modal="true" aria-label="Global search">
      <div className="search-modal" onClick={e => e.stopPropagation()}>
        <input
          ref={inputRef}
          className="search-modal-input"
          placeholder="Search endpoints, alerts, users, object IDs…"
          value={query}
          onChange={e => { setQuery(e.target.value); setFocused(0); }}
          aria-label="Search query"
        />
        <div className="search-results" role="listbox">
          {results.length === 0 && q && (
            <div className="empty-state" style={{ padding: '20px' }}>
              <span className="empty-desc">No results for "{query}"</span>
            </div>
          )}
          {!q && (
            <div className="empty-state" style={{ padding: '20px' }}>
              <span className="empty-desc">Type to search endpoints, alerts, users…</span>
            </div>
          )}
          {results.map((r, i) => (
            <div
              key={i}
              className={`search-result-item ${i === focused ? 'focused' : ''}`}
              role="option"
              aria-selected={i === focused}
              onClick={r.action}
            >
              <span className="search-result-category">{r.type}</span>
              <div>
                <div style={{ fontWeight: 500 }}>{r.label}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{r.sub}</div>
              </div>
            </div>
          ))}
        </div>
        <div className="search-hint">
          <span><kbd>↑↓</kbd> navigate</span>
          <span><kbd>Enter</kbd> select</span>
          <span><kbd>Esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
