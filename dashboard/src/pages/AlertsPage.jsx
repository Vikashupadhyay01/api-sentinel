import React, { useState, useMemo } from 'react';
import { useApp } from '../contexts/AppContext';
import { fmt } from '../lib/format';

const STATUS_OPTIONS = ['new', 'acknowledged', 'resolved', 'false-positive'];
const STATUS_LABELS = { 'new': '🔴 New', 'acknowledged': '🟡 Acknowledged', 'resolved': '✅ Resolved', 'false-positive': '⚪ False Positive' };
const STATUS_CLASS = { 'new': 'status-new', 'acknowledged': 'status-acknowledged', 'resolved': 'status-resolved', 'false-positive': 'status-false-positive' };

function AlertDrawer({ alert, status, onStatusChange, onClose }) {
  if (!alert) return null;
  const sevInfo = fmt.severity(alert.severity);
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <div className="drawer-panel" role="dialog" aria-modal="true" aria-label="Alert details">
        <div className="drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span aria-hidden="true" style={{ fontSize: '1rem' }}>{sevInfo.icon}</span>
            <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>{alert.type} Finding</span>
            <span className={`badge badge-${alert.severity?.toLowerCase()}`}>{alert.severity}</span>
            <span className={`status-chip ${STATUS_CLASS[status]}`}>{STATUS_LABELS[status]}</span>
          </div>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close drawer">✕</button>
        </div>
        <div className="drawer-body">
          <div className="drawer-section">
            <div className="drawer-section-title">📌 Alert Overview</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.82rem' }}>
              <div>Actor: <strong>{alert.user || 'anonymous'}</strong></div>
              <div>Object ID: <strong style={{ fontFamily: 'monospace', color: 'var(--danger)' }}>{alert.object_id || '—'}</strong></div>
              <div style={{ gridColumn: 'span 2', fontFamily: 'monospace', color: 'var(--teal)' }}>{alert.endpoint}</div>
            </div>
          </div>
          <div className="drawer-section">
            <div className="drawer-section-title">⚠️ Threat Explanation</div>
            <p style={{ fontSize: '0.84rem', lineHeight: 1.5, color: 'var(--text-secondary)' }}>{alert.explanation}</p>
          </div>
          <div className="drawer-section">
            <div className="drawer-section-title">🛡️ OWASP {alert.owasp_category}</div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{alert.owasp_description || 'OWASP API Security violation detected.'}</p>
          </div>
          <div className="drawer-section">
            <div className="drawer-section-title">🔍 Request / Response (PII-Masked)</div>
            <div className="code-block">{`${alert.method || 'GET'} ${alert.raw_path || alert.endpoint} HTTP/1.1\nHost: localhost:8080\nAuthorization: Bearer token-***\n\nHTTP/1.1 ${alert.status || 200} OK\n${alert.resp_body || '[response body]'}`}</div>
          </div>
          <div className="drawer-section" style={{ borderLeft: '3px solid var(--success)' }}>
            <div className="drawer-section-title" style={{ color: 'var(--success-text)' }}>💡 Remediation</div>
            <p style={{ fontSize: '0.82rem', lineHeight: 1.5, color: 'var(--text-secondary)' }}>{alert.remediation || 'Enforce strict object-level authorization checks at the service layer.'}</p>
          </div>
          <div className="drawer-section">
            <div className="drawer-section-title">🔖 Workflow Status</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {STATUS_OPTIONS.map(s => (
                <button
                  key={s}
                  className={`status-chip ${STATUS_CLASS[s]}`}
                  style={{ cursor: 'pointer', border: status === s ? undefined : '1px solid var(--border)', opacity: status === s ? 1 : 0.6 }}
                  onClick={() => onStatusChange(alert.id, s)}
                  aria-pressed={status === s}
                >
                  {STATUS_LABELS[s]}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export function AlertsPage({ filterUser, filterOwasp: initialOwasp }) {
  const { alerts, getAlertStatus, setAlertStatus } = useApp();
  const [severity, setSeverity] = useState('ALL');
  const [owasp, setOwasp] = useState(initialOwasp || 'ALL');
  const [user, setUser] = useState(filterUser || 'ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);

  const users = useMemo(() => [...new Set(alerts.map(a => a.user).filter(Boolean))].sort(), [alerts]);

  const filtered = useMemo(() => alerts.filter(a => {
    const matchSev = severity === 'ALL' || a.severity?.toUpperCase() === severity;
    const matchOwasp = owasp === 'ALL' || a.owasp_category?.toUpperCase() === owasp;
    const matchUser = user === 'ALL' || (a.user || 'anonymous') === user;
    const matchStatus = statusFilter === 'ALL' || getAlertStatus(a.id) === statusFilter;
    const q = search.toLowerCase().trim();
    const matchSearch = !q || a.endpoint?.toLowerCase().includes(q) || a.user?.toLowerCase().includes(q) || a.explanation?.toLowerCase().includes(q) || String(a.object_id || '').includes(q);
    return matchSev && matchOwasp && matchUser && matchStatus && matchSearch;
  }), [alerts, severity, owasp, user, statusFilter, search, getAlertStatus]);

  const sevInfo = (s) => ({ HIGH: { class: 'badge-high', icon: '🔴' }, MEDIUM: { class: 'badge-medium', icon: '🟡' }, LOW: { class: 'badge-low', icon: '🟢' }, CRITICAL: { class: 'badge-critical', icon: '💀' } }[s] || { class: '', icon: '⚪' });

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Security Alerts</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Click an alert to open the details drawer and manage workflow status</p>
        </div>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{filtered.length} of {alerts.length} alerts</span>
      </div>
      <div className="card">
        <div className="filter-bar">
          <select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)} aria-label="Filter by severity">
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select className="filter-select" value={owasp} onChange={e => setOwasp(e.target.value)} aria-label="Filter by OWASP category">
            <option value="ALL">All OWASP</option>
            <option value="API1">API1 — BOLA</option>
            <option value="API4">API4 — Rate Limit</option>
            <option value="API6">API6 — Enumeration</option>
            <option value="API9">API9 — Inventory</option>
          </select>
          <select className="filter-select" value={user} onChange={e => setUser(e.target.value)} aria-label="Filter by user">
            <option value="ALL">All Users</option>
            {users.map(u => <option key={u} value={u}>{u}</option>)}
          </select>
          <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)} aria-label="Filter by workflow status">
            <option value="ALL">All Statuses</option>
            {STATUS_OPTIONS.map(s => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
          </select>
          <input className="search-input" placeholder="Search alerts…" value={search} onChange={e => setSearch(e.target.value)} aria-label="Search alerts" />
        </div>
        {filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">🛡️</span>
            <span className="empty-title">{alerts.length === 0 ? 'No alerts yet' : 'No matches'}</span>
            <span className="empty-desc">{alerts.length === 0 ? 'Run an attack simulation to generate alerts.' : 'Try adjusting filters.'}</span>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Type</th>
                  <th scope="col">User</th>
                  <th scope="col">Endpoint</th>
                  <th scope="col">Object ID</th>
                  <th scope="col">OWASP</th>
                  <th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a, i) => {
                  const info = sevInfo(a.severity);
                  const status = getAlertStatus(a.id);
                  return (
                    <tr key={a.id || i} className="clickable" onClick={() => setSelected(a)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && setSelected(a)}>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{fmt.time(a.ts)}</td>
                      <td><span className={`badge ${info.class}`}><span aria-hidden="true">{info.icon}</span> {a.severity}</span></td>
                      <td style={{ fontWeight: 600, fontSize: '0.82rem' }}>{a.type}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{a.user || '—'}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--teal)' }}>{a.endpoint}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--danger)' }}>{a.object_id || '—'}</td>
                      <td><span style={{ background: 'var(--teal-light)', color: 'var(--teal-dark)', padding: '2px 7px', borderRadius: '99px', fontSize: '0.7rem', fontWeight: 600 }}>{a.owasp_category}</span></td>
                      <td><span className={`status-chip ${STATUS_CLASS[status]}`}>{STATUS_LABELS[status]}</span></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {selected && (
        <AlertDrawer
          alert={selected}
          status={getAlertStatus(selected.id)}
          onStatusChange={setAlertStatus}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}

