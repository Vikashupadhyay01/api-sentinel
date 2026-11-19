import React, { useState } from 'react';
import { useApp } from '../contexts/AppContext';

function MiniSparkline({ data, color = '#1cc8ae' }) {
  const max = Math.max(...data, 1);
  const w = 60; const h = 24; const n = data.length;
  if (n < 2) return <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>—</span>;
  const pts = data.map((v, i) => `${(i / (n-1)) * w},${h - (v / max) * (h - 2)}`).join(' ');
  return (
    <svg width={w} height={h} className="sparkline" aria-hidden="true">
      <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

export function UsersPage() {
  const { topUsers, alerts, setActiveTab } = useApp();
  const [sortBy, setSortBy] = useState('alert_count');

  const sorted = [...topUsers].sort((a, b) => (b[sortBy] || 0) - (a[sortBy] || 0));

  const getUserAlertHistory = (username) => {
    const userAlerts = alerts.filter(a => a.user === username);
    const counts = Array.from({ length: 10 }, (_, i) => {
      const slice = userAlerts.slice(i * 3, (i + 1) * 3);
      return slice.length;
    });
    return counts;
  };

  const threatColors = { BOLA: 'var(--danger)', 'Rate Limit': 'var(--warning)', Enumeration: 'var(--purple)', 'Shadow/Zombie': 'var(--info)' };

  const handleUserClick = (username) => {
    setActiveTab('alerts');
  };

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>User Threat Profiles</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Rank users by security risk. Click a user to filter their alerts.</p>
        </div>
        <select className="filter-select" value={sortBy} onChange={e => setSortBy(e.target.value)} aria-label="Sort by">
          <option value="alert_count">Sort by Alerts</option>
          <option value="blocked_count">Sort by Blocked</option>
        </select>
      </div>
      <div className="card">
        {sorted.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">👤</span>
            <span className="empty-title">No user data yet</span>
            <span className="empty-desc">Users will appear as requests pass through the proxy.</span>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th scope="col">User</th>
                  <th scope="col">Threat Score</th>
                  <th scope="col">Alerts</th>
                  <th scope="col">Blocked</th>
                  <th scope="col">Primary Threat</th>
                  <th scope="col">Activity</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((u, i) => {
                  const score = Math.min(100, (u.alert_count || 0) * 10 + (u.blocked_count || 0) * 20);
                  const scoreColor = score >= 60 ? 'var(--danger)' : score >= 30 ? 'var(--orange)' : 'var(--success)';
                  const sparkData = getUserAlertHistory(u.user);
                  return (
                    <tr key={u.user || i} className="clickable" onClick={() => handleUserClick(u.user)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && handleUserClick(u.user)}>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ width: 28, height: 28, background: 'var(--teal-light)', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 700, fontSize: '0.75rem', color: 'var(--teal-dark)', flexShrink: 0 }} aria-hidden="true">
                            {(u.user || '?')[0].toUpperCase()}
                          </div>
                          <span style={{ fontWeight: 600 }}>{u.user}</span>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ flex: 1, height: 6, background: 'var(--border)', borderRadius: '99px', overflow: 'hidden' }}>
                            <div style={{ width: `${score}%`, height: '100%', background: scoreColor, borderRadius: '99px', transition: 'width 0.3s ease' }} />
                          </div>
                          <span style={{ fontWeight: 700, color: scoreColor, minWidth: '28px', fontSize: '0.8rem' }}>{score}</span>
                        </div>
                      </td>
                      <td><span className="badge badge-high">{u.alert_count || 0}</span></td>
                      <td><span style={{ fontWeight: 600, color: u.blocked_count > 0 ? 'var(--orange)' : 'var(--text-muted)' }}>{u.blocked_count || 0}</span></td>
                      <td><span style={{ color: threatColors[u.top_threat] || 'var(--text-muted)', fontWeight: 600, fontSize: '0.78rem' }}>{u.top_threat || '—'}</span></td>
                      <td><MiniSparkline data={sparkData} color={scoreColor} /></td>
                      <td>
                        <button className="btn btn-sm btn-secondary" onClick={e => { e.stopPropagation(); handleUserClick(u.user); }} aria-label={`Filter alerts for ${u.user}`}>
                          View Alerts →
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

