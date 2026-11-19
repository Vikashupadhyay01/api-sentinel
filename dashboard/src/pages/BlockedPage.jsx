import React, { useState, useMemo } from 'react';
import { useApp } from '../contexts/AppContext';
import { fmt } from '../lib/format';

export function BlockedPage() {
  const { blockedRequests } = useApp();
  const [user, setUser] = useState('ALL');
  const [owasp, setOwasp] = useState('ALL');
  const [search, setSearch] = useState('');

  const users = useMemo(() => [...new Set(blockedRequests.map(b => b.user).filter(Boolean))].sort(), [blockedRequests]);

  const filtered = useMemo(() => blockedRequests.filter(b => {
    const matchUser = user === 'ALL' || (b.user || 'anonymous') === user;
    const matchOwasp = owasp === 'ALL' || (b.owasp_category || 'API1').toUpperCase() === owasp;
    const q = search.toLowerCase().trim();
    const matchSearch = !q || b.path?.toLowerCase().includes(q) || b.reason?.toLowerCase().includes(q) || b.user?.toLowerCase().includes(q);
    return matchUser && matchOwasp && matchSearch;
  }), [blockedRequests, user, owasp, search]);

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Blocked Requests</h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Requests blocked by enforcement mode (ENFORCE=1 or via mode toggle)</p>
        </div>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{filtered.length} of {blockedRequests.length} records</span>
      </div>
      <div className="card">
        <div className="filter-bar">
          <select className="filter-select" value={user} onChange={e => setUser(e.target.value)} aria-label="Filter by user">
            <option value="ALL">All Users</option>
            {users.map(u => <option key={u} value={u}>{u}</option>)}
          </select>
          <select className="filter-select" value={owasp} onChange={e => setOwasp(e.target.value)} aria-label="Filter by OWASP category">
            <option value="ALL">All OWASP</option>
            <option value="API1">API1 — BOLA</option>
            <option value="API4">API4 — Rate Limit</option>
          </select>
          <input className="search-input" placeholder="Search path, reason, user…" value={search} onChange={e => setSearch(e.target.value)} aria-label="Search blocked requests" />
        </div>
        {filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon" aria-hidden="true">🛡️</span>
            <span className="empty-title">{blockedRequests.length === 0 ? 'No blocked requests yet' : 'No matches'}</span>
            <span className="empty-desc">{blockedRequests.length === 0 ? 'Enable enforcement mode and run a BOLA attack.' : 'Try adjusting filters.'}</span>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">User</th>
                  <th scope="col">Method</th>
                  <th scope="col">Path</th>
                  <th scope="col">Object ID</th>
                  <th scope="col">Reason</th>
                  <th scope="col">OWASP</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((b, i) => (
                  <tr key={i}>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'var(--text-muted)' }}>{fmt.time(b.time || b.ts)}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{b.user || '—'}</td>
                    <td><span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--teal)', fontSize: '0.8rem' }}>{b.method}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>{b.path}</td>
                    <td style={{ fontFamily: 'monospace', color: 'var(--danger)', fontSize: '0.78rem' }}>{b.object_id || '—'}</td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--danger-text)' }}>{b.reason}</td>
                    <td><span style={{ background: 'var(--danger-bg)', color: 'var(--danger-text)', padding: '2px 7px', borderRadius: '99px', fontSize: '0.7rem', fontWeight: 600 }}>{b.owasp_category || 'API1'}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

