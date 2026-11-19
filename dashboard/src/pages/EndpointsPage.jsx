import React, { useState, useMemo } from 'react';
import { useApp } from '../contexts/AppContext';
import { fmt } from '../lib/format';

function EndpointDrawer({ endpoint, onClose }) {
  if (!endpoint) return null;
  const curlCmd = `curl -H "Authorization: Bearer token-alice" http://localhost:8080${endpoint.norm_path}`;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <div className="drawer-panel" role="dialog" aria-modal="true" aria-label="Endpoint details">
        <div className="drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontFamily: 'monospace', fontWeight: 700, fontSize: '0.9rem', color: 'var(--teal)' }}>{endpoint.method}</span>
            <span style={{ fontFamily: 'monospace', fontSize: '0.85rem', color: 'var(--text-primary)' }}>{endpoint.norm_path}</span>
            <span className={`badge badge-${endpoint.classification?.toLowerCase()}`}>{endpoint.classification}</span>
          </div>
          <button className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close drawer">✕</button>
        </div>
        <div className="drawer-body">
          <div className="drawer-section">
            <div className="drawer-section-title">📌 Endpoint Overview</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '0.82rem' }}>
              <div>Classification: <strong className={`badge badge-${endpoint.classification?.toLowerCase()}`}>{endpoint.classification}</strong></div>
              <div>Hit Count: <strong>{endpoint.hit_count || 0}</strong></div>
              <div>OWASP: <strong style={{ color: 'var(--warning)' }}>{endpoint.owasp_category || '—'}</strong></div>
              <div>Method: <strong style={{ fontFamily: 'monospace' }}>{endpoint.method}</strong></div>
            </div>
          </div>
          {endpoint.owasp_category && (
            <div className="drawer-section" style={{ borderLeft: '3px solid var(--warning)' }}>
              <div className="drawer-section-title">⚠️ Security Classification</div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {endpoint.classification === 'shadow' && 'This endpoint is NOT documented in the OpenAPI spec. It is accessible but unknown — a Shadow API (OWASP API9).'}
                {endpoint.classification === 'zombie' && 'This is a deprecated/legacy version endpoint still running in production — a Zombie API (OWASP API9).'}
                {endpoint.classification === 'documented' && 'This endpoint is covered by the official OpenAPI contract.'}
              </p>
            </div>
          )}
          <div className="drawer-section">
            <div className="drawer-section-title">🔧 Copy as cURL</div>
            <div className="code-block">{curlCmd}</div>
            <button
              className="btn btn-secondary btn-sm"
              style={{ marginTop: '8px' }}
              onClick={() => navigator.clipboard?.writeText(curlCmd)}
            >
              📋 Copy to clipboard
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

export function EndpointsPage() {
  const { endpoints } = useApp();
  const [classification, setClassification] = useState('ALL');
  const [method, setMethod] = useState('ALL');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState(null);

  const filtered = useMemo(() => endpoints.filter(ep => {
    const matchClass = classification === 'ALL' || ep.classification?.toUpperCase() === classification;
    const matchMethod = method === 'ALL' || ep.method?.toUpperCase() === method;
    const q = search.toLowerCase().trim();
    const matchSearch = !q || ep.norm_path?.toLowerCase().includes(q) || ep.method?.toLowerCase().includes(q);
    return matchClass && matchMethod && matchSearch;
  }), [endpoints, classification, method, search]);

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '16px' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)' }}>Endpoint Inventory</h2>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>All observed API endpoints classified against the OpenAPI spec</p>
      </div>
      <div className="card">
        <div className="filter-bar">
          <select className="filter-select" value={classification} onChange={e => setClassification(e.target.value)} aria-label="Filter by classification">
            <option value="ALL">All Classifications</option>
            <option value="DOCUMENTED">Documented</option>
            <option value="SHADOW">Shadow</option>
            <option value="ZOMBIE">Zombie</option>
          </select>
          <select className="filter-select" value={method} onChange={e => setMethod(e.target.value)} aria-label="Filter by method">
            <option value="ALL">All Methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>
          <input className="search-input" placeholder="Search path or method…" value={search} onChange={e => setSearch(e.target.value)} aria-label="Search endpoints" />
        </div>
        {filtered.length === 0 ? (
          <div className="empty-state">
            <span className="empty-icon">🔍</span>
            <span className="empty-title">{endpoints.length === 0 ? 'No endpoints observed yet' : 'No results match your filters'}</span>
            <span className="empty-desc">{endpoints.length === 0 ? 'Start the proxy and make some API requests.' : 'Try adjusting filters.'}</span>
          </div>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th scope="col">Method</th>
                  <th scope="col">Path</th>
                  <th scope="col">Classification</th>
                  <th scope="col">OWASP</th>
                  <th scope="col" style={{ textAlign: 'right' }}>Hits</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((ep, i) => (
                  <tr key={i} className="clickable" onClick={() => setSelected(ep)} tabIndex={0} onKeyDown={e => e.key === 'Enter' && setSelected(ep)} aria-label={`${ep.method} ${ep.norm_path}`}>
                    <td><span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--teal)', fontSize: '0.8rem' }}>{ep.method}</span></td>
                    <td><span style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}>{ep.norm_path}</span></td>
                    <td>
                      <span className={`badge badge-${ep.classification?.toLowerCase()}`}>{ep.classification}</span>
                    </td>
                    <td><span style={{ color: 'var(--warning)', fontWeight: 600, fontSize: '0.78rem' }}>{ep.owasp_category || '—'}</span></td>
                    <td style={{ textAlign: 'right', fontFamily: 'monospace', fontWeight: 600 }}>{ep.hit_count || 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {selected && <EndpointDrawer endpoint={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

