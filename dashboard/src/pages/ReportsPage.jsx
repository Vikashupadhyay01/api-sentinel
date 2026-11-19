import React from 'react';
import { useApp } from '../contexts/AppContext';

export function ReportsPage() {
  const { stats } = useApp();
  const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000/api';

  const exports = [
    { title: 'Executive PDF Report', desc: 'Full security assessment with risk score, OWASP breakdown, audit logs, and remediation advice', icon: '📄', href: `${API_BASE}/report.pdf`, download: false, color: 'var(--teal)' },
    { title: 'Alerts (CSV)', desc: 'All security alerts with PII masked, sortable in Excel/Sheets', icon: '📊', href: `${API_BASE}/export/alerts.csv`, download: true, color: 'var(--orange)' },
    { title: 'Alerts (JSON)', desc: 'Full alert data as JSON for SIEM/pipeline integration', icon: '📋', href: `${API_BASE}/export/alerts.json`, download: true, color: 'var(--orange)' },
    { title: 'Blocked Requests (CSV)', desc: 'Complete blocked request audit trail for compliance reporting', icon: '🛡️', href: `${API_BASE}/export/blocked.csv`, download: true, color: 'var(--danger)' },
    { title: 'Discovered OpenAPI (YAML)', desc: 'Enriched OpenAPI spec with shadow/zombie endpoints annotated', icon: '🗺️', href: `${API_BASE}/export/openapi.yaml`, download: true, color: 'var(--purple)' },
  ];

  return (
    <div className="fade-up">
      <div style={{ marginBottom: '16px' }}>
        <h2 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Reports & Exports</h2>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Download security reports and raw data exports</p>
      </div>

      {/* Stats summary */}
      <div className="card-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: '16px' }}>
        {[
          { label: 'Total Alerts', value: stats.total_alerts, color: 'var(--danger)' },
          { label: 'Blocked', value: stats.blocked_requests, color: 'var(--orange)' },
          { label: 'Endpoints', value: stats.total_endpoints, color: 'var(--teal)' },
          { label: 'Risk Score', value: `${stats.risk_score}/100`, color: stats.risk_color || 'var(--success)' },
        ].map(s => (
          <div key={s.label} className="kpi-card">
            <div className="kpi-label">{s.label}</div>
            <div className="kpi-value" style={{ color: s.color, fontSize: '1.8rem' }}>{s.value}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
        {exports.map(e => (
          <a
            key={e.title}
            href={e.href}
            download={e.download || undefined}
            target={!e.download ? '_blank' : undefined}
            rel="noopener noreferrer"
            style={{ textDecoration: 'none' }}
          >
            <div
              className="card"
              style={{ cursor: 'pointer', transition: 'transform 0.15s, box-shadow 0.15s', borderLeft: `4px solid ${e.color}` }}
              onMouseEnter={el => { if (el.currentTarget) el.currentTarget.style.transform = 'translateY(-2px)'; }}
              onMouseLeave={el => { if (el.currentTarget) el.currentTarget.style.transform = ''; }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '2rem' }} aria-hidden="true">{e.icon}</span>
                <div>
                  <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: '2px' }}>{e.title}</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{e.desc}</div>
                </div>
                <div style={{ marginLeft: 'auto', color: e.color, fontSize: '1.1rem' }}>
                  {e.download ? '⬇️' : '↗️'}
                </div>
              </div>
            </div>
          </a>
        ))}
      </div>

      <div style={{ marginTop: '16px' }}>
        <div className="card" style={{ borderLeft: '3px solid var(--warning)', background: 'var(--warning-bg)' }}>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            <strong style={{ color: 'var(--warning)' }}>Lab Environment Notice:</strong> All data is generated against a deliberately vulnerable mock API on localhost. No production systems were affected. All outputs have PII masking applied.
          </p>
        </div>
      </div>
    </div>
  );
}

