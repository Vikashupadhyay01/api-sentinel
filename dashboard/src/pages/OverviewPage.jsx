import React, { useState } from 'react';
import { useApp } from '../contexts/AppContext';
import { fmt } from '../lib/format';

const TEAL = '#1cc8ae';
const ORANGE = '#f5a623';
const DANGER = '#ef4444';
const PURPLE = '#8b5cf6';
const CYAN = '#0eb3d8';

const OWASP_CATEGORIES = [
  { code: 'API1', name: 'BOLA', fullName: 'Broken Object Level Auth', color: DANGER },
  { code: 'API4', name: 'Rate Limit', fullName: 'Unrestricted Resource Consumption', color: ORANGE },
  { code: 'API6', name: 'Enumeration', fullName: 'Unrestricted Business Flows', color: PURPLE },
  { code: 'API9', name: 'Inventory', fullName: 'Improper Inventory Management', color: CYAN },
];

function EmptyState({ icon = '📊', title = 'No data yet', desc = 'Run an attack simulation to populate this chart.' }) {
  return (
    <div className="empty-state">
      <span className="empty-icon" aria-hidden="true">{icon}</span>
      <span className="empty-title">{title}</span>
      <span className="empty-desc">{desc}</span>
    </div>
  );
}

// 1. OWASP Bar Chart (Pure SVG)
function OWASPBarCard({ owaspBreakdown, onCategoryClick }) {
  const [hovered, setHovered] = useState(null);
  const data = OWASP_CATEGORIES.map(c => ({
    name: c.name,
    code: c.code,
    alerts: owaspBreakdown[c.code] || 0,
    color: c.color,
  }));
  const maxVal = Math.max(1, ...data.map(d => d.alerts));
  const hasData = data.some(d => d.alerts > 0);

  return (
    <div className="card" style={{ gridColumn: 'span 2', position: 'relative' }}>
      <div className="card-title">Alerts by OWASP Category</div>
      {!hasData ? <EmptyState icon="📋" title="No alerts detected" desc="Run a demo attack to see OWASP breakdown." /> : (
        <div style={{ height: 160, width: '100%', position: 'relative' }}>
          <svg viewBox="0 0 400 150" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            {/* Grid lines */}
            {[0, 0.5, 1].map((pct, i) => (
              <g key={i}>
                <line x1="30" y1={120 - pct * 100} x2="390" y2={120 - pct * 100} stroke="var(--border)" strokeDasharray="3 3" />
                <text x="25" y={124 - pct * 100} fill="var(--text-muted)" fontSize="9" textAnchor="end">{Math.round(maxVal * pct)}</text>
              </g>
            ))}
            {/* Bars */}
            {data.map((d, i) => {
              const x = 50 + i * 85;
              const barHeight = (d.alerts / maxVal) * 100;
              const y = 120 - barHeight;
              const isHov = hovered === i;
              return (
                <g
                  key={d.code}
                  cursor="pointer"
                  onClick={() => onCategoryClick && onCategoryClick(d.code)}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)}
                >
                  <rect
                    x={x}
                    y={y}
                    width="45"
                    height={Math.max(barHeight, 2)}
                    rx="4"
                    fill={d.color}
                    opacity={isHov ? 1 : 0.88}
                    style={{ transition: 'all 0.15s ease' }}
                  />
                  <text x={x + 22.5} y="136" fill="var(--text-secondary)" fontSize="10" fontWeight="600" textAnchor="middle">{d.name}</text>
                  <text x={x + 22.5} y={y - 4} fill={d.color} fontSize="10" fontWeight="700" textAnchor="middle">{d.alerts}</text>
                </g>
              );
            })}
          </svg>
          {hovered !== null && (
            <div style={{ position: 'absolute', top: 0, right: 10, background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 8px', fontSize: '0.72rem', boxShadow: 'var(--shadow-md)', pointerEvents: 'none' }}>
              <strong>{data[hovered].name}</strong>: {data[hovered].alerts} alerts (Click to filter)
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 2. KPI Cards
function KPICards({ stats }) {
  const total = stats.total_endpoints || 0;
  const doc = stats.documented_endpoints || 0;
  const shadow = stats.shadow_endpoints || 0;
  const zombie = stats.zombie_endpoints || 0;
  const uncovered = shadow + zombie;
  return (
    <>
      <div className="kpi-card kpi-teal">
        <div className="kpi-label">In Scope</div>
        <div className="kpi-value">{total}</div>
        <div className="kpi-sub">Total endpoints observed</div>
      </div>
      <div className="kpi-card kpi-teal">
        <div className="kpi-label">Documented</div>
        <div className="kpi-value" style={{ color: 'var(--teal)' }}>{doc}</div>
        <div className="kpi-sub">Covered in OpenAPI spec</div>
      </div>
      <div className="kpi-card kpi-orange">
        <div className="kpi-label">Uncovered</div>
        <div className="kpi-value" style={{ color: uncovered > 0 ? 'var(--orange)' : 'var(--success)' }}>{uncovered}</div>
        <div className="kpi-sub">{shadow} shadow · {zombie} zombie</div>
      </div>
    </>
  );
}

// 3. Traffic Timeline (Requests vs Alerts) Line Chart
function TimelineCard({ buckets }) {
  const [hovIndex, setHovIndex] = useState(null);
  const data = (buckets || []).slice(-24);
  const maxReq = Math.max(1, ...data.map(b => (b.requests || 0) + (b.alerts || 0)));
  const hasData = data.some(d => (d.requests || 0) > 0 || (d.alerts || 0) > 0);

  const getPoints = (key) => {
    if (data.length < 2) return '';
    return data.map((d, i) => {
      const x = 30 + (i / (data.length - 1)) * 360;
      const y = 120 - ((d[key] || 0) / maxReq) * 95;
      return `${x},${y}`;
    }).join(' ');
  };

  const reqPoints = getPoints('requests');
  const alertPoints = getPoints('alerts');

  return (
    <div className="card" style={{ gridColumn: 'span 2', position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="card-title" style={{ margin: 0 }}>Requests vs Alerts — Last 15 Min</div>
        <div style={{ display: 'flex', gap: 12, fontSize: '0.72rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: TEAL }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: TEAL }} /> Requests
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: ORANGE }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: ORANGE }} /> Alerts
          </span>
        </div>
      </div>
      {!hasData ? <EmptyState icon="📈" title="No traffic yet" desc="Start the proxy and run requests to see the timeline." /> : (
        <div style={{ height: 160, width: '100%', position: 'relative' }}>
          <svg viewBox="0 0 400 150" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            {/* Grid */}
            {[0, 0.5, 1].map((pct, i) => (
              <g key={i}>
                <line x1="30" y1={120 - pct * 95} x2="390" y2={120 - pct * 95} stroke="var(--border)" strokeDasharray="3 3" />
                <text x="25" y={124 - pct * 95} fill="var(--text-muted)" fontSize="9" textAnchor="end">{Math.round(maxReq * pct)}</text>
              </g>
            ))}
            {/* Lines */}
            {reqPoints && <polyline points={reqPoints} fill="none" stroke={TEAL} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            {alertPoints && <polyline points={alertPoints} fill="none" stroke={ORANGE} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            {/* Hover points */}
            {data.map((d, i) => {
              const x = 30 + (i / Math.max(1, data.length - 1)) * 360;
              const yReq = 120 - ((d.requests || 0) / maxReq) * 95;
              const isHov = hovIndex === i;
              return (
                <g key={i} onMouseEnter={() => setHovIndex(i)} onMouseLeave={() => setHovIndex(null)} cursor="pointer">
                  <circle cx={x} cy={yReq} r={isHov ? 5 : 2} fill={TEAL} stroke="var(--card-bg)" strokeWidth="1.5" />
                  <rect x={x - 8} y={20} width={16} height={105} fill="transparent" />
                </g>
              );
            })}
          </svg>
          {hovIndex !== null && data[hovIndex] && (
            <div style={{ position: 'absolute', top: 0, left: 40, background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 10px', fontSize: '0.72rem', boxShadow: 'var(--shadow-md)', pointerEvents: 'none', display: 'flex', gap: 8 }}>
              <span>⏱ {data[hovIndex].label}</span>
              <span style={{ color: TEAL }}><strong>{data[hovIndex].requests || 0}</strong> reqs</span>
              <span style={{ color: ORANGE }}><strong>{data[hovIndex].alerts || 0}</strong> alerts</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 4. OWASP Tiles
function OWASPTiles({ owaspBreakdown, onCategoryClick, activeFilter }) {
  return (
    <div className="tiles-grid" style={{ marginBottom: 12 }}>
      {OWASP_CATEGORIES.map(c => {
        const count = owaspBreakdown[c.code] || 0;
        return (
          <button
            key={c.code}
            className={`owasp-tile ${activeFilter === c.code ? 'active' : ''}`}
            onClick={() => onCategoryClick && onCategoryClick(c.code)}
            style={{ borderTopColor: c.color, borderTopWidth: 3, borderTopStyle: 'solid', textAlign: 'left' }}
            aria-pressed={activeFilter === c.code}
            aria-label={`${c.fullName}: ${count} alerts`}
          >
            <div className="tile-code" style={{ color: c.color }}>{c.code}</div>
            <div className="tile-count">{count}</div>
            <div className="tile-name">{c.name}</div>
          </button>
        );
      })}
    </div>
  );
}

// 5. Validation Summary
function ValidationSummaryCard({ alerts }) {
  const high = alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length;
  const med = alerts.filter(a => a.severity === 'MEDIUM').length;
  const low = alerts.filter(a => a.severity === 'LOW').length;
  return (
    <div className="card">
      <div className="card-title">Validation Summary</div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8, marginBottom: 14 }}>
        <span style={{ fontSize: '3.2rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>{alerts.length}</span>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: 6 }}>total alerts</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { label: 'Critical / High', count: high, color: DANGER },
          { label: 'Medium', count: med, color: ORANGE },
          { label: 'Low', count: low, color: TEAL },
        ].map(s => (
          <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.color }} />
              <span style={{ color: 'var(--text-secondary)' }}>{s.label}</span>
            </div>
            <span style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// 6. SVG Donut Component
function SvgDonut({ pct, color = TEAL, label, sublabel }) {
  const r = 45;
  const circ = 2 * Math.PI * r;
  const offset = circ - (circ * Math.min(100, Math.max(0, pct))) / 100;
  return (
    <div className="donut-wrapper" style={{ position: 'relative', width: 140, height: 140, margin: '0 auto' }}>
      <svg width="140" height="140" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="var(--border)" strokeWidth="12" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      <div className="donut-center-label">
        <div className="donut-pct" style={{ color }}>{pct}%</div>
        <div className="donut-sub">{label}</div>
      </div>
    </div>
  );
}

function InventoryDonutCard({ stats }) {
  const total = stats.total_endpoints || 0;
  const doc = stats.documented_endpoints || 0;
  const pct = fmt.pct(doc, total);
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div className="card-title" style={{ alignSelf: 'flex-start' }}>API Inventory Coverage</div>
      <SvgDonut pct={pct} color={TEAL} label="Covered" />
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', marginTop: 6 }}>
        {doc} of {total} endpoints documented
      </div>
    </div>
  );
}

function EffectivenessDonutCard({ stats }) {
  const blocked = stats.blocked_requests || 0;
  const alerts = stats.total_alerts || 0;
  const denom = Math.max(blocked + alerts, 1);
  const pct = fmt.pct(blocked, denom);
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div className="card-title" style={{ alignSelf: 'flex-start' }}>Enforcement Rate</div>
      <SvgDonut pct={pct} color={ORANGE} label="Blocked" />
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', marginTop: 6 }}>
        {blocked} blocked · {alerts} alerted
      </div>
    </div>
  );
}

// 7. Combo Chart (Blocked Bars + Alerts Line)
function ComboChartCard({ buckets }) {
  const [hov, setHov] = useState(null);
  const data = (buckets || []).slice(-18);
  const maxVal = Math.max(1, ...data.map(b => Math.max(b.blocked || 0, b.alerts || 0)));
  const hasData = data.some(d => (d.blocked || 0) > 0 || (d.alerts || 0) > 0);

  const alertLinePts = data.map((d, i) => {
    const x = 30 + i * 20 + 8;
    const y = 120 - ((d.alerts || 0) / maxVal) * 95;
    return `${x},${y}`;
  }).join(' ');

  return (
    <div className="card" style={{ gridColumn: 'span 2', position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="card-title" style={{ margin: 0 }}>Blocked Requests (Bars) + Alerts (Line)</div>
        <div style={{ display: 'flex', gap: 12, fontSize: '0.72rem' }}>
          <span style={{ color: ORANGE }}>■ Blocked</span>
          <span style={{ color: DANGER }}>● Alerts</span>
        </div>
      </div>
      {!hasData ? <EmptyState icon="🛡️" title="No blocked events" desc="Enable ENFORCE mode to see blocked requests." /> : (
        <div style={{ height: 160, width: '100%', position: 'relative' }}>
          <svg viewBox="0 0 400 150" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            {/* Grid */}
            {[0, 0.5, 1].map((pct, i) => (
              <g key={i}>
                <line x1="25" y1={120 - pct * 95} x2="390" y2={120 - pct * 95} stroke="var(--border)" strokeDasharray="3 3" />
                <text x="20" y={124 - pct * 95} fill="var(--text-muted)" fontSize="9" textAnchor="end">{Math.round(maxVal * pct)}</text>
              </g>
            ))}
            {/* Bars for blocked */}
            {data.map((d, i) => {
              const x = 30 + i * 20;
              const h = ((d.blocked || 0) / maxVal) * 95;
              const y = 120 - h;
              return (
                <rect
                  key={i}
                  x={x}
                  y={y}
                  width="14"
                  height={Math.max(h, (d.blocked || 0) > 0 ? 3 : 0)}
                  rx="3"
                  fill={ORANGE}
                  opacity={hov === i ? 1 : 0.85}
                  onMouseEnter={() => setHov(i)}
                  onMouseLeave={() => setHov(null)}
                />
              );
            })}
            {/* Line for alerts */}
            {alertLinePts && <polyline points={alertLinePts} fill="none" stroke={DANGER} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />}
            {data.map((d, i) => {
              const x = 30 + i * 20 + 7;
              const y = 120 - ((d.alerts || 0) / maxVal) * 95;
              return (
                <circle key={i} cx={x} cy={y} r={(d.alerts || 0) > 0 ? 3 : 1} fill={DANGER} />
              );
            })}
          </svg>
          {hov !== null && data[hov] && (
            <div style={{ position: 'absolute', top: 0, left: 30, background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 8px', fontSize: '0.72rem', boxShadow: 'var(--shadow-md)', pointerEvents: 'none' }}>
              <span>⏱ {data[hov].label}: </span>
              <span style={{ color: ORANGE }}><strong>{data[hov].blocked || 0}</strong> blocked</span> · <span style={{ color: DANGER }}><strong>{data[hov].alerts || 0}</strong> alerts</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// 8. User Stacked Bar Chart (Pure SVG)
function UserStackedBarCard({ topUsers }) {
  const data = (topUsers || []).slice(0, 5);
  const maxTotal = Math.max(1, ...data.map(u => (u.alert_count || 0) + (u.blocked_count || 0)));
  const hasData = data.some(u => (u.alert_count || 0) > 0 || (u.blocked_count || 0) > 0);

  return (
    <div className="card" style={{ gridColumn: 'span 2' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div className="card-title" style={{ margin: 0 }}>Threat Activity by User</div>
        <div style={{ display: 'flex', gap: 12, fontSize: '0.72rem' }}>
          <span style={{ color: TEAL }}>■ Alerts</span>
          <span style={{ color: ORANGE }}>■ Blocked</span>
        </div>
      </div>
      {!hasData ? <EmptyState icon="👤" title="No user data" desc="Activity appears as requests are processed." /> : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 10 }}>
          {data.map(u => {
            const alertPct = ((u.alert_count || 0) / maxTotal) * 100;
            const blockedPct = ((u.blocked_count || 0) / maxTotal) * 100;
            return (
              <div key={u.user} style={{ display: 'grid', gridTemplateColumns: '80px 1fr 60px', alignItems: 'center', gap: 8, fontSize: '0.8rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis' }}>{u.user}</span>
                <div style={{ height: 16, background: 'var(--border)', borderRadius: 4, display: 'flex', overflow: 'hidden' }}>
                  <div style={{ width: `${alertPct}%`, background: TEAL, transition: 'width 0.4s' }} title={`${u.alert_count || 0} alerts`} />
                  <div style={{ width: `${blockedPct}%`, background: ORANGE, transition: 'width 0.4s' }} title={`${u.blocked_count || 0} blocked`} />
                </div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'right' }}>
                  {u.alert_count || 0} / {u.blocked_count || 0}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// 9. Risk Progress Card
function RiskProgressCard({ stats }) {
  const breakdown = stats.risk_breakdown || {};
  const riskScore = stats.risk_score || 0;
  const rows = [
    { label: 'BOLA (API1)', value: breakdown.bola || 0, color: 'danger' },
    { label: 'Rate Limit (API4)', value: breakdown.rate_limit || 0, color: '' },
    { label: 'Enumeration (API6)', value: breakdown.enumeration || 0, color: '' },
    { label: 'Shadow APIs (API9)', value: breakdown.shadow || 0, color: 'orange' },
    { label: 'Zombie APIs (API9)', value: breakdown.zombie || 0, color: 'orange' },
  ];
  return (
    <div className="card">
      <div className="card-title">Risk Score Components</div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 6, marginBottom: 12 }}>
        <span style={{ fontSize: '2.6rem', fontWeight: 800, color: stats.risk_color || 'var(--teal)', lineHeight: 1 }}>{riskScore}</span>
        <span style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: 4 }}>/100</span>
        <span className={`badge ${riskScore >= 75 ? 'badge-high' : riskScore >= 50 ? 'badge-medium' : riskScore >= 25 ? 'badge-medium' : 'badge-low'}`} style={{ marginBottom: 4, marginLeft: 4 }}>
          {stats.risk_level || 'LOW'}
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {rows.map(r => {
          const pct = Math.min(100, r.value);
          return (
            <div key={r.label} className="progress-row">
              <span className="progress-label" style={{ minWidth: 105, fontSize: '0.75rem' }}>{r.label}</span>
              <div className="progress-track" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={r.label}>
                <div className={`progress-fill ${r.color === 'danger' ? 'progress-fill-danger' : r.color === 'orange' ? 'progress-fill-orange' : ''}`} style={{ width: `${pct}%` }} />
              </div>
              <span className="progress-pct">{pct}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// 10. Blocked Area Chart (Pure SVG)
function BlockedAreaCard({ buckets }) {
  const data = (buckets || []).slice(-20);
  const maxB = Math.max(1, ...data.map(b => b.blocked || 0));
  const hasData = data.some(d => (d.blocked || 0) > 0);

  const pts = data.map((d, i) => {
    const x = 20 + (i / Math.max(1, data.length - 1)) * 360;
    const y = 110 - ((d.blocked || 0) / maxB) * 90;
    return `${x},${y}`;
  }).join(' ');

  const areaPts = pts ? `${pts} 380,110 20,110` : '';

  return (
    <div className="card">
      <div className="card-title">Blocked Over Time</div>
      {!hasData ? <EmptyState icon="🚫" title="No blocks" desc="Enable ENFORCE mode to see blocks." /> : (
        <div style={{ height: 120, width: '100%' }}>
          <svg viewBox="0 0 400 120" style={{ width: '100%', height: '100%' }}>
            <defs>
              <linearGradient id="areaG" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={ORANGE} stopOpacity="0.5" />
                <stop offset="100%" stopColor={ORANGE} stopOpacity="0.05" />
              </linearGradient>
            </defs>
            {areaPts && <polygon points={areaPts} fill="url(#areaG)" />}
            {pts && <polyline points={pts} fill="none" stroke={ORANGE} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />}
          </svg>
        </div>
      )}
    </div>
  );
}

// 11. Risk Gauge Card
function RiskGaugeCard({ stats }) {
  const radius = 60;
  const circ = Math.PI * radius;
  const score = Math.min(100, Math.max(0, stats.risk_score || 0));
  const offset = circ - (circ * score) / 100;
  const color = stats.risk_color || '#10b981';
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div className="card-title" style={{ alignSelf: 'flex-start' }}>Risk Gauge</div>
      <div style={{ position: 'relative', width: 140, height: 75, overflow: 'visible' }}>
        <svg width="140" height="75" viewBox="0 0 140 75" role="img" aria-label={`Risk score: ${score}`}>
          <path d="M 10 70 A 60 60 0 0 1 130 70" fill="none" stroke="var(--border)" strokeWidth="10" strokeLinecap="round" />
          <path
            d="M 10 70 A 60 60 0 0 1 130 70"
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
        </svg>
        <div style={{ position: 'absolute', bottom: 0, left: '50%', transform: 'translateX(-50%)', textAlign: 'center' }}>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
          <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 600 }}>{stats.risk_level || 'LOW'}</div>
        </div>
      </div>
    </div>
  );
}

// Main OverviewPage component
export function OverviewPage() {
  const { stats, alerts, timelineBuckets, topUsers, setActiveTab, connected } = useApp();
  const [activeOwasp, setActiveOwasp] = useState(null);

  const handleOwaspClick = (code) => {
    setActiveOwasp(prev => prev === code ? null : code);
    setActiveTab('alerts');
  };

  if (!connected && stats.total_requests === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 8, borderLeft: '3px solid var(--warning)', background: 'var(--warning-bg)' }}>
          <span style={{ color: 'var(--warning)', fontWeight: 700, fontSize: '0.85rem' }}>⚠️ Detection engine offline</span>
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>Start the backend at port 9000 to see live data.</span>
        </div>
        <div className="card-grid">
          {[0, 1, 2, 3].map(i => <div key={i} className="kpi-card"><div className="skeleton skeleton-kpi" /></div>)}
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }} className="fade-up">

      {/* Row 1: OWASP bars + 3 KPIs */}
      <div className="card-grid" style={{ gridTemplateColumns: '2fr 1fr 1fr 1fr', alignItems: 'stretch' }}>
        <OWASPBarCard owaspBreakdown={stats.owasp_breakdown || {}} onCategoryClick={handleOwaspClick} />
        <KPICards stats={stats} />
      </div>

      {/* Row 1b: Domain tiles + Timeline */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 14, alignItems: 'stretch' }}>
        <div className="card">
          <div className="card-title">OWASP Category Quick View</div>
          <OWASPTiles owaspBreakdown={stats.owasp_breakdown || {}} onCategoryClick={handleOwaspClick} activeFilter={activeOwasp} />
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Click a tile to filter Alerts by category</div>
        </div>
        <TimelineCard buckets={timelineBuckets} />
      </div>

      {/* Row 2: Summary + 2 Donuts + Combo */}
      <div className="card-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr 2fr', alignItems: 'stretch' }}>
        <ValidationSummaryCard alerts={alerts} />
        <InventoryDonutCard stats={stats} />
        <EffectivenessDonutCard stats={stats} />
        <ComboChartCard buckets={timelineBuckets} />
      </div>

      {/* Row 3: User stacked bars + Risk progress + Area chart */}
      <div className="card-grid" style={{ gridTemplateColumns: '2fr 1fr 1fr', alignItems: 'stretch' }}>
        <UserStackedBarCard topUsers={topUsers} />
        <RiskProgressCard stats={stats} />
        <BlockedAreaCard buckets={timelineBuckets} />
      </div>

      {/* Row 4: Risk gauge + Stats */}
      <div className="card-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr 1fr' }}>
        <RiskGaugeCard stats={stats} />
        <div className="kpi-card">
          <div className="kpi-label">Total Requests</div>
          <div className="kpi-value">{stats.total_requests}</div>
          <div className="kpi-sub">Captured by proxy</div>
        </div>
        <div className="kpi-card kpi-danger">
          <div className="kpi-label">Total Alerts</div>
          <div className="kpi-value" style={{ color: stats.total_alerts > 0 ? 'var(--danger)' : 'var(--text-primary)' }}>{stats.total_alerts}</div>
          <div className="kpi-sub">Security findings</div>
        </div>
        <div className="kpi-card kpi-orange">
          <div className="kpi-label">Blocked Requests</div>
          <div className="kpi-value" style={{ color: stats.blocked_requests > 0 ? 'var(--orange)' : 'var(--text-primary)' }}>{stats.blocked_requests}</div>
          <div className="kpi-sub">Enforcement blocks</div>
        </div>
      </div>

      {/* Footer */}
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', paddingBottom: 8 }}>
        API-Sentinel v1.1 · University/Lab Project · Plain HTTP Localhost Only · PII Masking Active
      </div>
    </div>
  );
}
