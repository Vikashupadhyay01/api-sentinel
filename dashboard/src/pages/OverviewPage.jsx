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
    <div className="empty-state" style={{ padding: '24px 12px' }}>
      <span className="empty-icon" aria-hidden="true" style={{ fontSize: '1.8rem' }}>{icon}</span>
      <span className="empty-title" style={{ fontSize: '0.85rem' }}>{title}</span>
      <span className="empty-desc" style={{ fontSize: '0.75rem' }}>{desc}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 1 Left: Alerts by OWASP Category (wide bar chart)
// ---------------------------------------------------------------------------
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
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div className="card-title" style={{ margin: 0 }}>Alerts by OWASP Category</div>
        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Click bar to filter</span>
      </div>
      {!hasData ? (
        <EmptyState icon="📋" title="No alerts detected" desc="Run a demo attack to see OWASP category breakdown." />
      ) : (
        <div style={{ height: 165, width: '100%', position: 'relative', marginTop: 4 }}>
          <svg viewBox="0 0 500 150" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            {/* Grid lines */}
            {[0, 0.5, 1].map((pct, i) => (
              <g key={i}>
                <line x1="30" y1={120 - pct * 100} x2="480" y2={120 - pct * 100} stroke="var(--border)" strokeDasharray="3 3" />
                <text x="25" y={124 - pct * 100} fill="var(--text-muted)" fontSize="9" textAnchor="end">{Math.round(maxVal * pct)}</text>
              </g>
            ))}
            {/* Bars */}
            {data.map((d, i) => {
              const x = 55 + i * 110;
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
                    width="55"
                    height={Math.max(barHeight, 2)}
                    rx="5"
                    fill={d.color}
                    opacity={isHov ? 1 : 0.88}
                    style={{ transition: 'all 0.15s ease' }}
                  />
                  <text x={x + 27.5} y="138" fill="var(--text-secondary)" fontSize="11" fontWeight="600" textAnchor="middle">{d.name}</text>
                  <text x={x + 27.5} y={y - 5} fill={d.color} fontSize="11" fontWeight="700" textAnchor="middle">{d.alerts}</text>
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

// ---------------------------------------------------------------------------
// Row 1 Right: KPI Column (In scope / Covered / Uncovered stacked in one card)
// ---------------------------------------------------------------------------
function KPICard({ stats }) {
  const total = stats.total_endpoints || 0;
  const doc = stats.documented_endpoints || 0;
  const shadow = stats.shadow_endpoints || 0;
  const zombie = stats.zombie_endpoints || 0;
  const uncovered = shadow + zombie;

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div className="card-title" style={{ marginBottom: 4 }}>Endpoint Scope & Coverage</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, flex: 1, justifyContent: 'space-around' }}>
        {/* In scope */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
          <div>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-secondary)' }}>
              In scope
            </div>
            <div style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
              Total API endpoints observed
            </div>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>
            {total}
          </div>
        </div>

        {/* Covered (documented in OpenAPI spec) */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: 8 }}>
          <div>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--teal)' }}>
              Covered
            </div>
            <div style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
              Documented in OpenAPI spec
            </div>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: 'var(--teal)', lineHeight: 1 }}>
            {doc}
          </div>
        </div>

        {/* Uncovered (shadow + zombie) */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: uncovered > 0 ? 'var(--orange)' : 'var(--success)' }}>
              Uncovered
            </div>
            <div style={{ fontSize: '0.70rem', color: 'var(--text-muted)' }}>
              Shadow + zombie ({shadow} shadow, {zombie} zombie)
            </div>
          </div>
          <div style={{ fontSize: '1.85rem', fontWeight: 800, color: uncovered > 0 ? 'var(--orange)' : 'var(--success)', lineHeight: 1 }}>
            {uncovered}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 2 Left: Requests vs Alerts Line Chart
// ---------------------------------------------------------------------------
function TimelineCard({ buckets }) {
  const [hovIndex, setHovIndex] = useState(null);
  const data = (buckets || []).slice(-24);
  const maxReq = Math.max(1, ...data.map(b => Math.max(b.requests || 0, b.alerts || 0)));
  const hasData = data.some(d => (d.requests || 0) > 0 || (d.alerts || 0) > 0);

  const getPoints = (key) => {
    if (data.length < 2) return '';
    return data.map((d, i) => {
      const x = 30 + (i / (data.length - 1)) * 450;
      const y = 120 - ((d[key] || 0) / maxReq) * 95;
      return `${x},${y}`;
    }).join(' ');
  };

  const reqPoints = getPoints('requests');
  const alertPoints = getPoints('alerts');

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
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
      {!hasData ? (
        <EmptyState icon="📈" title="No traffic yet" desc="Start the proxy and run requests to see the timeline." />
      ) : (
        <div style={{ height: 165, width: '100%', position: 'relative', marginTop: 4 }}>
          <svg viewBox="0 0 500 150" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            {/* Grid */}
            {[0, 0.5, 1].map((pct, i) => (
              <g key={i}>
                <line x1="30" y1={120 - pct * 95} x2="480" y2={120 - pct * 95} stroke="var(--border)" strokeDasharray="3 3" />
                <text x="25" y={124 - pct * 95} fill="var(--text-muted)" fontSize="9" textAnchor="end">{Math.round(maxReq * pct)}</text>
              </g>
            ))}
            {/* Lines */}
            {reqPoints && <polyline points={reqPoints} fill="none" stroke={TEAL} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            {alertPoints && <polyline points={alertPoints} fill="none" stroke={ORANGE} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            {/* Hover points */}
            {data.map((d, i) => {
              const x = 30 + (i / Math.max(1, data.length - 1)) * 450;
              const yReq = 120 - ((d.requests || 0) / maxReq) * 95;
              const isHov = hovIndex === i;
              return (
                <g key={i} onMouseEnter={() => setHovIndex(i)} onMouseLeave={() => setHovIndex(null)} cursor="pointer">
                  <circle cx={x} cy={yReq} r={isHov ? 5 : 2} fill={TEAL} stroke="var(--card-bg)" strokeWidth="1.5" />
                  <rect x={x - 10} y={15} width={20} height={115} fill="transparent" />
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

// ---------------------------------------------------------------------------
// Row 2 Right: OWASP Category Tiles (2x2 Grid)
// ---------------------------------------------------------------------------
function OWASPTilesCard({ owaspBreakdown, onCategoryClick, activeFilter }) {
  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div className="card-title" style={{ margin: 0 }}>OWASP Category Quick View</div>
        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Click to filter</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 8, flex: 1 }}>
        {OWASP_CATEGORIES.map(c => {
          const count = owaspBreakdown[c.code] || 0;
          return (
            <button
              key={c.code}
              className={`owasp-tile ${activeFilter === c.code ? 'active' : ''}`}
              onClick={() => onCategoryClick && onCategoryClick(c.code)}
              style={{
                borderTopColor: c.color,
                borderTopWidth: 3,
                borderTopStyle: 'solid',
                textAlign: 'left',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                padding: '8px 12px',
                height: '100%',
                background: 'var(--card-bg-alt)'
              }}
              aria-pressed={activeFilter === c.code}
              aria-label={`${c.fullName}: ${count} alerts`}
            >
              <div className="tile-code" style={{ color: c.color, fontSize: '0.65rem' }}>{c.code}</div>
              <div className="tile-count" style={{ fontSize: '1.35rem', margin: '1px 0' }}>{count}</div>
              <div className="tile-name" style={{ fontSize: '0.70rem' }}>{c.name}</div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 3 Col 1: Validation Summary
// ---------------------------------------------------------------------------
function ValidationSummaryCard({ alerts }) {
  const high = alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length;
  const med = alerts.filter(a => a.severity === 'MEDIUM').length;
  const low = alerts.filter(a => a.severity === 'LOW').length;

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div className="card-title" style={{ marginBottom: 6 }}>Validation Summary</div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 8, margin: '8px 0 12px' }}>
        <span style={{ fontSize: '3.2rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>{alerts.length}</span>
        <span style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: 6 }}>total findings</span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flex: 1, justifyContent: 'center' }}>
        {[
          { label: 'Critical / High Severity', count: high, color: DANGER },
          { label: 'Medium Severity', count: med, color: ORANGE },
          { label: 'Low Severity', count: low, color: TEAL },
        ].map(s => (
          <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
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

// ---------------------------------------------------------------------------
// Row 3 Col 2 & 3: SVG Donut Helper & Cards
// ---------------------------------------------------------------------------
function SvgDonut({ pct, color = TEAL, label }) {
  const r = 45;
  const circ = 2 * Math.PI * r;
  const offset = circ - (circ * Math.min(100, Math.max(0, pct))) / 100;
  return (
    <div className="donut-wrapper" style={{ position: 'relative', width: 130, height: 130, margin: '4px auto' }}>
      <svg width="130" height="130" viewBox="0 0 120 120">
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
        <div className="donut-pct" style={{ color, fontSize: '1.4rem' }}>{pct}%</div>
        <div className="donut-sub" style={{ fontSize: '0.68rem' }}>{label}</div>
      </div>
    </div>
  );
}

function InventoryDonutCard({ stats }) {
  const total = stats.total_endpoints || 0;
  const doc = stats.documented_endpoints || 0;
  const pct = fmt.pct(doc, total);
  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'space-between' }}>
      <div className="card-title" style={{ alignSelf: 'flex-start', margin: 0 }}>API Inventory Coverage</div>
      <SvgDonut pct={pct} color={TEAL} label="Documented" />
      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textAlign: 'center' }}>
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
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'space-between' }}>
      <div className="card-title" style={{ alignSelf: 'flex-start', margin: 0 }}>Enforcement Rate</div>
      <SvgDonut pct={pct} color={ORANGE} label="Blocked" />
      <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textAlign: 'center' }}>
        {blocked} blocked · {alerts} alerts logged
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 4 Col 1: Threat Activity by User (Stacked horizontal bars)
// ---------------------------------------------------------------------------
function UserStackedBarCard({ topUsers }) {
  const data = (topUsers || []).slice(0, 5);
  const maxTotal = Math.max(1, ...data.map(u => (u.alert_count || 0) + (u.blocked_count || 0)));
  const hasData = data.some(u => (u.alert_count || 0) > 0 || (u.blocked_count || 0) > 0);

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
          <div className="card-title" style={{ margin: 0 }}>Threat Activity by User</div>
          <div style={{ display: 'flex', gap: 10, fontSize: '0.70rem' }}>
            <span style={{ color: TEAL }}>■ Alerts</span>
            <span style={{ color: ORANGE }}>■ Blocked</span>
          </div>
        </div>
        <div style={{ fontSize: '0.70rem', color: 'var(--text-muted)', marginBottom: 10 }}>
          Security alerts vs blocked attempts by user
        </div>
      </div>

      {!hasData ? (
        <EmptyState icon="👤" title="No user activity" desc="User metrics will appear as traffic is processed." />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, flex: 1, justifyContent: 'center' }}>
          {data.map(u => {
            const alertPct = ((u.alert_count || 0) / maxTotal) * 100;
            const blockedPct = ((u.blocked_count || 0) / maxTotal) * 100;
            return (
              <div key={u.user} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 45px', alignItems: 'center', gap: 8, fontSize: '0.76rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={u.user}>
                  {u.user}
                </span>
                <div style={{ height: 16, background: 'var(--border)', borderRadius: 4, display: 'flex', overflow: 'hidden' }}>
                  <div style={{ width: `${alertPct}%`, background: TEAL, transition: 'width 0.4s' }} title={`${u.alert_count || 0} alerts`} />
                  <div style={{ width: `${blockedPct}%`, background: ORANGE, transition: 'width 0.4s' }} title={`${u.blocked_count || 0} blocked`} />
                </div>
                <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'right', fontFamily: 'monospace' }}>
                  {u.alert_count || 0}/{u.blocked_count || 0}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 4 Col 2: Risk Gauge Card (Moved up to Row 4)
// ---------------------------------------------------------------------------
function RiskGaugeCard({ stats }) {
  const radius = 60;
  const circ = Math.PI * radius;
  const score = Math.min(100, Math.max(0, stats.risk_score || 0));
  const offset = circ - (circ * score) / 100;
  const color = stats.risk_color || '#10b981';

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'space-between' }}>
      <div className="card-title" style={{ alignSelf: 'flex-start', margin: 0 }}>Overall Risk Gauge</div>
      <div style={{ position: 'relative', width: 150, height: 85, margin: 'auto 0', display: 'flex', alignItems: 'flex-end', justifyContent: 'center' }}>
        <svg width="150" height="85" viewBox="0 0 150 85" role="img" aria-label={`Risk score: ${score}`}>
          <path d="M 15 75 A 60 60 0 0 1 135 75" fill="none" stroke="var(--border)" strokeWidth="12" strokeLinecap="round" />
          <path
            d="M 15 75 A 60 60 0 0 1 135 75"
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 0.6s ease' }}
          />
        </svg>
        <div style={{ position: 'absolute', bottom: 0, left: '50%', transform: 'translateX(-50%)', textAlign: 'center' }}>
          <div style={{ fontSize: '2rem', fontWeight: 800, color, lineHeight: 1 }}>{score}</div>
          <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', marginTop: 2 }}>
            {stats.risk_level || 'LOW'} RISK
          </div>
        </div>
      </div>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center' }}>
        Threat score (0–100)
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 4 Col 3: Risk Score Components (Real keys from /api/stats, no duplicate big number)
// ---------------------------------------------------------------------------
function RiskScoreComponentsCard({ stats }) {
  const breakdown = stats.risk_breakdown || {};
  const alertPts = breakdown.alerts_points || 0;
  const shadowPts = breakdown.shadow_points || 0;
  const zombiePts = breakdown.zombie_points || 0;
  const blockedPts = breakdown.blocked_points || 0;
  const sevCounts = breakdown.severity_counts || {};

  const items = [
    {
      label: 'Active Alerts',
      points: alertPts,
      max: 100,
      color: DANGER,
      sub: `${sevCounts.HIGH || 0} High · ${sevCounts.MEDIUM || 0} Med`,
    },
    {
      label: 'Shadow API Exposure',
      points: shadowPts,
      max: 20,
      color: ORANGE,
      sub: `${stats.shadow_endpoints || 0} unlisted endpoints`,
    },
    {
      label: 'Zombie API Exposure',
      points: zombiePts,
      max: 30,
      color: '#f97316',
      sub: `${stats.zombie_endpoints || 0} legacy routes`,
    },
    {
      label: 'Enforcement Mitigation',
      points: blockedPts,
      max: 15,
      color: TEAL,
      sub: `${stats.blocked_requests || 0} attacks mitigated`,
    },
  ];

  return (
    <div className="card" style={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <div>
        <div className="card-title" style={{ margin: 0 }}>Risk Score Components</div>
        <div style={{ fontSize: '0.70rem', color: 'var(--text-muted)', marginTop: 2, marginBottom: 8 }}>
          Threat factor points contributing to overall risk
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 9, flex: 1, justifyContent: 'center' }}>
        {items.map(item => {
          const pct = Math.min(100, Math.round((item.points / Math.max(item.max, 1)) * 100));
          return (
            <div key={item.label} style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{item.label}</span>
                <span style={{ fontWeight: 700, color: item.points > 0 ? item.color : 'var(--text-muted)' }}>
                  {item.points} pts
                </span>
              </div>
              <div className="progress-track" style={{ height: 6, background: 'var(--border)', borderRadius: 99, overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${pct}%`,
                    background: item.color,
                    borderRadius: 99,
                    transition: 'width 0.4s ease',
                  }}
                />
              </div>
              <div style={{ fontSize: '0.66rem', color: 'var(--text-muted)' }}>
                {item.sub}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Row 5: Blocked Requests Over Time (Full Width Area Chart)
// ---------------------------------------------------------------------------
function BlockedAreaCard({ buckets }) {
  const [hov, setHov] = useState(null);
  const data = (buckets || []).slice(-30);
  const maxB = Math.max(1, ...data.map(b => b.blocked || 0));
  const hasData = data.some(d => (d.blocked || 0) > 0);

  const pts = data.map((d, i) => {
    const x = 30 + (i / Math.max(1, data.length - 1)) * 740;
    const y = 105 - ((d.blocked || 0) / maxB) * 80;
    return `${x},${y}`;
  }).join(' ');

  const areaPts = pts ? `${pts} 770,105 30,105` : '';

  return (
    <div className="card" style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <div className="card-title" style={{ margin: 0 }}>Blocked Requests Over Time</div>
        <div style={{ fontSize: '0.70rem', color: ORANGE, fontWeight: 600 }}>
          Enforcement Mode Mitigations (HTTP 403 Forbidden)
        </div>
      </div>
      {!hasData ? (
        <EmptyState icon="🚫" title="No blocked requests in current window" desc="Enable ENFORCE mode and execute an unauthorized request to observe blocked attacks." />
      ) : (
        <div style={{ height: 125, width: '100%', position: 'relative' }}>
          <svg viewBox="0 0 800 125" style={{ width: '100%', height: '100%', overflow: 'visible' }}>
            <defs>
              <linearGradient id="areaGradFull" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={ORANGE} stopOpacity="0.4" />
                <stop offset="100%" stopColor={ORANGE} stopOpacity="0.02" />
              </linearGradient>
            </defs>
            {/* Grid */}
            {[0, 0.5, 1].map((pct, i) => (
              <g key={i}>
                <line x1="30" y1={105 - pct * 80} x2="770" y2={105 - pct * 80} stroke="var(--border)" strokeDasharray="3 3" />
                <text x="25" y={109 - pct * 80} fill="var(--text-muted)" fontSize="9" textAnchor="end">{Math.round(maxB * pct)}</text>
              </g>
            ))}
            {areaPts && <polygon points={areaPts} fill="url(#areaGradFull)" />}
            {pts && <polyline points={pts} fill="none" stroke={ORANGE} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />}
            {/* Interactive hover points */}
            {data.map((d, i) => {
              const x = 30 + (i / Math.max(1, data.length - 1)) * 740;
              const y = 105 - ((d.blocked || 0) / maxB) * 80;
              const isHov = hov === i;
              return (
                <g key={i} onMouseEnter={() => setHov(i)} onMouseLeave={() => setHov(null)} cursor="pointer">
                  {(d.blocked || 0) > 0 && <circle cx={x} cy={y} r={isHov ? 5 : 3} fill={ORANGE} stroke="var(--card-bg)" strokeWidth="1.5" />}
                  <rect x={x - 12} y={15} width={24} height={90} fill="transparent" />
                </g>
              );
            })}
          </svg>
          {hov !== null && data[hov] && (
            <div style={{ position: 'absolute', top: 0, right: 20, background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 6, padding: '4px 10px', fontSize: '0.72rem', boxShadow: 'var(--shadow-md)', pointerEvents: 'none' }}>
              <span>⏱ {data[hov].label}: </span>
              <span style={{ color: ORANGE, fontWeight: 700 }}>{data[hov].blocked || 0} blocked</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main OverviewPage component (5 clean, full-width rows matching reference)
// ---------------------------------------------------------------------------
export function OverviewPage() {
  const { stats, alerts, timelineBuckets, topUsers, setActiveTab, connected } = useApp();
  const [activeOwasp, setActiveOwasp] = useState(null);

  const handleOwaspClick = (code) => {
    setActiveOwasp(prev => prev === code ? null : code);
    setActiveTab('alerts');
  };

  if (!connected && stats.total_requests === 0) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 8, borderLeft: '3px solid var(--warning)', background: 'var(--warning-bg)' }}>
          <span style={{ color: 'var(--warning)', fontWeight: 700, fontSize: '0.85rem' }}>⚠️ Detection engine offline</span>
          <span style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>Start the backend at port 9000 to see live telemetry.</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14 }}>
          <div className="card"><div className="skeleton skeleton-chart" /></div>
          <div className="card"><div className="skeleton skeleton-chart" /></div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14 }}>
          <div className="card"><div className="skeleton skeleton-chart" /></div>
          <div className="card"><div className="skeleton skeleton-chart" /></div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }} className="fade-up">

      {/* Row 1: Alerts by OWASP category (wide) + KPI column (In scope / Covered / Uncovered stacked) */}
      <div style={{ display: 'grid', gridTemplateColumns: '2.1fr 1fr', gap: 14, alignItems: 'stretch' }}>
        <OWASPBarCard owaspBreakdown={stats.owasp_breakdown || {}} onCategoryClick={handleOwaspClick} />
        <KPICard stats={stats} />
      </div>

      {/* Row 2: Requests vs Alerts line chart + OWASP category tiles (2x2) */}
      <div style={{ display: 'grid', gridTemplateColumns: '2.1fr 1fr', gap: 14, alignItems: 'stretch' }}>
        <TimelineCard buckets={timelineBuckets} />
        <OWASPTilesCard owaspBreakdown={stats.owasp_breakdown || {}} onCategoryClick={handleOwaspClick} activeFilter={activeOwasp} />
      </div>

      {/* Row 3: Validation summary + API inventory coverage donut + Enforcement rate donut */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14, alignItems: 'stretch' }}>
        <ValidationSummaryCard alerts={alerts} />
        <InventoryDonutCard stats={stats} />
        <EffectivenessDonutCard stats={stats} />
      </div>

      {/* Row 4: Threat activity by user + Risk gauge + Risk score components */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1.6fr', gap: 14, alignItems: 'stretch' }}>
        <UserStackedBarCard topUsers={topUsers} />
        <RiskGaugeCard stats={stats} />
        <RiskScoreComponentsCard stats={stats} />
      </div>

      {/* Row 5: Blocked over time (area chart) full width */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 14, alignItems: 'stretch' }}>
        <BlockedAreaCard buckets={timelineBuckets} />
      </div>

      {/* Footer */}
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', padding: '4px 0 8px' }}>
        API-Sentinel v1.2 · Security Validation Coverage Dashboard · Plain HTTP Localhost Only · PII Masking Active
      </div>
    </div>
  );
}
