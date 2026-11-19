import React from 'react';
import { useApp } from '../contexts/AppContext';

export function Toasts() {
  const { toasts, removeToast, setActiveTab } = useApp();
  if (toasts.length === 0) return null;

  return (
    <div className="toast-container" role="region" aria-label="Notifications" aria-live="polite">
      {toasts.map(t => (
        <div
          key={t.id}
          className={`toast ${t.type === 'warning' ? 'toast-warning' : t.type === 'success' ? 'toast-success' : t.type === 'info' ? 'toast-info' : ''}`}
          role="alert"
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, fontSize: '0.78rem' }}>
              <span aria-hidden="true">{t.type === 'danger' ? '🚨' : t.type === 'warning' ? '⚠️' : t.type === 'success' ? '✅' : 'ℹ️'}</span>
              <span>{t.type === 'danger' ? 'Security Alert' : t.type === 'warning' ? 'Warning' : t.type === 'success' ? 'Success' : 'Info'}</span>
            </div>
            <button onClick={() => removeToast(t.id)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: '0.9rem', lineHeight: 1 }} aria-label="Dismiss notification">✕</button>
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.3, marginTop: '2px' }}>{t.message}</p>
          {t.alertObj && (
            <button
              style={{ alignSelf: 'flex-start', background: 'var(--teal-light)', border: 'none', color: 'var(--teal-dark)', padding: '2px 8px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 600, cursor: 'pointer', marginTop: '4px' }}
              onClick={() => { setActiveTab('alerts'); removeToast(t.id); }}
            >
              View Alert →
            </button>
          )}
        </div>
      ))}
    </div>
  );
}
