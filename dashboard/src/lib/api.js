const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000/api';

export const api = {
  base: API_BASE,
  async stats() { return fetch(`${API_BASE}/stats`).then(r => r.json()); },
  async endpoints() { return fetch(`${API_BASE}/endpoints`).then(r => r.json()); },
  async alerts() { return fetch(`${API_BASE}/alerts`).then(r => r.json()); },
  async blocked() { return fetch(`${API_BASE}/blocked`).then(r => r.json()).catch(() => []); },
  async timeline() { return fetch(`${API_BASE}/timeline`).then(r => r.json()).catch(() => ({ buckets: [] })); },
  async topUsers() { return fetch(`${API_BASE}/top-users`).then(r => r.json()).catch(() => []); },
  async mode() { return fetch(`${API_BASE}/mode`).then(r => r.json()); },
  async setMode(mode) {
    return fetch(`${API_BASE}/mode`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) }).then(r => r.json());
  },
  async attack(type, target='http://127.0.0.1:8080') {
    return fetch(`${API_BASE}/demo/attack`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, target }) }).then(r => r.json());
  },
  async reset() { return fetch(`${API_BASE}/demo/reset`, { method: 'POST' }).then(r => r.json()); },
  reportUrl: `${API_BASE}/report.pdf`,
  exportUrl: (name) => `${API_BASE}/export/${name}`,
};
