const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:9000/api';

async function handleResponse(res) {
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    let errMsg = `HTTP ${res.status}`;
    try {
      const data = JSON.parse(text);
      if (data && data.error) errMsg = data.error;
    } catch {}
    throw new Error(errMsg);
  }
  return res.json();
}

export const api = {
  base: API_BASE,
  async stats() { return fetch(`${API_BASE}/stats`).then(handleResponse); },
  async endpoints() { return fetch(`${API_BASE}/endpoints`).then(handleResponse); },
  async alerts() { return fetch(`${API_BASE}/alerts`).then(handleResponse); },
  async blocked() { return fetch(`${API_BASE}/blocked`).then(handleResponse).catch(() => []); },
  async timeline() { return fetch(`${API_BASE}/timeline`).then(handleResponse).catch(() => ({ buckets: [] })); },
  async topUsers() { return fetch(`${API_BASE}/top-users`).then(handleResponse).catch(() => []); },
  async mode() { return fetch(`${API_BASE}/mode`).then(handleResponse); },
  async setMode(mode) {
    return fetch(`${API_BASE}/mode`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode })
    }).then(handleResponse);
  },
  async attack(type, target='http://127.0.0.1:8080') {
    return fetch(`${API_BASE}/demo/attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, target })
    }).then(handleResponse);
  },
  async reset() {
    return fetch(`${API_BASE}/demo/reset`, { method: 'POST' }).then(handleResponse);
  },
  reportUrl: `${API_BASE}/report.pdf`,
  exportUrl: (name) => `${API_BASE}/export/${name}`,
};
