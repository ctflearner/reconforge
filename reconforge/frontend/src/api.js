/**
 * ReconForge API client — fetch wrapper for all endpoints + WebSocket.
 */

const BASE = '';  // Vite proxy handles /api -> backend

async function request(url, options = {}) {
  const res = await fetch(`${BASE}${url}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text();
    let msg;
    try { msg = JSON.parse(body).detail; } catch { msg = body; }
    throw new Error(msg || `HTTP ${res.status}`);
  }
  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res;
}

// ── Dashboard ───────────────────────────────────────────────────────────
export function fetchDashboard() {
  return request('/api/dashboard');
}

export function fetchModules() {
  return request('/api/modules');
}

// ── Scans ───────────────────────────────────────────────────────────────
export function fetchScans({ offset = 0, limit = 50, status } = {}) {
  const params = new URLSearchParams({ offset, limit });
  if (status) params.set('status', status);
  return request(`/api/scans?${params}`);
}

export function fetchScan(id) {
  return request(`/api/scans/${id}`);
}

export function createScanJSON(data) {
  return request('/api/scans/json', {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export function createScanMultipart(formData) {
  return fetch(`${BASE}/api/scans`, {
    method: 'POST',
    body: formData,  // browser sets multipart boundary
  }).then(async res => {
    if (!res.ok) {
      const body = await res.text();
      let msg;
      try { msg = JSON.parse(body).detail; } catch { msg = body; }
      throw new Error(msg || `HTTP ${res.status}`);
    }
    return res.json();
  });
}

export function startScan(id) {
  return request(`/api/scans/${id}/start`, { method: 'POST' });
}

export function cancelScan(id) {
  return request(`/api/scans/${id}/cancel`, { method: 'POST' });
}

export function deleteScan(id) {
  return request(`/api/scans/${id}`, { method: 'DELETE' });
}

// ── Findings ────────────────────────────────────────────────────────────
export function fetchFindings(params = {}) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') sp.set(k, v);
  }
  return request(`/api/findings?${sp}`);
}

export function fetchFinding(id) {
  return request(`/api/findings/${id}`);
}

export function validateFinding(id, status, reason = '') {
  const params = new URLSearchParams({ status, reason });
  return request(`/api/findings/${id}/validate?${params}`, { method: 'PATCH' });
}

export function fetchFindingStats(scanId) {
  const params = scanId ? `?scan_id=${scanId}` : '';
  return request(`/api/findings/stats${params}`);
}

// ── Reports ─────────────────────────────────────────────────────────────
export async function generateReport(scanId, format = 'html', opts = {}) {
  const res = await fetch(`${BASE}/api/reports/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scan_id: scanId,
      format,
      include_raw: opts.includeRaw || false,
      include_screenshots: opts.includeScreenshots || true,
    }),
  });
  if (!res.ok) throw new Error(`Report generation failed: HTTP ${res.status}`);
  return res;
}

// ── WebSocket ───────────────────────────────────────────────────────────
export function connectScanWS(scanId, onMessage) {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${proto}//${window.location.host}/ws/scan/${scanId}`;
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log(`[WS] Connected to scan ${scanId}`);
  };

  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data);
      onMessage(data);
    } catch (e) {
      console.warn('[WS] Parse error:', e);
    }
  };

  ws.onerror = (err) => {
    console.error('[WS] Error:', err);
  };

  ws.onclose = () => {
    console.log(`[WS] Disconnected from scan ${scanId}`);
  };

  // Heartbeat
  const interval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send('ping');
    }
  }, 30000);

  return {
    ws,
    close: () => {
      clearInterval(interval);
      ws.close();
    },
  };
}
