import React, { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { fetchScan, cancelScan, deleteScan } from '../api';
import ScanProgress from '../components/ScanProgress';
import RiskMeter from '../components/RiskMeter';
import FindingCard from '../components/FindingCard';
import AssetGraph from '../components/AssetGraph';

const TABS = ['Findings', 'Assets', 'Correlations', 'Modules', 'Raw'];

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [tab, setTab] = useState('Findings');
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const load = useCallback(() => {
    fetchScan(id).then(setScan).catch(e => setError(e.message));
  }, [id]);

  useEffect(() => { load(); }, [load, refreshKey]);

  // Auto-refresh while scan is active
  useEffect(() => {
    if (!scan) return;
    const active = ['running', 'validating', 'correlating', 'pending'].includes(scan.status);
    if (!active) return;
    const timer = setInterval(() => setRefreshKey(k => k + 1), 3000);
    return () => clearInterval(timer);
  }, [scan?.status]);

  const handleWSUpdate = useCallback((data) => {
    if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
      // Reload full data
      setTimeout(load, 500);
    }
  }, [load]);

  if (error) return <div className="text-center py-12 text-red-400">{error}</div>;
  if (!scan) return <div className="text-center py-12 text-gray-500">Loading scan...</div>;

  const isActive = ['running', 'validating', 'correlating'].includes(scan.status);
  const isComplete = scan.status === 'completed';

  async function handleCancel() {
    if (!confirm('Cancel this scan?')) return;
    await cancelScan(id);
    load();
  }

  async function handleDelete() {
    if (!confirm('Delete this scan and all its data?')) return;
    await deleteScan(id);
    navigate('/');
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-2xl font-bold">{scan.name}</h2>
          <p className="text-gray-500 text-sm font-mono mt-1">{scan.target_value}</p>
          <div className="flex gap-3 mt-2 text-xs text-gray-500">
            <span>Type: {scan.target_type}</span>
            {scan.started_at && <span>Started: {new Date(scan.started_at).toLocaleString()}</span>}
            {scan.completed_at && <span>Completed: {new Date(scan.completed_at).toLocaleString()}</span>}
          </div>
        </div>
        <div className="flex items-center gap-3">
          {isActive && (
            <button
              onClick={handleCancel}
              className="px-4 py-2 text-sm bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg transition-colors"
            >
              Cancel
            </button>
          )}
          <button
            onClick={handleDelete}
            className="px-4 py-2 text-sm bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg border border-red-800 transition-colors"
          >
            Delete
          </button>
          <RiskMeter score={scan.risk_score} size={80} />
        </div>
      </div>

      {/* Progress bar */}
      <ScanProgress
        scanId={parseInt(id)}
        initialStatus={scan.status}
        initialProgress={scan.progress_pct}
        initialModule={scan.current_module}
        onUpdate={handleWSUpdate}
      />

      {/* Error message */}
      {scan.error_message && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg px-4 py-3 text-red-300 text-sm">
          {scan.error_message}
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        <MiniStat label="Critical" value={scan.critical_count} color="text-red-400" />
        <MiniStat label="High" value={scan.high_count} color="text-orange-400" />
        <MiniStat label="Medium" value={scan.medium_count} color="text-yellow-400" />
        <MiniStat label="Low" value={scan.low_count} color="text-green-400" />
        <MiniStat label="Info" value={scan.info_count} color="text-gray-400" />
        <MiniStat label="Total" value={scan.total_findings} />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-700">
        <div className="flex gap-1">
          {TABS.map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === t
                  ? 'border-blue-500 text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              {t}
              {t === 'Findings' && scan.findings && ` (${scan.findings.length})`}
              {t === 'Assets' && scan.assets && ` (${scan.assets.length})`}
              {t === 'Correlations' && scan.correlations && ` (${scan.correlations.length})`}
              {t === 'Modules' && scan.module_results && ` (${scan.module_results.length})`}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      {tab === 'Findings' && <FindingsTab findings={scan.findings || []} />}
      {tab === 'Assets' && <AssetsTab assets={scan.assets || []} />}
      {tab === 'Correlations' && <CorrelationsTab correlations={scan.correlations || []} />}
      {tab === 'Modules' && <ModulesTab modules={scan.module_results || []} />}
      {tab === 'Raw' && <RawTab scan={scan} />}
    </div>
  );
}

function MiniStat({ label, value, color = 'text-gray-200' }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 text-center">
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}

function FindingsTab({ findings }) {
  if (!findings.length) return <Empty msg="No findings yet" />;
  // Sort by severity
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) => (order[a.severity] || 5) - (order[b.severity] || 5));
  return (
    <div className="space-y-3">
      {sorted.map(f => <FindingCard key={f.id} finding={f} />)}
    </div>
  );
}

function AssetsTab({ assets }) {
  const [search, setSearch] = useState('');
  if (!assets.length) return <Empty msg="No assets discovered" />;

  const filtered = search
    ? assets.filter(a => a.value.toLowerCase().includes(search.toLowerCase()) || a.asset_type.toLowerCase().includes(search.toLowerCase()))
    : assets;

  // Group by type
  const grouped = {};
  filtered.forEach(a => {
    if (!grouped[a.asset_type]) grouped[a.asset_type] = [];
    grouped[a.asset_type].push(a);
  });

  return (
    <div className="space-y-4">
      <input
        type="text"
        value={search}
        onChange={e => setSearch(e.target.value)}
        placeholder="Search assets..."
        className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
      />
      <AssetGraph assets={filtered} />
      {Object.entries(grouped).map(([type, items]) => (
        <div key={type} className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-2 border-b border-gray-700 flex items-center justify-between">
            <h4 className="text-sm font-semibold text-gray-300">{type}</h4>
            <span className="text-xs text-gray-500">{items.length}</span>
          </div>
          <div className="max-h-64 overflow-y-auto">
            <table className="w-full text-sm">
              <tbody>
                {items.map(a => (
                  <tr key={a.id} className="border-t border-gray-700/50 hover:bg-gray-700/30">
                    <td className="px-4 py-2 font-mono text-xs text-gray-300">{a.value}</td>
                    <td className="px-4 py-2 text-xs text-gray-500">{a.source_module || 'N/A'}</td>
                    <td className="px-4 py-2">
                      <span className={`inline-block w-2 h-2 rounded-full ${a.is_alive ? 'bg-green-500' : 'bg-gray-600'}`} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}

function CorrelationsTab({ correlations }) {
  if (!correlations.length) return <Empty msg="No attack chains identified" />;
  const sevColors = {
    critical: 'border-red-500 bg-red-900/20',
    high: 'border-orange-500 bg-orange-900/20',
    medium: 'border-yellow-500 bg-yellow-900/20',
    low: 'border-green-500 bg-green-900/20',
    info: 'border-gray-500 bg-gray-900/20',
  };
  return (
    <div className="space-y-3">
      {correlations.map(c => {
        const sev = c.combined_severity || 'info';
        return (
          <div key={c.id} className={`border-l-4 rounded-lg p-4 ${sevColors[sev] || sevColors.info}`}>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-xs font-bold uppercase text-gray-400">{sev}</span>
              <h4 className="font-semibold text-gray-200">{c.title}</h4>
              {c.combined_cvss && <span className="text-xs font-mono text-gray-500">CVSS {c.combined_cvss}</span>}
            </div>
            <p className="text-sm text-gray-400">{c.description}</p>
            <p className="text-xs text-gray-600 mt-2">
              Chain: {c.chain_type} | Linked findings: {(c.source_findings || []).length}
            </p>
          </div>
        );
      })}
    </div>
  );
}

function ModulesTab({ modules }) {
  if (!modules.length) return <Empty msg="No module results" />;
  const statusColors = {
    completed: 'text-green-400',
    error: 'text-red-400',
    timeout: 'text-yellow-400',
    skipped: 'text-gray-500',
    pending: 'text-gray-500',
    running: 'text-blue-400',
  };
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-gray-500 text-xs uppercase tracking-wide border-b border-gray-700">
            <th className="text-left px-4 py-2">Module</th>
            <th className="text-left px-4 py-2">Status</th>
            <th className="text-left px-4 py-2">Duration</th>
            <th className="text-left px-4 py-2">Findings</th>
            <th className="text-left px-4 py-2">Assets</th>
            <th className="text-left px-4 py-2">Error</th>
          </tr>
        </thead>
        <tbody>
          {modules.map(m => (
            <tr key={m.id} className="border-t border-gray-700/50 hover:bg-gray-700/30">
              <td className="px-4 py-2 font-medium">{m.module_name}</td>
              <td className={`px-4 py-2 ${statusColors[m.status] || 'text-gray-400'}`}>{m.status}</td>
              <td className="px-4 py-2 font-mono text-gray-400">{m.duration_secs ? `${m.duration_secs.toFixed(1)}s` : '-'}</td>
              <td className="px-4 py-2">{m.findings_count}</td>
              <td className="px-4 py-2">{m.assets_count}</td>
              <td className="px-4 py-2 text-red-400 text-xs max-w-xs truncate">{m.error || ''}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RawTab({ scan }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
      <pre className="text-xs text-gray-400 overflow-x-auto whitespace-pre-wrap">
        {JSON.stringify(scan, null, 2)}
      </pre>
    </div>
  );
}

function Empty({ msg }) {
  return <div className="text-center text-gray-600 py-8">{msg}</div>;
}
