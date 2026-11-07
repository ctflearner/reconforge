import React, { useEffect, useState } from 'react';
import { fetchFindings, fetchFindingStats, validateFinding } from '../api';
import FindingCard from '../components/FindingCard';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const VALIDATIONS = ['', 'pending', 'confirmed', 'false_positive', 'uncertain'];

export default function Findings() {
  const [findings, setFindings] = useState([]);
  const [stats, setStats] = useState(null);
  const [filters, setFilters] = useState({
    severity: '', category: '', module_name: '', validation_status: '', scan_id: '',
  });
  const [loading, setLoading] = useState(true);

  function loadFindings() {
    setLoading(true);
    const params = {};
    for (const [k, v] of Object.entries(filters)) {
      if (v) params[k] = v;
    }
    fetchFindings(params)
      .then(setFindings)
      .catch(() => {})
      .finally(() => setLoading(false));
  }

  useEffect(() => { loadFindings(); }, [filters]);
  useEffect(() => { fetchFindingStats().then(setStats).catch(() => {}); }, []);

  async function handleValidate(findingId, status, reason) {
    await validateFinding(findingId, status, reason);
    loadFindings();
    fetchFindingStats().then(setStats).catch(() => {});
  }

  function setFilter(key, value) {
    setFilters(prev => ({ ...prev, [key]: value }));
  }

  // Extract unique categories from stats
  const categories = stats ? ['', ...Object.keys(stats.by_category || {})] : [''];
  const modules = stats ? ['', ...Object.keys(stats.by_module || {})] : [''];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold">Findings</h2>
        <span className="text-gray-500 text-sm">{findings.length} results</span>
      </div>

      {/* Stats bar */}
      {stats && (
        <div className="flex gap-4 text-sm">
          <span className="text-gray-400">Total: <strong className="text-gray-200">{stats.total}</strong></span>
          <span className="text-red-400">Critical: {stats.by_severity?.critical || 0}</span>
          <span className="text-orange-400">High: {stats.by_severity?.high || 0}</span>
          <span className="text-yellow-400">Medium: {stats.by_severity?.medium || 0}</span>
          <span className="text-green-400">Low: {stats.by_severity?.low || 0}</span>
          <span className="text-gray-400">Info: {stats.by_severity?.info || 0}</span>
        </div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={filters.severity}
          onChange={e => setFilter('severity', e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All Severities</option>
          {SEVERITIES.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        <select
          value={filters.validation_status}
          onChange={e => setFilter('validation_status', e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All Statuses</option>
          {VALIDATIONS.filter(Boolean).map(s => (
            <option key={s} value={s}>{s.replace('_', ' ')}</option>
          ))}
        </select>

        <select
          value={filters.category}
          onChange={e => setFilter('category', e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All Categories</option>
          {categories.filter(Boolean).map(c => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>

        <select
          value={filters.module_name}
          onChange={e => setFilter('module_name', e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">All Modules</option>
          {modules.filter(Boolean).map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>

        <input
          type="number"
          placeholder="Scan ID"
          value={filters.scan_id}
          onChange={e => setFilter('scan_id', e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 w-28 focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Results */}
      {loading ? (
        <div className="text-center text-gray-500 py-8">Loading...</div>
      ) : findings.length === 0 ? (
        <div className="text-center text-gray-600 py-12">No findings match your filters</div>
      ) : (
        <div className="space-y-3">
          {findings.map(f => (
            <FindingCard key={f.id} finding={f} onValidate={handleValidate} />
          ))}
        </div>
      )}
    </div>
  );
}
