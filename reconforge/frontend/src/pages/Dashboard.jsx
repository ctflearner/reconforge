import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { fetchDashboard, fetchFindingStats } from '../api';
import RiskMeter from '../components/RiskMeter';

const SEV_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#16a34a',
  info: '#6b7280',
};

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [findingStats, setFindingStats] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboard()
      .then(setStats)
      .catch(e => setError(e.message));
    fetchFindingStats()
      .then(setFindingStats)
      .catch(() => {});
  }, []);

  if (error) {
    return (
      <div className="text-center py-12">
        <p className="text-red-400 mb-2">Failed to load dashboard</p>
        <p className="text-gray-500 text-sm">{error}</p>
      </div>
    );
  }

  if (!stats) {
    return <div className="text-center py-12 text-gray-500">Loading dashboard...</div>;
  }

  // Severity chart data
  const sevData = findingStats
    ? Object.entries(findingStats.by_severity || {}).map(([k, v]) => ({ name: k, count: v, fill: SEV_COLORS[k] || '#6b7280' }))
    : [];

  // Category chart data
  const catData = findingStats
    ? Object.entries(findingStats.by_category || {}).slice(0, 12).map(([k, v]) => ({ name: k, count: v }))
    : [];

  // Average risk score from recent scans
  const avgRisk = stats.recent_scans.length
    ? stats.recent_scans.reduce((sum, s) => sum + (s.risk_score || 0), 0) / stats.recent_scans.length
    : 0;

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Dashboard</h2>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
        <StatCard label="Total Scans" value={stats.total_scans} />
        <StatCard label="Active" value={stats.active_scans} color="text-blue-400" />
        <StatCard label="Findings" value={stats.total_findings} />
        <StatCard label="Critical" value={stats.critical_findings} color="text-red-400" />
        <StatCard label="High" value={stats.high_findings} color="text-orange-400" />
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 flex items-center justify-center">
          <RiskMeter score={avgRisk} size={80} />
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Findings by severity */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-400 mb-4">Findings by Severity</h3>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={sevData}>
                <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {sevData.map((entry, i) => (
                    <Cell key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-center text-gray-600 py-8">No findings data yet</div>
          )}
        </div>

        {/* Findings by category */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
          <h3 className="text-sm font-semibold text-gray-400 mb-4">Findings by Category</h3>
          {catData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={catData} layout="vertical">
                <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <YAxis dataKey="name" type="category" width={100} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                  labelStyle={{ color: '#e2e8f0' }}
                />
                <Bar dataKey="count" fill="#3b82f6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-center text-gray-600 py-8">No category data yet</div>
          )}
        </div>
      </div>

      {/* Recent scans */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <h3 className="text-sm font-semibold text-gray-400">Recent Scans</h3>
          <Link to="/scans/new" className="text-xs text-blue-400 hover:text-blue-300">+ New Scan</Link>
        </div>
        {stats.recent_scans.length === 0 ? (
          <div className="text-center text-gray-600 py-8">
            No scans yet. <Link to="/scans/new" className="text-blue-400 hover:underline">Create one</Link>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-500 text-xs uppercase tracking-wide">
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">Target</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-left px-4 py-2">Risk</th>
                <th className="text-left px-4 py-2">Findings</th>
                <th className="text-left px-4 py-2">Date</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_scans.map((scan) => (
                <tr key={scan.id} className="border-t border-gray-700/50 hover:bg-gray-700/30 transition-colors">
                  <td className="px-4 py-2.5">
                    <Link to={`/scans/${scan.id}`} className="text-blue-400 hover:underline">{scan.name}</Link>
                  </td>
                  <td className="px-4 py-2.5 text-gray-400 font-mono text-xs">{scan.target_value.substring(0, 40)}</td>
                  <td className="px-4 py-2.5">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-2.5 font-mono">{scan.risk_score.toFixed(0)}</td>
                  <td className="px-4 py-2.5">
                    <span className="text-gray-300">{scan.total_findings}</span>
                    {scan.critical_count > 0 && <span className="text-red-400 ml-1">({scan.critical_count}C)</span>}
                  </td>
                  <td className="px-4 py-2.5 text-gray-500 text-xs">{new Date(scan.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function StatCard({ label, value, color = 'text-gray-100' }) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-gray-500 uppercase tracking-wide mt-1">{label}</div>
    </div>
  );
}

function StatusBadge({ status }) {
  const colors = {
    pending: 'bg-gray-600 text-gray-200',
    running: 'bg-blue-600 text-blue-100',
    validating: 'bg-purple-600 text-purple-100',
    correlating: 'bg-indigo-600 text-indigo-100',
    completed: 'bg-green-600 text-green-100',
    failed: 'bg-red-600 text-red-100',
    cancelled: 'bg-yellow-600 text-yellow-100',
  };
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded ${colors[status] || colors.pending}`}>
      {status}
    </span>
  );
}
