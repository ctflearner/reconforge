import React, { useEffect, useState } from 'react';
import { fetchScans, fetchScan } from '../api';
import AssetGraph from '../components/AssetGraph';

export default function Assets() {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [assets, setAssets] = useState([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchScans({ limit: 100, status: 'completed' }).then(setScans).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedScanId) { setAssets([]); return; }
    setLoading(true);
    fetchScan(selectedScanId)
      .then(scan => setAssets(scan.assets || []))
      .catch(() => setAssets([]))
      .finally(() => setLoading(false));
  }, [selectedScanId]);

  const filtered = search
    ? assets.filter(a =>
        a.value.toLowerCase().includes(search.toLowerCase()) ||
        a.asset_type.toLowerCase().includes(search.toLowerCase()) ||
        (a.source_module || '').toLowerCase().includes(search.toLowerCase())
      )
    : assets;

  // Group by type
  const grouped = {};
  filtered.forEach(a => {
    if (!grouped[a.asset_type]) grouped[a.asset_type] = [];
    grouped[a.asset_type].push(a);
  });

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold">Asset Inventory</h2>

      {/* Controls */}
      <div className="flex flex-wrap gap-3">
        <select
          value={selectedScanId}
          onChange={e => setSelectedScanId(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 min-w-[200px] focus:outline-none focus:border-blue-500"
        >
          <option value="">Select a scan...</option>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              {s.name} ({s.target_value.substring(0, 30)})
            </option>
          ))}
        </select>

        <input
          type="text"
          placeholder="Search assets..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-300 flex-1 min-w-[200px] focus:outline-none focus:border-blue-500"
        />
      </div>

      {!selectedScanId ? (
        <div className="text-center text-gray-600 py-12">Select a scan to view its assets</div>
      ) : loading ? (
        <div className="text-center text-gray-500 py-8">Loading assets...</div>
      ) : filtered.length === 0 ? (
        <div className="text-center text-gray-600 py-12">No assets found</div>
      ) : (
        <div className="space-y-6">
          {/* Graph visualization */}
          <AssetGraph assets={filtered} />

          {/* Summary */}
          <div className="flex flex-wrap gap-2">
            {Object.entries(grouped).map(([type, items]) => (
              <span
                key={type}
                className="bg-gray-800 border border-gray-700 rounded-full px-3 py-1 text-xs text-gray-300"
              >
                {type}: {items.length}
              </span>
            ))}
          </div>

          {/* Grouped tables */}
          {Object.entries(grouped).sort((a, b) => b[1].length - a[1].length).map(([type, items]) => (
            <div key={type} className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <div className="px-4 py-2.5 border-b border-gray-700 flex items-center justify-between">
                <h3 className="text-sm font-semibold text-gray-300 capitalize">{type}</h3>
                <span className="text-xs text-gray-500">{items.length} assets</span>
              </div>
              <div className="overflow-x-auto max-h-80 overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-gray-800">
                    <tr className="text-gray-500 text-xs uppercase tracking-wide">
                      <th className="text-left px-4 py-2">Value</th>
                      <th className="text-left px-4 py-2">Source</th>
                      <th className="text-left px-4 py-2">Status</th>
                      <th className="text-left px-4 py-2">Metadata</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map(a => (
                      <tr key={a.id} className="border-t border-gray-700/50 hover:bg-gray-700/30">
                        <td className="px-4 py-2 font-mono text-xs text-gray-300 break-all">{a.value}</td>
                        <td className="px-4 py-2 text-xs text-gray-500">{a.source_module || 'N/A'}</td>
                        <td className="px-4 py-2">
                          <span className={`inline-block w-2 h-2 rounded-full ${a.is_alive ? 'bg-green-500' : 'bg-gray-600'}`} />
                        </td>
                        <td className="px-4 py-2 text-xs text-gray-600 max-w-xs truncate font-mono">
                          {a.metadata_ && Object.keys(a.metadata_).length > 0
                            ? JSON.stringify(a.metadata_).substring(0, 100)
                            : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
