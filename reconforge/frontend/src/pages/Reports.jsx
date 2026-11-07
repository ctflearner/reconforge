import React, { useEffect, useState } from 'react';
import { fetchScans, generateReport } from '../api';

const FORMATS = [
  { value: 'html', label: 'HTML', desc: 'Interactive web report with dark theme' },
  { value: 'pdf', label: 'PDF', desc: 'Printable document (requires weasyprint)' },
  { value: 'json', label: 'JSON', desc: 'Machine-readable structured data' },
  { value: 'md', label: 'Markdown', desc: 'Plain text report for docs/repos' },
  { value: 'csv', label: 'CSV', desc: 'Spreadsheet-compatible findings export' },
];

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState('');
  const [format, setFormat] = useState('html');
  const [includeRaw, setIncludeRaw] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchScans({ limit: 100, status: 'completed' }).then(setScans).catch(() => {});
  }, []);

  async function handleGenerate() {
    if (!selectedScanId) { setError('Select a scan'); return; }
    setError('');
    setSuccess('');
    setGenerating(true);

    try {
      const res = await generateReport(parseInt(selectedScanId), format, { includeRaw });

      // Download the file
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);

      // Get filename from Content-Disposition header or generate one
      const cd = res.headers.get('content-disposition') || '';
      const match = cd.match(/filename=(.+)/);
      const filename = match ? match[1] : `report_${selectedScanId}.${format === 'markdown' ? 'md' : format}`;

      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      setSuccess(`Report generated and downloaded: ${filename}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setGenerating(false);
    }
  }

  const selectedScan = scans.find(s => s.id === parseInt(selectedScanId));

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h2 className="text-2xl font-bold">Generate Report</h2>

      {/* Scan selector */}
      <div>
        <label className="block text-sm font-medium text-gray-400 mb-2">Select Scan</label>
        <select
          value={selectedScanId}
          onChange={e => setSelectedScanId(e.target.value)}
          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-gray-300 focus:outline-none focus:border-blue-500"
        >
          <option value="">Choose a completed scan...</option>
          {scans.map(s => (
            <option key={s.id} value={s.id}>
              {s.name} - {s.target_value.substring(0, 40)} ({s.total_findings} findings)
            </option>
          ))}
        </select>
      </div>

      {/* Scan summary */}
      {selectedScan && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 grid grid-cols-2 sm:grid-cols-4 gap-4 text-center">
          <div>
            <div className="text-lg font-bold text-gray-200">{selectedScan.total_findings}</div>
            <div className="text-xs text-gray-500">Total Findings</div>
          </div>
          <div>
            <div className="text-lg font-bold text-red-400">{selectedScan.critical_count}</div>
            <div className="text-xs text-gray-500">Critical</div>
          </div>
          <div>
            <div className="text-lg font-bold text-orange-400">{selectedScan.high_count}</div>
            <div className="text-xs text-gray-500">High</div>
          </div>
          <div>
            <div className="text-lg font-bold" style={{ color: selectedScan.risk_score >= 50 ? '#ea580c' : '#16a34a' }}>
              {selectedScan.risk_score.toFixed(0)}
            </div>
            <div className="text-xs text-gray-500">Risk Score</div>
          </div>
        </div>
      )}

      {/* Format selector */}
      <div>
        <label className="block text-sm font-medium text-gray-400 mb-3">Report Format</label>
        <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          {FORMATS.map(f => (
            <button
              key={f.value}
              type="button"
              onClick={() => setFormat(f.value)}
              className={`p-3 rounded-lg border text-left transition-all ${
                format === f.value
                  ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                  : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
              }`}
            >
              <div className="font-semibold text-sm">{f.label}</div>
              <div className="text-xs text-gray-500 mt-1">{f.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Options */}
      <div className="space-y-3">
        <label className="flex items-center gap-3 cursor-pointer">
          <input
            type="checkbox"
            checked={includeRaw}
            onChange={e => setIncludeRaw(e.target.checked)}
            className="rounded bg-gray-700 border-gray-600 text-blue-500 focus:ring-blue-500"
          />
          <span className="text-sm text-gray-300">Include raw module data</span>
        </label>
      </div>

      {/* Error / Success */}
      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg px-4 py-3 text-red-300 text-sm">{error}</div>
      )}
      {success && (
        <div className="bg-green-900/30 border border-green-800 rounded-lg px-4 py-3 text-green-300 text-sm">{success}</div>
      )}

      {/* Generate button */}
      <button
        onClick={handleGenerate}
        disabled={generating || !selectedScanId}
        className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
      >
        {generating ? (
          <>
            <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Generating...
          </>
        ) : (
          <>
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Generate & Download
          </>
        )}
      </button>
    </div>
  );
}
