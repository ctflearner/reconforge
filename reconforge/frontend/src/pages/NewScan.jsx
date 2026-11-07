import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchModules, createScanJSON, createScanMultipart, startScan } from '../api';

const TARGET_TYPES = [
  { value: 'url',              label: 'URL',           icon: 'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101', upload: false },
  { value: 'ip',               label: 'IP Address',    icon: 'M5.121 17.804A13.937 13.937 0 0112 16c2.5 0 4.847.655 6.879 1.804M15 10a3 3 0 11-6 0 3 3 0 016 0zm6 2a9 9 0 11-18 0 9 9 0 0118 0z', upload: false },
  { value: 'apk',              label: 'APK',           icon: 'M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z', upload: true },
  { value: 'thick_client',     label: 'Thick Client',  icon: 'M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z', upload: true },
  { value: 'active_directory', label: 'Active Dir.',   icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0z', upload: false },
];

export default function NewScan() {
  const navigate = useNavigate();
  const [modules, setModules] = useState([]);
  const [targetType, setTargetType] = useState('url');
  const [targetValue, setTargetValue] = useState('');
  const [file, setFile] = useState(null);
  const [scanName, setScanName] = useState('');
  const [selectedModules, setSelectedModules] = useState(new Set());
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchModules().then(mods => {
      setModules(mods);
      // Select all by default
      setSelectedModules(new Set(mods.map(m => m.name)));
    }).catch(e => setError(e.message));
  }, []);

  const isUpload = TARGET_TYPES.find(t => t.value === targetType)?.upload;

  // Group modules by category, filtered by target type
  const applicableModules = modules.filter(m =>
    m.target_types.includes(targetType)
  );
  const grouped = {};
  applicableModules.forEach(m => {
    if (!grouped[m.category]) grouped[m.category] = [];
    grouped[m.category].push(m);
  });

  function toggleModule(name) {
    setSelectedModules(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  }

  function selectAll() {
    setSelectedModules(new Set(applicableModules.map(m => m.name)));
  }

  function selectNone() {
    setSelectedModules(new Set());
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      let scan;
      const enabledList = [...selectedModules].filter(n => applicableModules.some(m => m.name === n));

      if (isUpload) {
        if (!file) { setError('File required'); setLoading(false); return; }
        const fd = new FormData();
        fd.append('target_type', targetType);
        fd.append('file', file);
        fd.append('name', scanName || `Scan: ${file.name}`);
        fd.append('enabled_modules', JSON.stringify(enabledList));
        scan = await createScanMultipart(fd);
      } else {
        if (!targetValue.trim()) { setError('Target value required'); setLoading(false); return; }
        scan = await createScanJSON({
          name: scanName || `Scan: ${targetValue.substring(0, 80)}`,
          target_type: targetType,
          target_value: targetValue.trim(),
          enabled_modules: enabledList,
        });
      }

      // Start the scan
      await startScan(scan.id);
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <h2 className="text-2xl font-bold">New Scan</h2>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target type selector */}
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-3">Target Type</label>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {TARGET_TYPES.map(tt => (
              <button
                key={tt.value}
                type="button"
                onClick={() => { setTargetType(tt.value); setTargetValue(''); setFile(null); }}
                className={`flex flex-col items-center gap-2 p-4 rounded-lg border transition-all ${
                  targetType === tt.value
                    ? 'bg-blue-600/20 border-blue-500 text-blue-400'
                    : 'bg-gray-800 border-gray-700 text-gray-400 hover:border-gray-600'
                }`}
              >
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={tt.icon} />
                </svg>
                <span className="text-xs font-medium">{tt.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Scan name */}
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-1">Scan Name (optional)</label>
          <input
            type="text"
            value={scanName}
            onChange={e => setScanName(e.target.value)}
            placeholder="My scan..."
            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
          />
        </div>

        {/* Target input */}
        {isUpload ? (
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Upload File</label>
            <div className="border-2 border-dashed border-gray-700 rounded-lg p-6 text-center hover:border-gray-600 transition-colors">
              <input
                type="file"
                onChange={e => setFile(e.target.files[0])}
                accept={targetType === 'apk' ? '.apk' : '*'}
                className="hidden"
                id="file-upload"
              />
              <label htmlFor="file-upload" className="cursor-pointer">
                <svg className="w-8 h-8 mx-auto text-gray-600 mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
                <p className="text-gray-400 text-sm">
                  {file ? file.name : 'Click to select file or drag and drop'}
                </p>
                {file && <p className="text-gray-600 text-xs mt-1">{(file.size / 1024 / 1024).toFixed(1)} MB</p>}
              </label>
            </div>
          </div>
        ) : (
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">
              {targetType === 'url' ? 'Target URL' : targetType === 'ip' ? 'Target IP' : 'Domain / DC'}
            </label>
            <input
              type="text"
              value={targetValue}
              onChange={e => setTargetValue(e.target.value)}
              placeholder={
                targetType === 'url' ? 'https://example.com'
                : targetType === 'ip' ? '192.168.1.1'
                : 'corp.example.com'
              }
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>
        )}

        {/* Module selection */}
        <div>
          <div className="flex items-center justify-between mb-3">
            <label className="text-sm font-medium text-gray-400">
              Modules ({selectedModules.size} / {applicableModules.length} selected)
            </label>
            <div className="flex gap-2">
              <button type="button" onClick={selectAll} className="text-xs text-blue-400 hover:text-blue-300">Select All</button>
              <span className="text-gray-600">|</span>
              <button type="button" onClick={selectNone} className="text-xs text-blue-400 hover:text-blue-300">Select None</button>
            </div>
          </div>

          <div className="space-y-4">
            {Object.entries(grouped).map(([category, mods]) => (
              <div key={category} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
                <h4 className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">{category}</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                  {mods.map(mod => (
                    <label
                      key={mod.name}
                      className={`flex items-center gap-2.5 p-2 rounded cursor-pointer hover:bg-gray-700/50 ${
                        selectedModules.has(mod.name) ? 'text-gray-200' : 'text-gray-500'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selectedModules.has(mod.name)}
                        onChange={() => toggleModule(mod.name)}
                        className="rounded bg-gray-700 border-gray-600 text-blue-500 focus:ring-blue-500"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{mod.display_name}</div>
                        <div className="text-xs text-gray-500 truncate">{mod.description}</div>
                      </div>
                      {mod.requires_api_key && (
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${mod.api_key_configured ? 'bg-green-500' : 'bg-red-500'}`}
                              title={mod.api_key_configured ? 'API key configured' : `Missing: ${mod.requires_api_key}`} />
                      )}
                    </label>
                  ))}
                </div>
              </div>
            ))}
          </div>
          {applicableModules.length === 0 && (
            <p className="text-gray-600 text-sm">No modules available for this target type.</p>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-900/30 border border-red-800 rounded-lg px-4 py-3 text-red-300 text-sm">
            {error}
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Starting scan...
            </>
          ) : (
            <>
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Start Scan
            </>
          )}
        </button>
      </form>
    </div>
  );
}
