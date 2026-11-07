import React, { useState } from 'react';

const API_KEYS = [
  { key: 'shodan_api_key', label: 'Shodan', desc: 'Network intelligence and device search' },
  { key: 'virustotal_api_key', label: 'VirusTotal', desc: 'Malware and URL scanning' },
  { key: 'securitytrails_api_key', label: 'SecurityTrails', desc: 'DNS and domain intelligence' },
  { key: 'censys_api_id', label: 'Censys API ID', desc: 'Internet-wide scanning data' },
  { key: 'censys_api_secret', label: 'Censys API Secret', desc: 'Censys authentication secret' },
  { key: 'hunter_api_key', label: 'Hunter.io', desc: 'Email discovery and verification' },
  { key: 'github_token', label: 'GitHub Token', desc: 'Code and repository search' },
  { key: 'google_api_key', label: 'Google API Key', desc: 'Custom search engine' },
  { key: 'google_cse_id', label: 'Google CSE ID', desc: 'Custom search engine ID' },
  { key: 'abuseipdb_api_key', label: 'AbuseIPDB', desc: 'IP reputation and abuse reports' },
  { key: 'whoisxml_api_key', label: 'WhoisXML', desc: 'WHOIS and DNS lookup' },
];

export default function Settings() {
  const [values, setValues] = useState(() => {
    const saved = {};
    API_KEYS.forEach(k => { saved[k.key] = ''; });
    return saved;
  });
  const [testing, setTesting] = useState({});
  const [testResults, setTestResults] = useState({});
  const [saved, setSaved] = useState(false);

  function updateValue(key, val) {
    setValues(prev => ({ ...prev, [key]: val }));
    setSaved(false);
  }

  async function testKey(key) {
    setTesting(prev => ({ ...prev, [key]: true }));
    setTestResults(prev => ({ ...prev, [key]: null }));

    try {
      // Simple validation — check if key is non-empty and has reasonable format
      const val = values[key].trim();
      if (!val) {
        setTestResults(prev => ({ ...prev, [key]: { ok: false, msg: 'Key is empty' } }));
        return;
      }
      // For now just validate format
      if (val.length < 8) {
        setTestResults(prev => ({ ...prev, [key]: { ok: false, msg: 'Key too short' } }));
        return;
      }
      setTestResults(prev => ({ ...prev, [key]: { ok: true, msg: 'Format valid' } }));
    } catch (err) {
      setTestResults(prev => ({ ...prev, [key]: { ok: false, msg: err.message } }));
    } finally {
      setTesting(prev => ({ ...prev, [key]: false }));
    }
  }

  function handleSave() {
    // Build .env content
    const lines = [];
    API_KEYS.forEach(({ key }) => {
      const val = values[key].trim();
      if (val) {
        lines.push(`RF_${key.toUpperCase()}=${val}`);
      }
    });

    // Create downloadable .env file
    const content = lines.join('\n') + '\n';
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '.env';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    setSaved(true);
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <h2 className="text-2xl font-bold">Settings</h2>
      <p className="text-gray-500 text-sm">
        Configure API keys for OSINT modules. Keys are stored in a <code className="text-gray-400">.env</code> file
        in the project root with <code className="text-gray-400">RF_</code> prefix.
      </p>

      <div className="space-y-4">
        {API_KEYS.map(({ key, label, desc }) => {
          const result = testResults[key];
          return (
            <div key={key} className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <div>
                  <label className="text-sm font-medium text-gray-300">{label}</label>
                  <p className="text-xs text-gray-500">{desc}</p>
                </div>
                <button
                  onClick={() => testKey(key)}
                  disabled={testing[key]}
                  className="text-xs px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded transition-colors disabled:opacity-50"
                >
                  {testing[key] ? 'Testing...' : 'Test'}
                </button>
              </div>
              <div className="flex gap-2">
                <input
                  type="password"
                  value={values[key]}
                  onChange={e => updateValue(key, e.target.value)}
                  placeholder={`Enter ${label} key...`}
                  className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-300 font-mono placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>
              {result && (
                <p className={`text-xs mt-2 ${result.ok ? 'text-green-400' : 'text-red-400'}`}>
                  {result.ok ? 'OK' : 'Error'}: {result.msg}
                </p>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex items-center gap-4">
        <button
          onClick={handleSave}
          className="bg-blue-600 hover:bg-blue-700 text-white font-medium px-6 py-2.5 rounded-lg transition-colors"
        >
          Download .env File
        </button>
        {saved && (
          <span className="text-green-400 text-sm">
            Downloaded! Place the .env file in the ReconForge root directory and restart the server.
          </span>
        )}
      </div>

      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-sm text-gray-500">
        <h4 className="font-medium text-gray-400 mb-2">Manual Setup</h4>
        <p>Create a <code className="text-gray-400">.env</code> file in the project root:</p>
        <pre className="bg-gray-900 rounded p-3 mt-2 text-xs overflow-x-auto text-gray-400">
{`RF_SHODAN_API_KEY=your_key_here
RF_VIRUSTOTAL_API_KEY=your_key_here
RF_GITHUB_TOKEN=ghp_xxxxxxxxxxxx
# ... etc`}
        </pre>
      </div>
    </div>
  );
}
