import { useState, useEffect } from "react";
import { api } from "../api.js";

export default function Results() {
  const [folders, setFolders] = useState([]);
  const [selected, setSelected] = useState(null);
  const [files, setFiles] = useState([]);
  const [preview, setPreview] = useState(null);
  const [previewContent, setPreviewContent] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => { loadFolders(); }, []);

  async function loadFolders() {
    setLoading(true);
    try {
      const resp = await fetch("/api/results");
      const data = await resp.json();
      setFolders(data);
    } catch (e) {
      console.error("Failed to load results:", e);
    }
    setLoading(false);
  }

  async function selectFolder(scanId) {
    setSelected(scanId);
    setPreview(null);
    setPreviewContent("");
    try {
      const resp = await fetch(`/api/results/${scanId}`);
      setFiles(await resp.json());
    } catch (e) {
      console.error(e);
    }
  }

  async function viewFile(scanId, filename) {
    setPreview(filename);
    try {
      const resp = await fetch(`/api/results/${scanId}/${filename}`);
      const text = await resp.text();
      if (filename.endsWith(".json")) {
        try { setPreviewContent(JSON.stringify(JSON.parse(text), null, 2)); }
        catch { setPreviewContent(text); }
      } else {
        setPreviewContent(text);
      }
    } catch (e) {
      setPreviewContent("Error loading file: " + e.message);
    }
  }

  async function downloadZip(scanId) {
    window.open(`/api/results/${scanId}/download/zip`, "_blank");
  }

  async function deleteFolder(scanId) {
    if (!confirm(`Delete all results for scan ${scanId}? This cannot be undone.`)) return;
    await fetch(`/api/results/${scanId}`, { method: "DELETE" });
    setFolders(folders.filter(f => f.scan_id !== scanId));
    if (selected === scanId) {
      setSelected(null);
      setFiles([]);
      setPreview(null);
    }
  }

  async function deleteFile(scanId, filename) {
    if (!confirm(`Delete ${filename}?`)) return;
    await fetch(`/api/results/${scanId}/${filename}`, { method: "DELETE" });
    setFiles(files.filter(f => f.name !== filename));
    if (preview === filename) {
      setPreview(null);
      setPreviewContent("");
    }
  }

  function formatBytes(b) {
    if (b < 1024) return b + " B";
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + " KB";
    return (b / (1024 * 1024)).toFixed(1) + " MB";
  }

  function riskColor(score) {
    if (score >= 75) return "text-red-400";
    if (score >= 50) return "text-orange-400";
    if (score >= 25) return "text-yellow-400";
    return "text-green-400";
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-white">Saved Results</h1>
        <button onClick={loadFolders} className="px-3 py-1.5 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 text-sm">
          Refresh
        </button>
      </div>

      {loading ? (
        <p className="text-gray-400">Loading results...</p>
      ) : folders.length === 0 ? (
        <div className="bg-gray-800 rounded-lg p-8 text-center text-gray-400">
          <p className="text-lg">No saved results yet.</p>
          <p className="text-sm mt-2">Results are automatically saved when a scan completes.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left: Folder list */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Scan Results ({folders.length})</h2>
            {folders.map(f => (
              <div
                key={f.scan_id}
                className={`p-4 rounded-lg cursor-pointer border transition-colors ${
                  selected === f.scan_id
                    ? "bg-blue-900/30 border-blue-500"
                    : "bg-gray-800 border-gray-700 hover:border-gray-500"
                }`}
                onClick={() => selectFolder(f.scan_id)}
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1 min-w-0">
                    <h3 className="text-white font-medium truncate">{f.scan_name || `Scan #${f.scan_id}`}</h3>
                    <p className="text-gray-400 text-sm truncate mt-0.5">{f.target || "—"}</p>
                  </div>
                  {f.risk_score != null && (
                    <span className={`text-lg font-bold ml-2 ${riskColor(f.risk_score)}`}>
                      {f.risk_score.toFixed(0)}
                    </span>
                  )}
                </div>
                <div className="flex justify-between items-center mt-2 text-xs text-gray-500">
                  <span>{f.findings_count != null ? `${f.findings_count} findings` : ""}</span>
                  <span>{f.files.length} files • {formatBytes(f.total_size_bytes)}</span>
                </div>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={(e) => { e.stopPropagation(); downloadZip(f.scan_id); }}
                    className="px-2 py-1 bg-blue-600 text-white text-xs rounded hover:bg-blue-500"
                  >
                    Download ZIP
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); deleteFolder(f.scan_id); }}
                    className="px-2 py-1 bg-red-600/20 text-red-400 text-xs rounded hover:bg-red-600/40"
                  >
                    Delete
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Middle: File list */}
          <div className="space-y-3">
            {selected ? (
              <>
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">
                  Files — Scan #{selected}
                </h2>
                {files.map(f => (
                  <div
                    key={f.name}
                    className={`flex items-center justify-between p-3 rounded-lg cursor-pointer border ${
                      preview === f.name
                        ? "bg-gray-700 border-blue-500"
                        : "bg-gray-800 border-gray-700 hover:border-gray-500"
                    }`}
                    onClick={() => viewFile(selected, f.name)}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${
                        f.is_json ? "bg-yellow-900/50 text-yellow-400" : "bg-blue-900/50 text-blue-400"
                      }`}>
                        {f.is_json ? "JSON" : "MD"}
                      </span>
                      <span className="text-gray-200 truncate">{f.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-gray-500 text-xs">{formatBytes(f.size_bytes)}</span>
                      <button
                        onClick={(e) => { e.stopPropagation(); deleteFile(selected, f.name); }}
                        className="text-red-400 hover:text-red-300 text-xs"
                      >
                        ✕
                      </button>
                    </div>
                  </div>
                ))}
              </>
            ) : (
              <p className="text-gray-500 text-center mt-8">Select a scan to view its result files.</p>
            )}
          </div>

          {/* Right: Preview */}
          <div className="space-y-3">
            {preview ? (
              <>
                <div className="flex justify-between items-center">
                  <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">{preview}</h2>
                  <a
                    href={`/api/results/${selected}/${preview}`}
                    target="_blank"
                    className="text-xs text-blue-400 hover:text-blue-300"
                  >
                    Open raw
                  </a>
                </div>
                <pre className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-xs text-gray-300 overflow-auto max-h-[75vh] whitespace-pre-wrap">
                  {previewContent}
                </pre>
              </>
            ) : (
              <p className="text-gray-500 text-center mt-8">Click a file to preview its contents.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
