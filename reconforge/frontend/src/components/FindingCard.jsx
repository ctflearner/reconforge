import React, { useState } from 'react';

const SEV_COLORS = {
  critical: 'bg-red-600',
  high: 'bg-orange-600',
  medium: 'bg-yellow-600',
  low: 'bg-green-600',
  info: 'bg-gray-500',
};

const SEV_TEXT = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
  info: 'text-gray-400',
};

export default function FindingCard({ finding, onValidate }) {
  const [expanded, setExpanded] = useState(false);

  const sev = finding.severity || 'info';
  const badgeClass = SEV_COLORS[sev] || SEV_COLORS.info;

  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      {/* Header — always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-750 transition-colors"
      >
        <span className={`${badgeClass} text-white text-xs font-bold px-2 py-0.5 rounded uppercase tracking-wide`}>
          {sev}
        </span>
        <span className="flex-1 font-medium text-sm">{finding.title}</span>
        <span className="text-xs text-gray-500">{finding.module_name}</span>
        {finding.cvss_score && (
          <span className={`text-xs font-mono ${SEV_TEXT[sev]}`}>CVSS {finding.cvss_score}</span>
        )}
        <svg
          className={`w-4 h-4 text-gray-500 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none" viewBox="0 0 24 24" stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Body — expanded */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-700 pt-3 space-y-3">
          <p className="text-sm text-gray-300">{finding.description}</p>

          <div className="flex flex-wrap gap-2 text-xs text-gray-500">
            <span>Category: {finding.category}</span>
            {finding.cwe_id && <span>| {finding.cwe_id}</span>}
            {finding.owasp_category && <span>| {finding.owasp_category}</span>}
            <span>| Confidence: {(finding.confidence * 100).toFixed(0)}%</span>
            <span>| Status: {finding.validation_status}</span>
          </div>

          {finding.evidence && (
            <div className="bg-gray-900 border border-gray-700 rounded p-3">
              <h4 className="text-xs font-semibold text-blue-400 mb-1">Evidence</h4>
              <pre className="text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap break-all">
                {finding.evidence}
              </pre>
            </div>
          )}

          {finding.impact && (
            <div className="border-l-2 border-blue-500 pl-3">
              <h4 className="text-xs font-semibold text-blue-400">Impact</h4>
              <p className="text-sm text-gray-300">{finding.impact}</p>
            </div>
          )}

          {finding.remediation && (
            <div className="border-l-2 border-green-500 pl-3">
              <h4 className="text-xs font-semibold text-green-400">Remediation</h4>
              <p className="text-sm text-gray-300">{finding.remediation}</p>
            </div>
          )}

          {onValidate && finding.validation_status === 'pending' && (
            <div className="flex gap-2 pt-2">
              <button
                onClick={() => onValidate(finding.id, 'confirmed', '')}
                className="px-3 py-1.5 text-xs bg-green-600 hover:bg-green-700 text-white rounded font-medium transition-colors"
              >
                Confirm
              </button>
              <button
                onClick={() => onValidate(finding.id, 'false_positive', '')}
                className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded font-medium transition-colors"
              >
                False Positive
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
