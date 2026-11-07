import React, { useEffect, useRef, useState } from 'react';
import { connectScanWS } from '../api';

export default function ScanProgress({ scanId, initialStatus, initialProgress, initialModule, onUpdate }) {
  const [status, setStatus] = useState(initialStatus || 'pending');
  const [progress, setProgress] = useState(initialProgress || 0);
  const [module, setModule] = useState(initialModule || '');
  const [message, setMessage] = useState('');
  const wsRef = useRef(null);

  useEffect(() => {
    if (!scanId) return;
    // Only connect for active scans
    if (['completed', 'failed', 'cancelled'].includes(initialStatus)) return;

    const conn = connectScanWS(scanId, (data) => {
      if (data.status) setStatus(data.status);
      if (data.progress_pct !== undefined) setProgress(data.progress_pct);
      if (data.current_module !== undefined) setModule(data.current_module || '');
      if (data.message) setMessage(data.message);
      if (onUpdate) onUpdate(data);
    });
    wsRef.current = conn;

    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [scanId, initialStatus]);

  // Update from props
  useEffect(() => {
    if (initialStatus) setStatus(initialStatus);
    if (initialProgress !== undefined) setProgress(initialProgress);
    if (initialModule !== undefined) setModule(initialModule || '');
  }, [initialStatus, initialProgress, initialModule]);

  const isActive = ['running', 'validating', 'correlating'].includes(status);
  const barColor = status === 'completed' ? 'bg-green-500'
    : status === 'failed' ? 'bg-red-500'
    : status === 'cancelled' ? 'bg-yellow-500'
    : 'bg-blue-500';

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <div className="flex items-center gap-2">
          {isActive && (
            <span className="inline-block w-2 h-2 bg-blue-500 rounded-full animate-pulse" />
          )}
          <span className="capitalize text-gray-300 font-medium">{status}</span>
        </div>
        <span className="text-gray-500">{progress}%</span>
      </div>

      <div className="w-full bg-gray-700 rounded-full h-2.5 overflow-hidden">
        <div
          className={`${barColor} h-full rounded-full transition-all duration-500 ease-out`}
          style={{ width: `${Math.min(progress, 100)}%` }}
        />
      </div>

      {module && (
        <p className="text-xs text-gray-500">
          Running: <span className="text-gray-400">{module}</span>
        </p>
      )}
      {message && (
        <p className="text-xs text-gray-500">{message}</p>
      )}
    </div>
  );
}
