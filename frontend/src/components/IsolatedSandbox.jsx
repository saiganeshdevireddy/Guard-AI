import React, { useState } from 'react';
import { api } from '../services/api';
import { GlobeIcon, AlertIcon } from './Icons';

export function IsolatedSandbox() {
  const [targetUrl, setTargetUrl] = useState('https://example.com');
  const [loading, setLoading] = useState(false);
  const [sandboxDoc, setSandboxDoc] = useState(null);
  const [error, setError] = useState(null);

  const handlePreview = async (e) => {
    e.preventDefault();
    if (!targetUrl) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.previewURLSafely(targetUrl);
      setSandboxDoc(res);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff' }}>Isolated Browsing Sandbox</h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Render untrusted web destinations with active scripts stripped, headers analyzed, and network storage blocked
          </p>
        </div>
        <span className="badge badge-medium">Air-Gap Emulation</span>
      </div>

      {/* URL Input Form */}
      <form onSubmit={handlePreview} style={{ display: 'flex', gap: '10px', marginBottom: '18px' }}>
        <input
          type="text"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          placeholder="Enter untrusted destination URL to safely preview..."
          className="input-field"
          style={{ flex: 1 }}
        />
        <button type="submit" disabled={loading} className="btn btn-primary" style={{ whiteSpace: 'nowrap' }}>
          {loading ? 'Inspecting & Sanitizing...' : 'Launch Isolated Preview'}
        </button>
      </form>

      {error && (
        <div style={{ padding: '10px 14px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid var(--crimson-danger)', borderRadius: '6px', color: '#ff6b6b', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Mandatory Sandbox Security Disclaimer */}
      <div style={{
        padding: '10px 14px',
        background: 'rgba(245, 158, 11, 0.1)',
        border: '1px solid rgba(245, 158, 11, 0.3)',
        borderRadius: '6px',
        color: '#fbbf24',
        fontSize: '11px',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        marginBottom: '18px',
      }}>
        <AlertIcon size={16} />
        <span>
          <strong>Operational Warning:</strong> Isolated browsing strips executable scripts and event handlers. While this mitigates typical drive-by download vectors, browser sandboxing cannot guarantee 100% protection against novel OS zero-day exploits.
        </span>
      </div>

      {/* Sandboxed Iframe Preview */}
      {sandboxDoc && (
        <div style={{
          border: '1px solid rgba(0, 242, 254, 0.3)',
          borderRadius: '8px',
          overflow: 'hidden',
          background: '#ffffff',
        }}>
          <div style={{
            background: '#101522',
            padding: '8px 14px',
            borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            color: '#fff',
          }}>
            <span style={{ fontFamily: 'var(--font-mono)' }}>Safe Frame: {sandboxDoc.url}</span>
            <span style={{ color: '#10b981' }}>Scripts Blocked &bull; Size: {Math.round(sandboxDoc.raw_size_bytes / 1024)} KB</span>
          </div>
          <iframe
            title="Safe Sandbox Inspector"
            srcDoc={sandboxDoc.sanitized_html}
            sandbox="allow-same-origin"
            style={{
              width: '100%',
              height: '420px',
              border: 'none',
              background: '#ffffff',
            }}
          />
        </div>
      )}
    </div>
  );
}
