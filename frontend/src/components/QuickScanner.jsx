import React, { useState } from 'react';
import { api } from '../services/api';
import { GlobeIcon, AlertIcon, CheckIcon, ActivityIcon, WifiIcon } from './Icons';

export function QuickScanner({ onThreatDetected }) {
  const [activeTab, setActiveTab] = useState('url'); // 'url', 'file', 'text', 'network'
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // Form states
  const [urlInput, setUrlInput] = useState('http://paypal-verification-account.xyz/login');
  const [fileInput, setFileInput] = useState(null);
  const [textInput, setTextInput] = useState('URGENT: Your bank account will be suspended within 24 hours. Send Bitcoin wire transfer immediately to verify your identity.');
  const [networkInput, setNetworkInput] = useState({
    ssid: 'PublicCoffee_FreeWifi',
    security_type: 'OPEN',
    duplicate_ssids_detected: 1,
    dns_servers: ['192.168.1.1'],
  });

  const handleScan = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let res;
      if (activeTab === 'url') {
        res = await api.scanURL(urlInput);
      } else if (activeTab === 'file') {
        if (!fileInput) throw new Error('Please select a file to inspect.');
        res = await api.scanFile(fileInput);
      } else if (activeTab === 'text') {
        res = await api.scanText(textInput);
      } else if (activeTab === 'network') {
        res = await api.scanNetwork(networkInput);
      }
      setResult(res);
      if (onThreatDetected) {
        onThreatDetected(res);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadgeClass = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'badge-critical';
      case 'HIGH': return 'badge-high';
      case 'MEDIUM': return 'badge-medium';
      default: return 'badge-low';
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-main)' }}>Finder AI Threat Scanner</h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Real-time heuristic evaluation across web links, binary files, communications, and network profiles
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--line-subtle)', paddingBottom: '12px', marginBottom: '18px' }}>
        {[
          { id: 'url', label: 'URL & Phishing' },
          { id: 'file', label: 'Suspicious File' },
          { id: 'text', label: 'Spam & Social Engineering' },
          { id: 'network', label: 'Wi-Fi & Network Posture' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => { setActiveTab(tab.id); setResult(null); setError(null); }}
            className={`btn ${activeTab === tab.id ? 'btn-primary' : 'btn-outline'}`}
            style={{ padding: '7px 14px', fontSize: '12px' }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Scan Input Forms */}
      <form onSubmit={handleScan}>
        {activeTab === 'url' && (
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '6px', color: 'var(--text-muted)' }}>
              Target Web Destination / Domain:
            </label>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="e.g. http://suspicious-login.xyz"
              className="input-field"
              required
            />
          </div>
        )}

        {activeTab === 'file' && (
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '6px', color: 'var(--text-muted)' }}>
              Upload Suspicious File for Bytecode & Entropy Inspection:
            </label>
            <input
              type="file"
              onChange={(e) => setFileInput(e.target.files[0])}
              className="input-field"
              style={{ padding: '8px' }}
              required
            />
          </div>
        )}

        {activeTab === 'text' && (
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '6px', color: 'var(--text-muted)' }}>
              Message Text / Suspicious Email Body:
            </label>
            <textarea
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              rows={3}
              className="input-field"
              style={{ resize: 'vertical' }}
              required
            />
          </div>
        )}

        {activeTab === 'network' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', marginBottom: '16px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '6px', color: 'var(--text-muted)' }}>
                Wi-Fi SSID:
              </label>
              <input
                type="text"
                value={networkInput.ssid}
                onChange={(e) => setNetworkInput({ ...networkInput, ssid: e.target.value })}
                className="input-field"
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '12px', fontWeight: '600', marginBottom: '6px', color: 'var(--text-muted)' }}>
                Security Protocol:
              </label>
              <select
                value={networkInput.security_type}
                onChange={(e) => setNetworkInput({ ...networkInput, security_type: e.target.value })}
                className="input-field"
              >
                <option value="OPEN">OPEN (Unencrypted)</option>
                <option value="WEP">WEP (Deprecated/Insecure)</option>
                <option value="WPA_PSK">WPA-Personal (Weak)</option>
                <option value="WPA2_PSK">WPA2-PSK (AES)</option>
                <option value="WPA3_SAE">WPA3-SAE (Strong)</option>
              </select>
            </div>
          </div>
        )}

        <button type="submit" disabled={loading} className="btn btn-primary" style={{ width: '100%' }}>
          {loading ? 'Finder AI Analyzing Vectors...' : 'Execute Deep Inspection'}
        </button>
      </form>

      {error && (
        <div style={{ marginTop: '16px', padding: '12px', background: 'var(--danger-soft)', border: '1px solid var(--crimson-danger)', borderRadius: '8px', color: 'var(--crimson-danger)', fontSize: '13px' }}>
          Error: {error}
        </div>
      )}

      {/* Results View */}
      {result && (
        <div style={{ marginTop: '20px', padding: '16px', background: 'var(--surface-subtle)', borderRadius: '8px', border: '1px solid var(--cyan-border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <span style={{ fontSize: '14px', fontWeight: '700', color: 'var(--text-main)' }}>
              Threat Assessment Output: {result.report?.target}
            </span>
            <span className={`badge ${getSeverityBadgeClass(result.report?.severity)}`}>
              Severity: {result.report?.severity} ({result.report?.composite_score}/100)
            </span>
          </div>

          <p style={{ color: 'var(--amber-warning)', fontSize: '11px', marginBottom: '10px' }}>
            Results are heuristic only. A low score is not proof that a URL or file is safe.
          </p>

          {/* Indicators List */}
          <div style={{ marginBottom: '14px' }}>
            <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-dim)', textTransform: 'uppercase' }}>
              Specific Indicators Identified:
            </span>
            <ul style={{ marginTop: '6px', paddingLeft: '18px', fontSize: '12px', color: 'var(--text-main)' }}>
              {result.report?.all_indicators?.map((ind, i) => (
                <li key={i} style={{ marginBottom: '4px' }}>{ind}</li>
              ))}
            </ul>
          </div>

          {/* Hybrid AI Intelligence */}
          {result.hybrid_explanation && (
            <div style={{ padding: '12px', background: 'var(--surface-subtle)', borderRadius: '6px', borderLeft: '3px solid var(--cyan-primary)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span className="badge badge-cyan" style={{ fontSize: '10px' }}>
                  {result.hybrid_explanation.mode}
                </span>
                <span style={{ fontSize: '11px', color: 'var(--emerald-success)' }}>
                  Local rules &bull; no external request
                </span>
              </div>
              <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: '1.4' }}>
                {result.hybrid_explanation.ai_summary}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
