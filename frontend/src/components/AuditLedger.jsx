import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { CheckIcon, AlertIcon, RefreshIcon } from './Icons';

export function AuditLedger() {
  const [entries, setEntries] = useState([]);
  const [verification, setVerification] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadAudit();
  }, []);

  const loadAudit = async () => {
    try {
      const res = await api.getAuditEntries();
      setEntries(res.entries || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    try {
      const res = await api.verifyAuditLedger();
      setVerification(res);
      await loadAudit();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff' }}>
              Tamper-Evident Blockchain Audit Ledger
            </h2>
            <span className="badge badge-cyan">SHA-256 Hash Chaining</span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Mathematical immutability log: Each security event cryptographically seals the previous block hash
          </p>
        </div>

        <button
          onClick={handleVerify}
          disabled={loading}
          className="btn btn-primary"
          style={{ fontSize: '12px', padding: '8px 16px' }}
        >
          <RefreshIcon size={14} />
          {loading ? 'Verifying Hashes...' : 'Verify Cryptographic Integrity'}
        </button>
      </div>

      {/* Verification Status Banner */}
      {verification && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '8px',
          marginBottom: '18px',
          background: verification.valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${verification.valid ? 'var(--emerald-success)' : 'var(--crimson-danger)'}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div>
            <span style={{ fontSize: '13px', fontWeight: '700', color: verification.valid ? '#10b981' : '#ff6b6b' }}>
              {verification.valid ? 'CHAIN INTEGRITY VERIFIED' : 'TAMPERING DETECTED'}
            </span>
            <p style={{ fontSize: '12px', color: '#cbd5e1' }}>{verification.message}</p>
          </div>
          <span className={`badge ${verification.valid ? 'badge-low' : 'badge-critical'}`}>
            Blocks Validated: {verification.block_count}
          </span>
        </div>
      )}

      {/* Chain Entries Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left', fontFamily: 'var(--font-mono)' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '8px 12px' }}>Block #</th>
              <th style={{ padding: '8px 12px' }}>Event</th>
              <th style={{ padding: '8px 12px' }}>Actor</th>
              <th style={{ padding: '8px 12px' }}>Prev Block Hash</th>
              <th style={{ padding: '8px 12px' }}>Block SHA-256</th>
              <th style={{ padding: '8px 12px' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr
                key={entry.id}
                style={{
                  borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                  color: '#e2e8f0',
                }}
              >
                <td style={{ padding: '10px 12px', fontWeight: 'bold', color: '#00f2fe' }}>#{entry.id}</td>
                <td style={{ padding: '10px 12px', color: '#fff' }}>{entry.event_type}</td>
                <td style={{ padding: '10px 12px', color: 'var(--text-muted)' }}>{entry.actor}</td>
                <td style={{ padding: '10px 12px', color: 'var(--text-dim)' }} title={entry.prev_hash}>
                  {entry.prev_hash?.substring(0, 12)}...
                </td>
                <td style={{ padding: '10px 12px', color: '#10b981' }} title={entry.block_hash}>
                  {entry.block_hash?.substring(0, 16)}...
                </td>
                <td style={{ padding: '10px 12px' }}>
                  <span className="badge badge-low" style={{ fontSize: '9px' }}>SEALED</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
