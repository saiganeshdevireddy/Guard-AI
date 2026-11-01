import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { CheckIcon, AlertIcon, RefreshIcon } from './Icons';

export function AuditLedger() {
  const [entries, setEntries] = useState([]);
  const [verification, setVerification] = useState(null);
  const [loading, setLoading] = useState(false);
  const [blockchain, setBlockchain] = useState(null);
  const [anchorBusy, setAnchorBusy] = useState(null);
  const [anchorMessage, setAnchorMessage] = useState('');
  const [auditError, setAuditError] = useState('');
  const [auditLoading, setAuditLoading] = useState(true);
  const [lastVerifiedAt, setLastVerifiedAt] = useState(null);
  const [chainChecks, setChainChecks] = useState({});
  const [blockchainLoading, setBlockchainLoading] = useState(true);

  useEffect(() => {
    loadAudit();
    loadBlockchainStatus();
    const timer = setInterval(loadAudit, 3000);
    return () => clearInterval(timer);
  }, []);

  const loadAudit = async () => {
    setAuditLoading(true);
    try {
      const res = await api.getAuditEntries();
      if (!res || !Array.isArray(res.entries)) throw new Error('The backend returned an invalid audit entry list.');
      setEntries(res.entries);
      setAuditError('');
      const confirmed = res.entries.filter((entry) => entry.blockchain_anchor?.status === 'CONFIRMED');
      const checks = await Promise.all(confirmed.map(async (entry) => {
        try {
          const result = await api.verifyBlockchainEntry(entry.id);
          return [entry.id, result?.status === 'CONFIRMED' && result?.verified === true ? 'verified' : 'unverified'];
        } catch {
          return [entry.id, 'unavailable'];
        }
      }));
      setChainChecks(Object.fromEntries(checks));
    } catch (err) {
      setEntries([]);
      setVerification(null);
      setAuditError(err.message || 'Audit entries are unavailable.');
    } finally {
      setAuditLoading(false);
    }
  };

  const loadBlockchainStatus = async () => {
    setBlockchainLoading(true);
    try {
      const result = await api.getBlockchainStatus();
      if (!result || typeof result.available !== 'boolean') throw new Error('Malformed blockchain status.');
      setBlockchain(result);
    } catch (err) {
      setBlockchain({ available: false, message: err.message || 'Blockchain status unavailable.' });
    } finally {
      setBlockchainLoading(false);
    }
  };

  const handleVerify = async () => {
    setLoading(true);
    setVerification(null);
    setAuditError('');
    try {
      const res = await api.verifyAuditLedger();
      if (!res || typeof res.valid !== 'boolean' || !Number.isFinite(res.block_count)) throw new Error('The backend returned an invalid verification result.');
      setVerification(res);
      setLastVerifiedAt(new Date());
      await loadAudit();
    } catch (err) {
      setVerification(null);
      setAuditError(err.message || 'Audit verification is unavailable.');
    } finally {
      setLoading(false);
    }
  };

  const handleAnchor = async (entryId) => {
    setAnchorBusy(entryId);
    setAnchorMessage('');
    try {
      const result = await api.anchorAuditEntry(entryId);
      setAnchorMessage(result.message || `Anchoring ${result.status?.toLowerCase() || 'started'}.`);
      await loadAudit();
    } catch (err) {
      setAnchorMessage(err.message);
    } finally {
      setAnchorBusy(null);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-main)' }}>
              Tamper-Evident Audit Ledger
            </h2>
            <span className="badge badge-cyan">SHA-256 Hash Chaining</span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Local SHA-256 hash chain, with optional non-sensitive hash anchoring to a local Hardhat chain
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

      {auditError && <div role="alert" className="status-notice status-notice-error">Audit Ledger unavailable: {auditError}</div>}
      {!auditError && auditLoading && entries.length === 0 && <div role="status" className="status-notice">Loading audit entries from backend…</div>}

      <div role="status" style={{ marginBottom: '16px', padding: '12px 14px', borderRadius: '9px', background: blockchain?.available ? 'var(--success-soft)' : 'var(--surface-subtle)', border: '1px solid var(--border-card)' }}>
        <strong style={{ color: 'var(--text-main)', fontSize: '12px' }}>Blockchain: </strong>
        <span style={{ color: blockchain?.available ? 'var(--emerald-success)' : 'var(--text-muted)', fontSize: '12px' }}>
          {blockchainLoading ? 'Checking blockchain node…' : blockchain?.available ? `Local Hardhat connected (chain ${blockchain.chain_id})` : (blockchain?.message || 'Blockchain unavailable; local ledger remains in use.')}
        </span>
        {anchorMessage && <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '6px' }}>{anchorMessage}</p>}
      </div>

      {/* Verification Status Banner */}
      {verification && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '8px',
          marginBottom: '18px',
          background: verification.valid ? 'var(--success-soft)' : 'var(--danger-soft)',
          border: `1px solid ${verification.valid ? 'var(--emerald-success)' : 'var(--crimson-danger)'}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <div>
            <span style={{ fontSize: '13px', fontWeight: '700', color: verification.valid ? 'var(--emerald-success)' : 'var(--crimson-danger)' }}>
              {verification.valid ? 'LOCAL CHAIN INTEGRITY VERIFIED' : 'LOCAL INTEGRITY CHECK FAILED'}
            </span>
            <p style={{ fontSize: '12px', color: 'var(--text-main)' }}>{verification.message}</p>
            {lastVerifiedAt && <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Last verification: {lastVerifiedAt.toLocaleString()}</p>}
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
            <tr style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '8px 12px' }}>Block #</th>
              <th style={{ padding: '8px 12px' }}>Event</th>
              <th style={{ padding: '8px 12px' }}>Actor</th>
              <th style={{ padding: '8px 12px' }}>Prev Block Hash</th>
              <th style={{ padding: '8px 12px' }}>Block SHA-256</th>
              <th style={{ padding: '8px 12px' }}>Status</th>
              <th style={{ padding: '8px 12px' }}>On-chain anchor</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && !auditLoading && <tr><td colSpan="7" style={{ padding: '18px 12px', color: 'var(--text-muted)' }}>No audit entries are currently available.</td></tr>}
            {entries.map((entry) => (
              <tr
                key={entry.id}
                style={{
                  borderBottom: '1px solid var(--line-subtle)',
                  color: 'var(--text-main)',
                }}
              >
                <td style={{ padding: '10px 12px', fontWeight: 'bold', color: 'var(--cyan-primary)' }}>#{entry.id}</td>
                <td style={{ padding: '10px 12px', color: 'var(--text-main)' }}>{entry.event_type}</td>
                <td style={{ padding: '10px 12px', color: 'var(--text-muted)' }}>{entry.actor}</td>
                <td style={{ padding: '10px 12px', color: 'var(--text-dim)' }} title={entry.prev_hash}>
                  {entry.prev_hash?.substring(0, 12)}...
                </td>
                <td style={{ padding: '10px 12px', color: 'var(--emerald-success)' }} title={entry.block_hash}>
                  {entry.block_hash?.substring(0, 16)}...
                </td>
                <td style={{ padding: '10px 12px' }}>
                  <span className={`badge ${entry.verified ? 'badge-low' : 'badge-critical'}`} style={{ fontSize: '9px' }}>{entry.verified ? 'LOCAL HASHED' : 'UNVERIFIED'}</span>
                </td>
                <td style={{ padding: '10px 12px', minWidth: '210px' }}>
                  {entry.blockchain_anchor?.status === 'CONFIRMED' && chainChecks[entry.id] === 'verified' ? (
                    <span title={entry.blockchain_anchor.transaction_hash} style={{ color: 'var(--emerald-success)' }}>Receipt verified · {entry.blockchain_anchor.transaction_hash?.slice(0, 12)}…</span>
                  ) : entry.blockchain_anchor?.status === 'CONFIRMED' ? (
                    <span style={{ color: chainChecks[entry.id] === 'unavailable' ? 'var(--text-muted)' : 'var(--amber-warning)' }}>{chainChecks[entry.id] === 'unavailable' ? 'Receipt check unavailable' : 'Confirmation unverified'}</span>
                  ) : entry.blockchain_anchor?.status === 'PENDING' ? (
                    <span style={{ color: 'var(--amber-warning)' }}>Pending · attempt {entry.blockchain_anchor.retry_count}</span>
                  ) : (
                    <button type="button" className="btn btn-outline" disabled={!blockchain?.available || anchorBusy === entry.id} onClick={() => handleAnchor(entry.id)} style={{ padding: '5px 8px', fontSize: '10px' }}>
                      {anchorBusy === entry.id ? 'Queueing…' : entry.blockchain_anchor?.status === 'FAILED' ? 'Retry anchor' : 'Anchor hash'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
