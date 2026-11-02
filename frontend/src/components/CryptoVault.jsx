import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { LockIcon, UnlockIcon, CheckIcon, AlertIcon } from './Icons';

export function CryptoVault({ onVaultUpdated }) {
  const [status, setStatus] = useState(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState(null);
  const [items, setItems] = useState([]);
  const [passphrase, setPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // New item form
  const [newLabel, setNewLabel] = useState('');
  const [newPlaintext, setNewPlaintext] = useState('');
  const [newCategory, setNewCategory] = useState('CREDENTIAL');

  // Decrypted item viewer
  const [decryptedView, setDecryptedView] = useState({});

  // Escrow recovery modal
  const [escrowResult, setEscrowResult] = useState(null);
  const [recoveryKeyVisible, setRecoveryKeyVisible] = useState(false);
  const [recoveryKeyInput, setRecoveryKeyInput] = useState('');
  const [recoveryTokenInput, setRecoveryTokenInput] = useState('');
  const [restoredPayload, setRestoredPayload] = useState('');

  useEffect(() => {
    loadVaultData();
  }, []);

  const loadVaultData = async () => {
    setStatusLoading(true);
    try {
      const s = await api.getVaultStatus();
      if (!s || typeof s.is_locked !== 'boolean' || !Number.isFinite(s.items_count) || typeof s.algorithm !== 'string') {
        throw new Error('The backend returned an invalid Vault status.');
      }
      setStatus(s);
      setStatusError(null);
    } catch (err) {
      setStatus(null);
      setItems([]);
      setStatusError(err.message || 'Vault status is unavailable.');
      setStatusLoading(false);
      return;
    }

    try {
      const it = await api.getVaultItems();
      if (!it || !Array.isArray(it.items)) throw new Error('The backend returned an invalid Vault item list.');
      setItems(it.items || []);
    } catch (err) {
      setItems([]);
      setStatusError(err.message || 'Vault items are unavailable.');
    } finally {
      setStatusLoading(false);
    }
  };

  const handleUnlock = async (e) => {
    e.preventDefault();
    if (!passphrase) return;
    setLoading(true);
    setError(null);
    try {
      if (!window.confirm('Unlocking the vault is a high-impact action. Continue to authenticated server approval?')) return;
      const approvalId = await api.requestActionApproval('VAULT_UNLOCK', 'vault', { passphrase });
      await api.unlockVault(passphrase, approvalId);
      setSuccess('Vault unlocked successfully.');
      await loadVaultData();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLock = async () => {
    try {
      await api.lockVault();
      setPassphrase('');
      setDecryptedView({});
      setSuccess('Vault sealed and memory keys purged.');
      await loadVaultData();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleStore = async (e) => {
    e.preventDefault();
    if (!newLabel || !newPlaintext || !passphrase) {
      setError('Label, plaintext, and master passphrase are required.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.storeVaultItem(newLabel, newPlaintext, passphrase, newCategory);
      setNewLabel('');
      setNewPlaintext('');
      setSuccess('Secret securely encrypted with AES-256-GCM and stored.');
      await loadVaultData();
      if (onVaultUpdated) onVaultUpdated();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDecryptItem = async (itemId) => {
    if (!passphrase) {
      setError('Please provide your master passphrase above to decrypt items.');
      return;
    }
    try {
      if (!window.confirm(`Decrypt vault item ${itemId}? The action requires authenticated server approval.`)) return;
      const approvalId = await api.requestActionApproval('VAULT_ITEM_DECRYPT', String(itemId), { item_id: itemId, passphrase });
      const res = await api.decryptVaultItem(itemId, passphrase, approvalId);
      setDecryptedView({ ...decryptedView, [itemId]: res.plaintext });
    } catch (err) {
      setError(`Decryption failed: ${err.message}`);
    }
  };

  const handleCreateEscrow = async () => {
    const backupText = prompt('Enter confidential text to package into an offline recovery envelope:');
    if (!backupText) return;
    try {
      if (!window.confirm('Create an emergency recovery envelope for this payload? The server stores only an approval hash, but the payload is sent to the Guard AI backend for processing.')) return;
      const approvalId = await api.requestActionApproval('VAULT_ESCROW_GENERATE', 'vault', { payload: backupText });
      const res = await api.generateEscrow(backupText, approvalId);
      setEscrowResult(res);
      setRecoveryKeyVisible(false);
      setRestoredPayload('');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleRestoreEscrow = async (event) => {
    event.preventDefault();
    setError(null);
    setRestoredPayload('');
    try {
      if (!window.confirm('Restore this escrow envelope? This is a high-impact recovery action and requires authenticated server approval.')) return;
      const approvalId = await api.requestActionApproval('VAULT_ESCROW_RESTORE', 'vault', {
        recovery_key: recoveryKeyInput, encrypted_token: recoveryTokenInput,
      });
      const result = await api.restoreEscrow(recoveryKeyInput, recoveryTokenInput, approvalId);
      setRestoredPayload(result.payload);
    } catch {
      setError('Recovery failed. Verify the key and encrypted envelope, then try again.');
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-main)' }}>
              Cryptographic Maze Vault
            </h2>
            <span className={`badge ${status ? (status.is_locked ? 'badge-high' : 'badge-low') : 'badge-cyan'}`}>
              {statusLoading ? 'CHECKING' : status ? (status.is_locked ? 'LOCKED' : 'UNLOCKED') : 'UNKNOWN'}
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {status?.algorithm || 'Cryptographic capability has not been confirmed by the backend.'}
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={handleCreateEscrow} className="btn btn-outline" style={{ fontSize: '12px' }}>
            Emergency Escrow
          </button>
          {status && !status.is_locked && (
            <button onClick={handleLock} className="btn btn-danger" style={{ fontSize: '12px' }}>
              <LockIcon size={14} /> Seal Vault
            </button>
          )}
        </div>
      </div>

      {statusError && (
        <div role="status" style={{ padding: '10px 14px', background: 'var(--surface-subtle)', border: '1px solid var(--border-card)', borderRadius: '6px', color: 'var(--text-muted)', fontSize: '12px', marginBottom: '16px' }}>
          Vault status unavailable: {statusError}
        </div>
      )}

      {/* Lock/Unlock Form */}
      <div style={{ background: 'var(--surface-subtle)', padding: '16px', borderRadius: '8px', marginBottom: '20px' }}>
        <form onSubmit={handleUnlock} style={{ display: 'flex', gap: '12px' }}>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter Master Vault Passphrase..."
            className="input-field"
            style={{ flex: 1 }}
          />
          {status?.is_locked && (
            <button type="submit" disabled={loading} className="btn btn-primary" style={{ minWidth: '130px' }}>
              <UnlockIcon size={16} /> Unlock
            </button>
          )}
        </form>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', background: 'var(--danger-soft)', border: '1px solid var(--crimson-danger)', borderRadius: '6px', color: 'var(--crimson-danger)', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}
      {success && (
        <div style={{ padding: '10px 14px', background: 'var(--success-soft)', border: '1px solid var(--emerald-success)', borderRadius: '6px', color: 'var(--emerald-success)', fontSize: '12px', marginBottom: '16px' }}>
          {success}
        </div>
      )}

      {/* Store New Secret Form */}
      <div style={{ borderTop: '1px solid var(--line-subtle)', paddingTop: '16px', marginBottom: '20px' }}>
        <h4 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-main)', marginBottom: '10px' }}>
          Encrypt & Protect New Asset
        </h4>
        <form onSubmit={handleStore} style={{ display: 'grid', gridTemplateColumns: '1fr 2fr auto', gap: '10px' }}>
          <input
            type="text"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
            placeholder="Label (e.g. Master SSH Key)"
            className="input-field"
          />
          <input
            type="text"
            value={newPlaintext}
            onChange={(e) => setNewPlaintext(e.target.value)}
            placeholder="Confidential Secret Plaintext..."
            className="input-field"
          />
          <button type="submit" disabled={loading} className="btn btn-primary" style={{ whiteSpace: 'nowrap' }}>
            Encrypt Secret
          </button>
        </form>
      </div>

      {/* Stored Items List */}
      <div>
        <h4 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-main)', marginBottom: '10px' }}>
          Encrypted Enclaves ({items.length})
        </h4>
        {items.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
            No secrets encrypted in vault yet.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {items.map((it) => (
              <div
                key={it.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '12px 16px',
                  background: 'var(--surface-subtle)',
                  borderRadius: '6px',
                  border: '1px solid var(--line-subtle)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-main)' }}>{it.label}</span>
                    <span className="badge badge-cyan" style={{ fontSize: '9px' }}>{it.category}</span>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    Payload: AES-256-GCM Authenticated Ciphertext &bull; {new Date(it.created_at).toLocaleTimeString()}
                  </span>
                  {decryptedView[it.id] && (
                    <div style={{ marginTop: '6px', padding: '6px 10px', background: 'var(--success-soft)', border: '1px solid var(--emerald-success)', borderRadius: '4px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--emerald-success)' }}>
                      Decrypted Plaintext: <strong>{decryptedView[it.id]}</strong>
                    </div>
                  )}
                </div>

                <button
                  onClick={() => handleDecryptItem(it.id)}
                  className="btn btn-outline"
                  style={{ padding: '6px 12px', fontSize: '11px' }}
                >
                  Verify & Decrypt
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recovery material is kept out of view until the user explicitly reveals it. */}
      {escrowResult && (
        <div style={{ marginTop: '16px', padding: '14px', background: 'var(--surface-emphasis)', border: '1px solid var(--purple-accent)', borderRadius: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-main)' }}>Offline Recovery Envelope</span>
            <button onClick={() => { setEscrowResult(null); setRecoveryKeyVisible(false); }} className="btn btn-outline" style={{ padding: '2px 8px', fontSize: '10px' }}>Clear</button>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>{escrowResult.instructions} Keep the recovery key separate from the encrypted envelope.</p>
          <button type="button" className="btn btn-outline" onClick={() => setRecoveryKeyVisible((visible) => !visible)}>
            {recoveryKeyVisible ? 'Hide recovery key' : 'Reveal recovery key'}
          </button>
          {recoveryKeyVisible && <p role="alert" style={{ marginTop: '10px', color: 'var(--amber-warning)', fontFamily: 'var(--font-mono)', fontSize: '12px', wordBreak: 'break-all' }}>{escrowResult.recovery_key}</p>}
          <label style={{ display: 'block', marginTop: '12px', color: 'var(--text-muted)', fontSize: '11px' }}>Encrypted envelope (safe to store separately from its key)</label>
          <textarea readOnly value={escrowResult.encrypted_token} className="input-field" rows={3} style={{ marginTop: '5px', fontSize: '11px', wordBreak: 'break-all' }} />
        </div>
      )}

      <div style={{ marginTop: '18px', paddingTop: '16px', borderTop: '1px solid var(--line-subtle)' }}>
        <h4 style={{ color: 'var(--text-main)', fontSize: '14px', marginBottom: '8px' }}>Restore an offline recovery envelope</h4>
        <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '10px' }}>The key and envelope are sent to the local backend for one-time recovery; they are not saved by this interface.</p>
        <form onSubmit={handleRestoreEscrow} style={{ display: 'grid', gap: '9px' }}>
          <input type="password" autoComplete="off" value={recoveryKeyInput} onChange={(event) => setRecoveryKeyInput(event.target.value)} placeholder="Recovery key" className="input-field" required />
          <textarea value={recoveryTokenInput} onChange={(event) => setRecoveryTokenInput(event.target.value)} placeholder="Encrypted envelope" className="input-field" rows={3} required />
          <button type="submit" className="btn btn-outline" style={{ justifySelf: 'start' }}>Restore payload</button>
        </form>
        {restoredPayload && <div role="status" style={{ marginTop: '10px', padding: '10px', background: 'var(--success-soft)', border: '1px solid var(--success-border)', borderRadius: '8px', color: 'var(--text-main)', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}><strong>Recovered payload</strong><button className="btn btn-outline" onClick={() => { setRestoredPayload(''); setRecoveryKeyInput(''); setRecoveryTokenInput(''); }} type="button">Clear</button></div>
          <p style={{ marginTop: '6px' }}>{restoredPayload}</p>
        </div>}
      </div>
    </div>
  );
}
