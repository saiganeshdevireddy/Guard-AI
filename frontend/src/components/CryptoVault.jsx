import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { LockIcon, UnlockIcon, CheckIcon, AlertIcon } from './Icons';

export function CryptoVault({ onVaultUpdated }) {
  const [status, setStatus] = useState({ is_locked: true, items_count: 0 });
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

  useEffect(() => {
    loadVaultData();
  }, []);

  const loadVaultData = async () => {
    try {
      const s = await api.getVaultStatus();
      setStatus(s);
      const it = await api.getVaultItems();
      setItems(it.items || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleUnlock = async (e) => {
    e.preventDefault();
    if (!passphrase) return;
    setLoading(true);
    setError(null);
    try {
      await api.unlockVault(passphrase);
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
      const res = await api.decryptVaultItem(itemId, passphrase);
      setDecryptedView({ ...decryptedView, [itemId]: res.plaintext });
    } catch (err) {
      setError(`Decryption failed: ${err.message}`);
    }
  };

  const handleCreateEscrow = async () => {
    const backupText = prompt('Enter confidential text to package into an offline recovery envelope:');
    if (!backupText) return;
    try {
      const res = await api.generateEscrow(backupText);
      setEscrowResult(res);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff' }}>
              Cryptographic Maze Vault
            </h2>
            <span className={`badge ${status.is_locked ? 'badge-high' : 'badge-low'}`}>
              {status.is_locked ? 'LOCKED' : 'UNLOCKED'}
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Layered AEAD encryption (AES-256-GCM + PBKDF2 600K rounds + HKDF Key Separation)
          </p>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={handleCreateEscrow} className="btn btn-outline" style={{ fontSize: '12px' }}>
            Emergency Escrow
          </button>
          {!status.is_locked && (
            <button onClick={handleLock} className="btn btn-danger" style={{ fontSize: '12px' }}>
              <LockIcon size={14} /> Seal Vault
            </button>
          )}
        </div>
      </div>

      {/* Lock/Unlock Form */}
      <div style={{ background: 'rgba(10, 15, 26, 0.7)', padding: '16px', borderRadius: '8px', marginBottom: '20px' }}>
        <form onSubmit={handleUnlock} style={{ display: 'flex', gap: '12px' }}>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter Master Vault Passphrase..."
            className="input-field"
            style={{ flex: 1 }}
          />
          {status.is_locked && (
            <button type="submit" disabled={loading} className="btn btn-primary" style={{ minWidth: '130px' }}>
              <UnlockIcon size={16} /> Unlock
            </button>
          )}
        </form>
      </div>

      {error && (
        <div style={{ padding: '10px 14px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid var(--crimson-danger)', borderRadius: '6px', color: '#ff6b6b', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}
      {success && (
        <div style={{ padding: '10px 14px', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid var(--emerald-success)', borderRadius: '6px', color: '#10b981', fontSize: '12px', marginBottom: '16px' }}>
          {success}
        </div>
      )}

      {/* Store New Secret Form */}
      <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '16px', marginBottom: '20px' }}>
        <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#fff', marginBottom: '10px' }}>
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
        <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#fff', marginBottom: '10px' }}>
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
                  background: 'rgba(10, 15, 26, 0.65)',
                  borderRadius: '6px',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '13px', fontWeight: '600', color: '#fff' }}>{it.label}</span>
                    <span className="badge badge-cyan" style={{ fontSize: '9px' }}>{it.category}</span>
                  </div>
                  <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                    Payload: AES-256-GCM Authenticated Ciphertext &bull; {new Date(it.created_at).toLocaleTimeString()}
                  </span>
                  {decryptedView[it.id] && (
                    <div style={{ marginTop: '6px', padding: '6px 10px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #10b981', borderRadius: '4px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#10b981' }}>
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

      {/* Escrow Modal Output */}
      {escrowResult && (
        <div style={{ marginTop: '16px', padding: '14px', background: 'rgba(15, 23, 42, 0.95)', border: '1px solid var(--purple-accent)', borderRadius: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', fontWeight: '700', color: '#fff' }}>Emergency Disaster Escrow Envelope</span>
            <button onClick={() => setEscrowResult(null)} className="btn btn-outline" style={{ padding: '2px 8px', fontSize: '10px' }}>Close</button>
          </div>
          <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#cbd5e1', wordBreak: 'break-all' }}>
            <p><strong>Recovery Key:</strong> {escrowResult.recovery_key}</p>
            <p style={{ marginTop: '4px' }}><strong>Encrypted Envelope:</strong> {escrowResult.encrypted_token}</p>
          </div>
        </div>
      )}
    </div>
  );
}
