import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AlertIcon, ShieldIcon, CheckIcon } from './Icons';

export function EmergencyLockdown({ onStatusChanged }) {
  const [status, setStatus] = useState(null);
  const [quarantine, setQuarantine] = useState([]);
  const [humanConfirmed, setHumanConfirmed] = useState(false);
  const [simResult, setSimResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadStatus();
  }, []);

  const loadStatus = async () => {
    try {
      const s = await api.getEmergencyStatus();
      setStatus(s);
      const q = await api.getQuarantine();
      setQuarantine(q.quarantined_items || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleActivate = async (level) => {
    if (level === 'FULL_CONTAINMENT' && !humanConfirmed) {
      setError('Full containment mandates checking the explicit human operator confirmation box.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.activateLockdown(level, 'Operator triggered containment', humanConfirmed);
      await loadStatus();
      if (onStatusChanged) onStatusChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    setLoading(true);
    setError(null);
    try {
      await api.resetLockdown(true);
      await loadStatus();
      if (onStatusChanged) onStatusChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async (actionType, target) => {
    try {
      const res = await api.simulateContainment(actionType, target);
      setSimResult(res);
    } catch (err) {
      setError(err.message);
    }
  };

  const isEmergency = status?.is_active;

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px', borderLeft: isEmergency ? '4px solid var(--crimson-danger)' : undefined }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '18px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff' }}>
              Offence AI Defensive Incident Response
            </h2>
            <span className={`badge ${isEmergency ? 'badge-critical' : 'badge-low'}`}>
              Level: {status?.lockdown_level || 'STANDARD'}
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Strictly defensive emergency containment, quarantine management, and recovery coordination
          </p>
        </div>

        {isEmergency ? (
          <button onClick={handleReset} disabled={loading} className="btn btn-outline" style={{ color: '#10b981', borderColor: '#10b981' }}>
            <CheckIcon size={16} /> Disengage Containment
          </button>
        ) : (
          <button onClick={() => handleActivate('HEIGHTENED')} disabled={loading} className="btn btn-danger">
            <AlertIcon size={16} /> Activate Containment
          </button>
        )}
      </div>

      {error && (
        <div style={{ padding: '10px 14px', background: 'rgba(239, 68, 68, 0.15)', border: '1px solid var(--crimson-danger)', borderRadius: '6px', color: '#ff6b6b', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Human Approval Safeguard Checkbox */}
      <div style={{
        background: 'rgba(10, 15, 26, 0.65)',
        padding: '14px 18px',
        borderRadius: '8px',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        marginBottom: '20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '13px', color: '#fff', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={humanConfirmed}
            onChange={(e) => setHumanConfirmed(e.target.checked)}
            style={{ width: '16px', height: '16px', accentColor: '#ef4444' }}
          />
          <span>I authorize Offence AI to enforce high-impact containment (Human Confirmation Gating)</span>
        </label>
        <button
          onClick={() => handleActivate('FULL_CONTAINMENT')}
          disabled={!humanConfirmed || loading}
          className="btn btn-danger"
          style={{ opacity: humanConfirmed ? 1 : 0.5, fontSize: '12px' }}
        >
          Full System Containment
        </button>
      </div>

      {/* Containment Simulation Tool */}
      <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.08)', paddingTop: '16px', marginBottom: '20px' }}>
        <h4 style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '10px' }}>
          Simulated Containment Testing
        </h4>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            onClick={() => handleSimulate('PROCESS_TERMINATION', 'powershell.exe [PID 4108]')}
            className="btn btn-outline"
            style={{ fontSize: '12px' }}
          >
            Simulate Process Suspension
          </button>
          <button
            onClick={() => handleSimulate('NETWORK_ISOLATION', 'Ethernet Adapter 0')}
            className="btn btn-outline"
            style={{ fontSize: '12px' }}
          >
            Simulate Network Cutoff
          </button>
        </div>
        {simResult && (
          <div style={{ marginTop: '10px', padding: '10px', background: 'rgba(15, 23, 42, 0.8)', borderRadius: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: '#00f2fe' }}>
            &bull; {simResult.details} ({simResult.status})
          </div>
        )}
      </div>

      {/* Quarantined Items List */}
      <div>
        <h4 style={{ fontSize: '14px', fontWeight: '600', color: '#fff', marginBottom: '10px' }}>
          Isolated Quarantine Storage ({quarantine.length})
        </h4>
        {quarantine.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
            Quarantine vault is empty. No files or processes currently contained.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {quarantine.map((q) => (
              <div
                key={q.id}
                style={{
                  padding: '10px 14px',
                  background: 'rgba(10, 15, 26, 0.65)',
                  borderRadius: '6px',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <span style={{ fontSize: '13px', fontWeight: '600', color: '#ff6b6b' }}>
                    {q.target_identifier}
                  </span>
                  <p style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                    Reason: {q.reason} &bull; {q.notes}
                  </p>
                </div>
                <span className="badge badge-critical" style={{ fontSize: '9px' }}>
                  ISOLATED
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
