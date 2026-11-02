import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { AlertIcon, ShieldIcon, CheckIcon } from './Icons';

export function EmergencyLockdown({ onStatusChanged }) {
  const [status, setStatus] = useState(null);
  const [quarantine, setQuarantine] = useState([]);
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
    const reason = 'Operator triggered containment';
    const target = null;
    if (!window.confirm(`Request server-verified approval to activate ${level} defensive incident mode? This records Guard AI state only; it does not isolate the operating system or network.`)) return;
    setLoading(true);
    setError(null);
    try {
      const approvalId = await api.requestActionApproval('EMERGENCY_ACTIVATE', target, { level, reason, target });
      await api.activateLockdown(level, reason, target, approvalId);
      await loadStatus();
      if (onStatusChanged) onStatusChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    if (!window.confirm('Request server-verified approval to reset defensive incident mode?')) return;
    setLoading(true);
    setError(null);
    try {
      const approvalId = await api.requestActionApproval('EMERGENCY_RESET', null, {});
      await api.resetLockdown(approvalId);
      await loadStatus();
      if (onStatusChanged) onStatusChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSimulate = async (actionType, target) => {
    if (!window.confirm(`Request approval for the simulated ${actionType} action on “${target}”? No process or network configuration will be changed.`)) return;
    try {
      const permission = actionType === 'PROCESS_TERMINATION' ? 'PROCESS_TERMINATE' : 'NETWORK_ISOLATE';
      const payload = { action_type: actionType, target };
      const approvalId = await api.requestActionApproval(permission, target, payload);
      const res = await api.simulateContainment(actionType, target, approvalId);
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
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-main)' }}>
              Offence AI Defensive Incident Response
            </h2>
            <span className={`badge ${isEmergency ? 'badge-critical' : 'badge-low'}`}>
              Level: {status?.lockdown_level || 'STANDARD'}
            </span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Local incident status and simulated containment actions. No OS or network isolation is performed.
          </p>
        </div>

        {isEmergency ? (
          <button onClick={handleReset} disabled={loading} className="btn btn-outline" style={{ color: 'var(--emerald-success)', borderColor: 'var(--emerald-success)' }}>
            <CheckIcon size={16} /> Disengage Containment
          </button>
        ) : (
          <button onClick={() => handleActivate('HEIGHTENED')} disabled={loading} className="btn btn-danger">
            <AlertIcon size={16} /> Activate Containment
          </button>
        )}
      </div>

      {error && (
        <div style={{ padding: '10px 14px', background: 'var(--danger-soft)', border: '1px solid var(--crimson-danger)', borderRadius: '6px', color: 'var(--crimson-danger)', fontSize: '12px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Human confirmation starts an authenticated, server-side approval flow; no client Boolean authorizes the action. */}
      <div style={{
        background: 'var(--surface-subtle)',
        padding: '14px 18px',
        borderRadius: '8px',
        border: '1px solid var(--line-subtle)',
        marginBottom: '20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>High-impact actions require authenticated, server-verified, single-use approval.</span>
        <button
          onClick={() => handleActivate('FULL_CONTAINMENT')}
          disabled={loading}
          className="btn btn-danger"
          style={{ fontSize: '12px' }}
        >
          Full System Containment
        </button>
      </div>

      {/* Containment Simulation Tool */}
      <div style={{ borderTop: '1px solid var(--line-subtle)', paddingTop: '16px', marginBottom: '20px' }}>
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
          <div style={{ marginTop: '10px', padding: '10px', background: 'var(--surface-subtle)', borderRadius: '6px', fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--cyan-primary)' }}>
            &bull; {simResult.details} ({simResult.status})
          </div>
        )}
      </div>

      {/* Quarantined Items List */}
      <div>
        <h4 style={{ fontSize: '14px', fontWeight: '600', color: 'var(--text-main)', marginBottom: '10px' }}>
          Quarantined Files ({quarantine.length})
        </h4>
        {quarantine.length === 0 ? (
          <p style={{ fontSize: '12px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
            No files have been moved to the local quarantine directory.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {quarantine.map((q) => (
              <div
                key={q.id}
                style={{
                  padding: '10px 14px',
                  background: 'var(--surface-subtle)',
                  borderRadius: '6px',
                  border: '1px solid var(--line-subtle)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <span style={{ fontSize: '13px', fontWeight: '600', color: 'var(--crimson-danger)' }}>
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
