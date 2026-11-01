import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import { SmartphoneIcon, LockIcon, CheckIcon } from './Icons';

export function AndroidCompanion() {
  const [device, setDevice] = useState(null);
  const [locked, setLocked] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadDeviceStatus();
  }, []);

  const loadDeviceStatus = async () => {
    try {
      const res = await api.getAndroidStatus();
      setDevice(res);
      setLocked(res.remote_lock_engaged);
    } catch (err) {
      console.error(err);
    }
  };

  const handleRemoteLock = async () => {
    if (!device) return;
    setLoading(true);
    try {
      await api.remoteLockAndroid(device.device_id);
      setLocked(true);
      await loadDeviceStatus();
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (!device) return null;

  return (
    <div className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '36px',
            height: '36px',
            borderRadius: '8px',
            background: 'rgba(0, 242, 254, 0.1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            border: '1px solid rgba(0, 242, 254, 0.3)',
          }}>
            <SmartphoneIcon size={20} color="#00f2fe" />
          </div>
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#fff' }}>
              Android Mobile Companion
            </h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Cross-platform device telemetry & remote defensive lock coordination
            </p>
          </div>
        </div>

        <button
          onClick={handleRemoteLock}
          disabled={loading || locked}
          className={`btn ${locked ? 'btn-outline' : 'btn-danger'}`}
          style={{ fontSize: '12px' }}
        >
          <LockIcon size={14} />
          {locked ? 'Remote Lock Engaged' : 'Dispatch Defensive Lock'}
        </button>
      </div>

      {/* Device Telemetry Card */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '16px' }}>
        <div style={{ background: 'rgba(10, 15, 26, 0.65)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Device Model</span>
          <p style={{ fontSize: '14px', fontWeight: '600', color: '#fff', marginTop: '2px' }}>{device.device_name}</p>
        </div>

        <div style={{ background: 'rgba(10, 15, 26, 0.65)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>OS & Security Patch</span>
          <p style={{ fontSize: '14px', fontWeight: '600', color: '#00f2fe', marginTop: '2px' }}>{device.os_version}</p>
        </div>

        <div style={{ background: 'rgba(10, 15, 26, 0.65)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Battery & Wireless</span>
          <p style={{ fontSize: '14px', fontWeight: '600', color: '#10b981', marginTop: '2px' }}>
            {device.battery_percent}% &bull; {device.wifi_ssid}
          </p>
        </div>

        <div style={{ background: 'rgba(10, 15, 26, 0.65)', padding: '12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Permission Audit</span>
          <p style={{ fontSize: '14px', fontWeight: '600', color: '#e2e8f0', marginTop: '2px' }}>
            {device.permission_audit?.apps_with_sms_read} SMS &bull; {device.permission_audit?.apps_with_accessibility} Acc.
          </p>
        </div>
      </div>

      <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontStyle: 'italic' }}>
        Note: The Android companion communicates with Guard AI via authenticated companion APIs, honoring Android runtime permissions without claiming silent OS monitoring.
      </div>
    </div>
  );
}
