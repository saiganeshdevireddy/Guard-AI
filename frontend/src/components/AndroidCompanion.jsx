import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { SmartphoneIcon, LockIcon } from './Icons';

export function AndroidCompanion() {
  const [device, setDevice] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const loadDeviceStatus = async () => {
    try {
      setDevice(await api.getAndroidStatus());
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => { loadDeviceStatus(); }, []);

  const handleDemoLock = async () => {
    if (!device) return;
    setLoading(true);
    setError('');
    setNotice('');
    try {
      const result = await api.remoteLockAndroid(device.device_id);
      setNotice(result.message);
      await loadDeviceStatus();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '14px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <SmartphoneIcon size={22} color="var(--cyan-primary)" />
          <div>
            <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-main)' }}>Android Companion</h2>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Demo workflow; no native Android app is paired</p>
          </div>
        </div>
        <button onClick={handleDemoLock} disabled={!device || loading || device.remote_lock_engaged} className="btn btn-outline">
          <LockIcon size={15} />
          {device?.remote_lock_engaged ? 'Demo lock active' : loading ? 'Updating demo…' : 'Run demo lock action'}
        </button>
      </div>

      <div role="note" style={{ padding: '12px 14px', borderRadius: '9px', background: 'var(--warning-soft)', border: '1px solid var(--warning-border)', color: 'var(--amber-warning)', fontSize: '12px', marginBottom: '16px' }}>
        Demonstration data only. Telemetry and lock changes stay in backend memory. No real device is contacted or locked.
      </div>

      {error && <p role="alert" style={{ color: 'var(--crimson-danger)', marginBottom: '12px' }}>{error}</p>}
      {notice && <p role="status" style={{ color: 'var(--text-muted)', marginBottom: '12px' }}>{notice}</p>}
      {device ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: '12px' }}>
          <div style={{ padding: '14px', borderRadius: '9px', background: 'var(--surface-subtle)', border: '1px solid var(--line-subtle)' }}>
            <span style={{ color: 'var(--text-dim)', fontSize: '10px', textTransform: 'uppercase' }}>Demo device</span>
            <p style={{ color: 'var(--text-main)', fontWeight: 650, marginTop: '4px' }}>{device.device_name}</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{device.connection_status}</p>
          </div>
          <div style={{ padding: '14px', borderRadius: '9px', background: 'var(--surface-subtle)', border: '1px solid var(--line-subtle)' }}>
            <span style={{ color: 'var(--text-dim)', fontSize: '10px', textTransform: 'uppercase' }}>Example telemetry</span>
            <p style={{ color: 'var(--text-main)', fontWeight: 650, marginTop: '4px' }}>{device.battery_percent}% battery</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{device.wifi_ssid}</p>
          </div>
          <div style={{ padding: '14px', borderRadius: '9px', background: 'var(--surface-subtle)', border: '1px solid var(--line-subtle)' }}>
            <span style={{ color: 'var(--text-dim)', fontSize: '10px', textTransform: 'uppercase' }}>Demo lock state</span>
            <p style={{ color: device.remote_lock_engaged ? 'var(--amber-warning)' : 'var(--text-main)', fontWeight: 650, marginTop: '4px' }}>
              {device.remote_lock_engaged ? 'Active in demo only' : 'Not activated'}
            </p>
          </div>
        </div>
      ) : !error ? <p style={{ color: 'var(--text-muted)' }}>Loading companion status…</p> : null}
    </section>
  );
}
