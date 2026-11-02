import React, { useState } from 'react';
import { api } from '../services/api';
import { GlobeIcon, AlertIcon } from './Icons';

export function IsolatedSandbox() {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [review, setReview] = useState(null);
  const [error, setError] = useState('');

  const handleReview = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    setReview(null);
    try {
      setReview(await api.previewURLSafely(targetUrl));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="glass-panel" style={{ padding: '24px', marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '14px' }}>
        <GlobeIcon size={20} color="var(--cyan-primary)" />
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: 'var(--text-main)' }}>URL Review</h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Local review only; remote content is not fetched or rendered.</p>
        </div>
      </div>

      <form onSubmit={handleReview} style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
        <input
          type="text"
          value={targetUrl}
          onChange={(event) => setTargetUrl(event.target.value)}
          placeholder="Enter a URL to review locally"
          className="input-field"
          style={{ flex: 1 }}
          maxLength={2048}
          required
        />
        <button type="submit" disabled={loading} className="btn btn-primary" style={{ whiteSpace: 'nowrap' }}>
          {loading ? 'Reviewing…' : 'Review URL'}
        </button>
      </form>

      <div style={{ padding: '10px 14px', background: 'var(--warning-soft)', border: '1px solid var(--warning-border)', borderRadius: '6px', color: 'var(--amber-warning)', fontSize: '12px', display: 'flex', gap: '8px' }}>
        <AlertIcon size={16} />
        <span>A low heuristic score does not mean a URL is safe. A hardened isolated browser is not included in this prototype.</span>
      </div>

      {error && <p role="alert" style={{ color: 'var(--crimson-danger)', marginTop: '14px' }}>{error}</p>}
      {review && (
        <div style={{ marginTop: '16px', padding: '14px', borderRadius: '8px', background: 'var(--surface-subtle)' }}>
          <strong style={{ color: 'var(--text-main)' }}>{review.url}</strong>
          <p style={{ color: 'var(--amber-warning)', marginTop: '8px', fontSize: '13px' }}>{review.warning}</p>
          <ul style={{ color: 'var(--text-muted)', margin: '8px 0 0 18px', fontSize: '12px' }}>
            {review.limitations?.map((limitation) => <li key={limitation}>{limitation}</li>)}
          </ul>
        </div>
      )}
    </section>
  );
}
