import { useCallback, useEffect, useRef, useState } from 'react';

/**
 * Keeps backend capability state tied to its latest response. A refresh clears
 * current data immediately; a failed refresh cannot leave old success looking
 * current. Sequence numbers discard responses that finish out of order.
 */
export function useStatusResource(loader, { source = 'Guard AI API', intervalMs = 0, validate = () => true } = {}) {
  const sequence = useRef(0);
  const [resource, setResource] = useState({
    state: 'loading', data: null, source, updatedAt: null, lastSuccessAt: null, reason: '',
  });

  const refresh = useCallback(async () => {
    const requestId = ++sequence.current;
    setResource((previous) => ({
      state: 'loading', data: null, source, updatedAt: null,
      lastSuccessAt: previous.lastSuccessAt, reason: '',
    }));
    try {
      const data = await loader();
      if (requestId !== sequence.current) return null;
      if (!validate(data)) throw new Error('The backend returned an invalid status response.');
      const now = new Date();
      setResource({ state: 'verified', data, source, updatedAt: now, lastSuccessAt: now, reason: '' });
      return data;
    } catch (error) {
      if (requestId !== sequence.current) return null;
      setResource((previous) => ({
        state: previous.lastSuccessAt ? 'stale' : 'unavailable',
        data: null, source, updatedAt: null,
        lastSuccessAt: previous.lastSuccessAt,
        reason: error?.message || 'The backend status could not be verified.',
      }));
      return null;
    }
  }, [loader, source, validate]);

  useEffect(() => {
    refresh();
    if (!intervalMs) return undefined;
    const timer = setInterval(refresh, intervalMs);
    return () => {
      clearInterval(timer);
      sequence.current += 1;
    };
  }, [refresh, intervalMs]);

  return { ...resource, refresh };
}

export function formatStatusTime(value) {
  return value instanceof Date ? value.toLocaleString() : 'Never';
}

export function statusLabel(state) {
  return ({ loading: 'Loading', verified: 'Verified', stale: 'Stale', unavailable: 'Unavailable', degraded: 'Degraded', unverified: 'Unverified' })[state] || 'Unverified';
}
