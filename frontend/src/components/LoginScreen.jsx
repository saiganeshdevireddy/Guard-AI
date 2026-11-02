import React, { useState } from 'react';
import { useTheme } from '../theme/ThemeProvider';

export function LoginScreen({ auth }) {
  const { preference, setPreference } = useTheme();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      await auth.login(username.trim(), password);
      setPassword('');
    } catch (cause) {
      setPassword('');
      setError(cause?.status === 401
        ? 'Username or password was not accepted.'
        : cause?.status === 403
          ? 'This account is not allowed to sign in.'
          : cause?.code === 'network' || cause?.code === 'timeout'
            ? 'The Guard AI authentication service could not be reached.'
            : cause?.message || 'Sign in failed. Check the backend and try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-panel" aria-labelledby="auth-title">
        <div className="auth-panel-top">
          <div className="auth-brand-mark" aria-hidden="true">G</div>
          <div className="auth-theme" role="group" aria-label="Color theme">
            {['dark', 'light', 'system'].map((mode) => (
              <button key={mode} type="button" aria-pressed={preference === mode}
                onClick={() => setPreference(mode)}>{mode[0].toUpperCase() + mode.slice(1)}</button>
            ))}
          </div>
        </div>
        <p className="eyebrow">SECURE ACCESS GATEWAY</p>
        <h1 id="auth-title">Sign in to Guard AI</h1>
        <p className="auth-copy">Use an account provisioned by your Guard AI administrator to access protected security operations.</p>
        {auth.endReason === 'expired' && <p role="status" className="status-notice status-notice-warning">Your session expired. Sign in again to continue.</p>}
        {auth.endReason === 'invalid' && <p role="status" className="status-notice status-notice-warning">The backend rejected this session. Sign in again to continue.</p>}
        {auth.endReason === 'logout' && <p role="status" className="status-notice">You have signed out.</p>}
        {auth.endReason === 'logout-unconfirmed' && <p role="alert" className="status-notice status-notice-error">You are signed out locally, but the backend could not confirm token revocation. Check the API connection and contact an administrator if needed.</p>}
        {error && <p role="alert" className="status-notice status-notice-error">{error}</p>}
        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="guard-username">Username</label>
          <input id="guard-username" name="username" autoComplete="username" required maxLength={128}
            value={username} onChange={(event) => setUsername(event.target.value)} />
          <label htmlFor="guard-password">Password</label>
          <input id="guard-password" name="password" type="password" autoComplete="current-password" required maxLength={1024}
            value={password} onChange={(event) => setPassword(event.target.value)} />
          <button className="btn btn-primary auth-submit" type="submit" disabled={busy || !username.trim() || !password}>
            {busy ? 'Verifying credentials…' : 'Sign in securely'}
          </button>
        </form>
        <p className="auth-session-note">Session tokens stay in memory for this tab and are cleared on sign out, expiry, or backend rejection.</p>
      </section>
      <footer className="auth-footer">Guard AI · Protected access is verified by the FastAPI backend</footer>
    </main>
  );
}
