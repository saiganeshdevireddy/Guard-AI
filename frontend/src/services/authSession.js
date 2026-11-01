/** In-memory bearer session. Tokens are never written to browser storage. */
export class AuthSession {
  constructor(client, { schedule = setTimeout, cancel = clearTimeout, now = () => Date.now() } = {}) {
    this.client = client;
    this.schedule = schedule;
    this.cancel = cancel;
    this.now = now;
    this.listeners = new Set();
    this.expiryTimer = null;
    this.state = { accessToken: null, username: null, expiresAt: null, endReason: null, permissionError: false };
    this.client.setUnauthorizedHandler(() => this.clear('invalid'));
    this.client.setForbiddenHandler(() => {
      this.state = { ...this.state, permissionError: true };
      this.emit();
    });
  }

  snapshot() {
    if (this.state.accessToken && this.state.expiresAt <= this.now()) this.clear('expired');
    return { ...this.state, isAuthenticated: Boolean(this.state.accessToken) };
  }

  subscribe(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  emit() {
    const next = this.snapshotWithoutExpiry();
    for (const listener of this.listeners) listener(next);
  }

  snapshotWithoutExpiry() {
    return { ...this.state, isAuthenticated: Boolean(this.state.accessToken) };
  }

  async login(username, password) {
    const result = await this.client.login(username, password);
    if (typeof result?.access_token !== 'string' || !result.access_token ||
        !Number.isFinite(result.expires_in) || result.expires_in < 1 || result.expires_in > 3600) {
      throw Object.assign(new Error('The authentication service returned an invalid session.'), { code: 'malformed_auth_response' });
    }
    this.cancelExpiry();
    const expiresAt = this.now() + result.expires_in * 1000;
    // Verify the issued credential on a protected route before mounting any dashboard UI.
    this.client.setAccessToken(result.access_token);
    try {
      await this.client.getAgents();
    } catch (error) {
      this.client.setAccessToken(null);
      throw error;
    }
    this.state = { accessToken: result.access_token, username, expiresAt, endReason: null, permissionError: false };
    this.expiryTimer = this.schedule(() => this.clear('expired'), result.expires_in * 1000);
    this.emit();
    return this.snapshotWithoutExpiry();
  }

  async logout() {
    let revokeError;
    if (this.state.accessToken) {
      try { await this.client.revoke(); }
      catch (error) { revokeError = error; }
    }
    this.clear(revokeError ? 'logout-unconfirmed' : 'logout');
    if (revokeError) throw revokeError;
  }

  clear(reason = null) {
    this.cancelExpiry();
    this.client.setAccessToken(null);
    this.state = { accessToken: null, username: null, expiresAt: null, endReason: reason, permissionError: false };
    this.emit();
  }

  clearPermissionError() {
    if (!this.state.permissionError) return;
    this.state = { ...this.state, permissionError: false };
    this.emit();
  }

  cancelExpiry() {
    if (this.expiryTimer !== null) this.cancel(this.expiryTimer);
    this.expiryTimer = null;
  }
}
