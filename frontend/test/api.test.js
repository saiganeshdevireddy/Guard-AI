import assert from 'node:assert/strict';
import test from 'node:test';
import { ApiError, createApiClient, resolveApiConfig } from '../src/services/api.js';
import { AuthSession } from '../src/services/authSession.js';

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('production requires a public HTTPS API origin and rejects loopback hosts', () => {
  assert.equal(resolveApiConfig({ mode: 'production' }).error?.code, 'configuration');
  assert.equal(resolveApiConfig({ mode: 'production', apiBaseUrl: 'http://api.example.com' }).error?.code, 'configuration');
  assert.equal(resolveApiConfig({ mode: 'production', apiBaseUrl: 'https://localhost:8000' }).error?.code, 'configuration');
  assert.equal(resolveApiConfig({ mode: 'production', apiBaseUrl: 'https://127.0.0.1:8000' }).error?.code, 'configuration');
  const valid = resolveApiConfig({ mode: 'production', apiBaseUrl: 'https://api.example.com' });
  assert.equal(valid.origin, 'https://api.example.com');
  assert.equal(valid.error, null);
});

test('development keeps same-origin paths for the Vite /api proxy', async () => {
  const calls = [];
  const client = createApiClient({
    mode: 'development',
    fetchImpl: async (url) => { calls.push(url); return jsonResponse({ agents: [] }); },
  });
  await client.getAgents();
  await client.getHealth();
  assert.deepEqual(calls, ['/api/v1/agents', '/api/health']);
});

test('production requests use the configured HTTPS origin and make no request when unset', async () => {
  const calls = [];
  const configured = createApiClient({
    mode: 'production',
    apiBaseUrl: 'https://api.guard-ai.example',
    fetchImpl: async (url) => { calls.push(url); return jsonResponse({ status: 'OPERATIONAL' }); },
  });
  await configured.getAgents();
  assert.equal(calls[0], 'https://api.guard-ai.example/api/v1/agents');
  let unconfiguredFetches = 0;
  const unconfigured = createApiClient({
    mode: 'production',
    fetchImpl: async () => { unconfiguredFetches += 1; return jsonResponse({}); },
  });
  await assert.rejects(unconfigured.getHealth(), (error) => error.code === 'configuration');
  assert.equal(unconfiguredFetches, 0);
});

test('HTTP authentication, authorization, missing endpoint, rate limit, and server errors are distinct', async (t) => {
  const cases = [
    [401, 'http_401', 'Authentication is required'],
    [403, 'http_403', 'not allowed'],
    [404, 'http_404', 'endpoint was not found'],
    [429, 'http_429', 'Too many requests'],
    [500, 'http_500', 'internal error'],
  ];
  for (const [status, code, message] of cases) {
    await t.test(`HTTP ${status}`, async () => {
      const client = createApiClient({
        mode: 'development',
        fetchImpl: async () => jsonResponse({ detail: 'private backend detail' }, status),
      });
      await assert.rejects(client.getHealth(), (error) => {
        assert.ok(error instanceof ApiError);
        assert.equal(error.status, status);
        assert.equal(error.code, code);
        assert.match(error.message, new RegExp(message, 'i'));
        assert.doesNotMatch(error.message, /private backend detail/);
        return true;
      });
    });
  }
});

test('malformed and non-JSON successful responses are rejected', async (t) => {
  await t.test('malformed JSON', async () => {
    const client = createApiClient({ mode: 'development', fetchImpl: async () => new Response('{', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }) });
    await assert.rejects(client.getHealth(), (error) => error.code === 'malformed_response');
  });
  await t.test('HTML error page with successful status', async () => {
    const client = createApiClient({ mode: 'development', fetchImpl: async () => new Response('<html>ok</html>', {
      status: 200,
      headers: { 'content-type': 'text/html' },
    }) });
    await assert.rejects(client.getHealth(), (error) => error.code === 'malformed_response');
  });
});

test('network failures are surfaced as API errors', async () => {
  const client = createApiClient({
    mode: 'development',
    fetchImpl: async () => { throw new TypeError('network unavailable'); },
  });
  await assert.rejects(client.getHealth(), (error) => error.code === 'network');
});

test('requests abort at the configured timeout', async () => {
  const client = createApiClient({
    mode: 'development',
    timeoutMs: 20,
    fetchImpl: (_url, { signal }) => new Promise((resolve, reject) => {
      signal.addEventListener('abort', () => {
        const error = new Error('aborted');
        error.name = 'AbortError';
        reject(error);
      }, { once: true });
    }),
  });
  await assert.rejects(client.getHealth(), (error) => error.code === 'timeout');
});

test('login never sends an existing bearer token and protected requests attach the in-memory token', async () => {
  const calls = [];
  const client = createApiClient({ mode: 'development', fetchImpl: async (url, options) => {
    calls.push({ url, options });
    return jsonResponse(url === '/api/auth/token'
      ? { access_token: 'short-lived-test-token', token_type: 'bearer', expires_in: 900 }
      : { agents: [] });
  } });
  client.setAccessToken('prior-token');
  const result = await client.login('analyst', 'password-not-in-a-real-test-account');
  assert.equal(result.access_token, 'short-lived-test-token');
  assert.equal(calls[0].options.headers.get('Authorization'), null);
  client.setAccessToken(result.access_token);
  await client.getAgents();
  assert.equal(calls[1].options.headers.get('Authorization'), 'Bearer short-lived-test-token');
});

test('HTTP 401 clears the bearer and signals session invalidation; HTTP 403 preserves the session', async (t) => {
  await t.test('401 invalidates', async () => {
    let invalidated = 0;
    let authorization = null;
    const client = createApiClient({ mode: 'development', fetchImpl: async (_url, options) => {
      authorization = options.headers.get('Authorization');
      return jsonResponse({ detail: 'expired' }, 401);
    } });
    client.setAccessToken('test-token');
    client.setUnauthorizedHandler(() => { invalidated += 1; });
    await assert.rejects(client.getAgents(), (error) => error.status === 401 && error.code === 'http_401');
    assert.equal(authorization, 'Bearer test-token');
    assert.equal(invalidated, 1);
    await assert.rejects(client.getAgents(), (error) => error.status === 401);
    assert.equal(authorization, null);
    assert.equal(invalidated, 1);
  });
  await t.test('403 remains a permission error without invalidating token', async () => {
    let denied = 0;
    let invalidated = 0;
    const client = createApiClient({ mode: 'development', fetchImpl: async () => jsonResponse({ detail: 'forbidden' }, 403) });
    client.setAccessToken('test-token');
    client.setForbiddenHandler(() => { denied += 1; });
    client.setUnauthorizedHandler(() => { invalidated += 1; });
    await assert.rejects(client.getVaultStatus(), (error) => error.status === 403 && error.code === 'http_403');
    assert.equal(denied, 1);
    assert.equal(invalidated, 0);
  });
});

test('AuthSession clears tokens on expiry, invalidation, and logout; logout calls backend revocation', async () => {
  let clock = 1000;
  let expiryCallback;
  let scheduledDelay;
  let revoked = 0;
  let token = null;
  const listeners = [];
  const client = {
    setAccessToken(value) { token = value; },
    setUnauthorizedHandler(handler) { this.unauthorized = handler; },
    setForbiddenHandler() {},
    async login() { return { access_token: 'memory-token', expires_in: 60 }; },
    async getAgents() { return { agents: [] }; },
    async revoke() { revoked += 1; },
  };
  const session = new AuthSession(client, {
    now: () => clock,
    schedule(callback, delay) { expiryCallback = callback; scheduledDelay = delay; return 1; },
    cancel() {},
  });
  session.subscribe((state) => listeners.push(state));
  await session.login('analyst', 'password');
  assert.equal(token, 'memory-token');
  assert.equal(scheduledDelay, 60_000);
  assert.equal(session.snapshot().isAuthenticated, true);
  clock += 60_001;
  assert.equal(session.snapshot().isAuthenticated, false);
  assert.equal(session.snapshot().endReason, 'expired');
  assert.equal(token, null);

  clock = 2000;
  await session.login('analyst', 'password');
  client.unauthorized();
  assert.equal(session.snapshot().endReason, 'invalid');
  assert.equal(token, null);

  await session.login('analyst', 'password');
  await session.logout();
  assert.equal(revoked, 1);
  assert.equal(session.snapshot().endReason, 'logout');
  assert.equal(token, null);
  assert.ok(listeners.length >= 5);
  assert.equal(typeof expiryCallback, 'function');
});
