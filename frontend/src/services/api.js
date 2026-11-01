/**
 * Guard AI API client.
 *
 * Development uses Vite's same-origin /api proxy. Production requires an
 * explicit HTTPS FastAPI origin via VITE_API_BASE_URL; no production request
 * silently falls back to localhost or the frontend host.
 */

const DEFAULT_TIMEOUT_MS = 12_000;
const MIN_TIMEOUT_MS = 100;
const MAX_TIMEOUT_MS = 120_000;

export class ApiError extends Error {
  constructor(message, { code = 'api_error', status = null, cause = undefined } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

function apiConfigError(message) {
  return new ApiError(message, { code: 'configuration' });
}

function isLoopback(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return host === 'localhost' || host.endsWith('.localhost') || host === '::1' ||
    host === '0.0.0.0' || /^127(?:\.\d{1,3}){0,3}$/.test(host);
}

/** Resolve and validate public build-time API configuration. */
export function resolveApiConfig({ mode = 'development', apiBaseUrl = '', timeoutMs } = {}) {
  const production = mode === 'production';
  const rawBaseUrl = typeof apiBaseUrl === 'string' ? apiBaseUrl.trim() : '';
  const parsedTimeout = Number.parseInt(timeoutMs, 10);
  const resolvedTimeout = Number.isFinite(parsedTimeout)
    ? Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, parsedTimeout))
    : DEFAULT_TIMEOUT_MS;
  let origin = '';
  let error = null;

  if (production && !rawBaseUrl) {
    error = apiConfigError('Production API is not configured. Set VITE_API_BASE_URL to the FastAPI HTTPS origin.');
  } else if (rawBaseUrl) {
    try {
      const parsed = new URL(rawBaseUrl);
      if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password ||
          parsed.pathname !== '/' || parsed.search || parsed.hash) {
        throw new Error('Use an origin only, for example https://api.example.com.');
      }
      if (production && parsed.protocol !== 'https:') {
        throw new Error('Production API URLs must use HTTPS.');
      }
      if (production && isLoopback(parsed.hostname)) {
        throw new Error('Production API URLs cannot target localhost or a loopback address.');
      }
      origin = parsed.origin;
    } catch (cause) {
      error = apiConfigError(cause.message || 'VITE_API_BASE_URL is invalid.');
    }
  }

  return { origin, timeoutMs: resolvedTimeout, error };
}

function messageForStatus(status) {
  switch (status) {
    case 401: return 'Authentication is required or the session has expired.';
    case 403: return 'The account is not allowed to perform this action.';
    case 404: return 'The requested Guard AI API endpoint was not found.';
    case 408: return 'The backend timed out while processing the request.';
    case 429: return 'Too many requests. Wait briefly and try again.';
    case 500: return 'The Guard AI backend encountered an internal error.';
    case 502:
    case 503:
    case 504: return 'The Guard AI backend is unavailable. Check its deployment and try again.';
    default:
      if (status >= 400 && status < 500) return `The backend rejected the request (HTTP ${status}).`;
      if (status >= 500) return `The backend request failed (HTTP ${status}).`;
      return `The API request failed (HTTP ${status}).`;
  }
}

export async function handleResponse(response) {
  const contentType = response.headers?.get('content-type') || '';
  const isJson = /(?:application\/json|\+json)(?:\s*;|$)/i.test(contentType);
  let data = null;
  let malformed = false;

  if (isJson) {
    try {
      data = await response.json();
    } catch {
      malformed = true;
    }
  }

  if (!response.ok) {
    throw new ApiError(messageForStatus(response.status), {
      code: `http_${response.status}`,
      status: response.status,
    });
  }
  if (malformed || !isJson) {
    throw new ApiError('The Guard AI backend returned a malformed or non-JSON response.', {
      code: 'malformed_response',
      status: response.status,
    });
  }
  return data;
}

/** Factory keeps the transport injectable so timeout and error paths are testable. */
export function createApiClient({
  mode = 'development',
  apiBaseUrl = '',
  timeoutMs = DEFAULT_TIMEOUT_MS,
  fetchImpl = globalThis.fetch,
} = {}) {
  const config = resolveApiConfig({ mode, apiBaseUrl, timeoutMs });
  let accessToken = null;
  let unauthorizedHandler = () => {};
  let forbiddenHandler = () => {};

  function setAccessToken(token) {
    accessToken = typeof token === 'string' && token ? token : null;
  }

  async function request(path, options = {}, { authenticated = true } = {}) {
    if (config.error) throw config.error;
    if (typeof fetchImpl !== 'function') {
      throw new ApiError('This browser does not provide the fetch API.', { code: 'unsupported_runtime' });
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeoutMs);
    const url = config.origin ? `${config.origin}${path}` : path;
    let response;
    const headers = new Headers(options.headers || {});
    if (authenticated && accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
    try {
      response = await fetchImpl(url, { ...options, headers, signal: controller.signal });
    } catch (cause) {
      if (controller.signal.aborted || cause?.name === 'AbortError') {
        throw new ApiError(`The request timed out after ${config.timeoutMs} ms.`, {
          code: 'timeout',
          cause,
        });
      }
      throw new ApiError('Could not connect to the Guard AI backend. Check the API URL and network connection.', {
        code: 'network',
        cause,
      });
    } finally {
      clearTimeout(timer);
    }
    if (response.status === 401 && authenticated && accessToken) {
      setAccessToken(null);
      unauthorizedHandler();
    } else if (response.status === 403) {
      forbiddenHandler();
    }
    return handleResponse(response);
  }

  const get = (path) => request(path);
  const postJson = (path, body, requestOptions) => request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, requestOptions);

  return {
    setAccessToken,
    setUnauthorizedHandler(handler) { unauthorizedHandler = typeof handler === 'function' ? handler : () => {}; },
    setForbiddenHandler(handler) { forbiddenHandler = typeof handler === 'function' ? handler : () => {}; },
    login: (username, password) => postJson('/api/auth/token', { username, password }, { authenticated: false }),
    revoke: () => request('/api/auth/revoke', { method: 'POST' }),
    // System health and agents
    getHealth: () => get('/api/health'),
    getAgents: () => get('/api/v1/agents'),
    getRecentEvents: () => get('/api/v1/agents/events?limit=30'),
    getVoiceBriefing: () => get('/api/v1/agents/informer/briefing'),

    // Scanners
    scanURL: (url) => postJson('/api/v1/scan/url', { url }),
    scanFile: (file) => {
      const formData = new FormData();
      formData.append('file', file);
      return request('/api/v1/scan/file', { method: 'POST', body: formData });
    },
    scanText: (text) => postJson('/api/v1/scan/text', { text }),
    scanNetwork: (networkData) => postJson('/api/v1/scan/network', networkData),
    getThreats: () => get('/api/v1/scan/threats'),

    // Cryptographic vault
    getVaultStatus: () => get('/api/v1/vault/status'),
    lockVault: () => request('/api/v1/vault/lock', { method: 'POST' }),
    unlockVault: (passphrase) => postJson('/api/v1/vault/unlock', { passphrase }),
    getVaultItems: () => get('/api/v1/vault/items'),
    storeVaultItem: (label, plaintext, passphrase, category = 'CREDENTIAL') =>
      postJson('/api/v1/vault/items', { label, plaintext, passphrase, category }),
    decryptVaultItem: (itemId, passphrase) =>
      postJson(`/api/v1/vault/items/${itemId}/decrypt`, { passphrase }),
    generateEscrow: (payload) => postJson('/api/v1/vault/escrow', { payload }),
    restoreEscrow: (recoveryKey, encryptedToken) =>
      postJson('/api/v1/vault/escrow/restore', {
        recovery_key: recoveryKey,
        encrypted_token: encryptedToken,
      }),

    // Audit ledger and optional blockchain anchoring
    getAuditEntries: () => get('/api/v1/audit/entries'),
    verifyAuditLedger: () => get('/api/v1/audit/verify'),
    getBlockchainStatus: () => get('/api/v1/audit/blockchain/status'),
    anchorAuditEntry: (entryId) => request(`/api/v1/audit/entries/${entryId}/anchor`, { method: 'POST' }),
    verifyBlockchainEntry: (entryId) => get(`/api/v1/audit/entries/${entryId}/verify-blockchain`),

    // Emergency response
    getEmergencyStatus: () => get('/api/v1/emergency/status'),
    activateLockdown: (level, reason, humanConfirmed = true) =>
      postJson('/api/v1/emergency/activate', { level, reason, human_confirmed: humanConfirmed }),
    resetLockdown: (humanConfirmed = true) =>
      postJson('/api/v1/emergency/reset', { human_confirmed: humanConfirmed }),
    getQuarantine: () => get('/api/v1/emergency/quarantine'),
    simulateContainment: (actionType, target) =>
      postJson('/api/v1/emergency/simulate-containment', { action_type: actionType, target }),

    // URL preview does not fetch remote page contents
    previewURLSafely: (url) => postJson('/api/v1/sandbox/preview-url', { url }),

    // Android demo endpoints
    getAndroidStatus: () => get('/api/v1/android/status'),
    remoteLockAndroid: (deviceId) => postJson('/api/v1/android/remote-lock', { device_id: deviceId }),
  };
}

const viteEnv = import.meta.env || {};
export const api = createApiClient({
  mode: viteEnv.PROD ? 'production' : 'development',
  apiBaseUrl: viteEnv.VITE_API_BASE_URL || '',
  timeoutMs: viteEnv.VITE_API_TIMEOUT_MS,
});
