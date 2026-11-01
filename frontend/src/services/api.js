/**
 * Guard AI API Client
 * Interfaces with FastAPI Backend at /api/v1
 */

const API_BASE = '/api/v1';

async function handleResponse(response) {
  if (!response.ok) {
    let errorDetail = `Request failed (${response.status})`;
    try {
      const data = await response.json();
      errorDetail = data.detail || data.message || errorDetail;
    } catch (e) {
      // ignore
    }
    throw new Error(errorDetail);
  }
  return response.json();
}

export const api = {
  // System Health
  async getHealth() {
    const res = await fetch('/api/health');
    return handleResponse(res);
  },

  // Multi-Agent Status
  async getAgents() {
    const res = await fetch(`${API_BASE}/agents`);
    return handleResponse(res);
  },

  async getRecentEvents() {
    const res = await fetch(`${API_BASE}/agents/events?limit=30`);
    return handleResponse(res);
  },

  async getVoiceBriefing() {
    const res = await fetch(`${API_BASE}/agents/informer/briefing`);
    return handleResponse(res);
  },

  // Scanners
  async scanURL(url) {
    const res = await fetch(`${API_BASE}/scan/url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return handleResponse(res);
  },

  async scanFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/scan/file`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse(res);
  },

  async scanText(text) {
    const res = await fetch(`${API_BASE}/scan/text`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    return handleResponse(res);
  },

  async scanNetwork(networkData) {
    const res = await fetch(`${API_BASE}/scan/network`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(networkData),
    });
    return handleResponse(res);
  },

  async getThreats() {
    const res = await fetch(`${API_BASE}/scan/threats`);
    return handleResponse(res);
  },

  // Cryptographic Vault
  async getVaultStatus() {
    const res = await fetch(`${API_BASE}/vault/status`);
    return handleResponse(res);
  },

  async lockVault() {
    const res = await fetch(`${API_BASE}/vault/lock`, { method: 'POST' });
    return handleResponse(res);
  },

  async unlockVault(passphrase) {
    const res = await fetch(`${API_BASE}/vault/unlock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase }),
    });
    return handleResponse(res);
  },

  async getVaultItems() {
    const res = await fetch(`${API_BASE}/vault/items`);
    return handleResponse(res);
  },

  async storeVaultItem(label, plaintext, passphrase, category = 'CREDENTIAL') {
    const res = await fetch(`${API_BASE}/vault/items`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, plaintext, passphrase, category }),
    });
    return handleResponse(res);
  },

  async decryptVaultItem(itemId, passphrase) {
    const res = await fetch(`${API_BASE}/vault/items/${itemId}/decrypt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase }),
    });
    return handleResponse(res);
  },

  async generateEscrow(payload) {
    const res = await fetch(`${API_BASE}/vault/escrow`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload }),
    });
    return handleResponse(res);
  },

  // Audit Ledger
  async getAuditEntries() {
    const res = await fetch(`${API_BASE}/audit/entries`);
    return handleResponse(res);
  },

  async verifyAuditLedger() {
    const res = await fetch(`${API_BASE}/audit/verify`);
    return handleResponse(res);
  },

  // Emergency & Lockdown
  async getEmergencyStatus() {
    const res = await fetch(`${API_BASE}/emergency/status`);
    return handleResponse(res);
  },

  async activateLockdown(level, reason, humanConfirmed = true) {
    const res = await fetch(`${API_BASE}/emergency/activate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level, reason, human_confirmed: humanConfirmed }),
    });
    return handleResponse(res);
  },

  async resetLockdown(humanConfirmed = true) {
    const res = await fetch(`${API_BASE}/emergency/reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ human_confirmed: humanConfirmed }),
    });
    return handleResponse(res);
  },

  async getQuarantine() {
    const res = await fetch(`${API_BASE}/emergency/quarantine`);
    return handleResponse(res);
  },

  async simulateContainment(actionType, target) {
    const res = await fetch(`${API_BASE}/emergency/simulate-containment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action_type: actionType, target }),
    });
    return handleResponse(res);
  },

  // Isolated Sandbox
  async previewURLSafely(url) {
    const res = await fetch(`${API_BASE}/sandbox/preview-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    return handleResponse(res);
  },

  // Android Companion
  async getAndroidStatus() {
    const res = await fetch(`${API_BASE}/android/status`);
    return handleResponse(res);
  },

  async remoteLockAndroid(deviceId) {
    const res = await fetch(`${API_BASE}/android/remote-lock`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ device_id: deviceId }),
    });
    return handleResponse(res);
  },
};
