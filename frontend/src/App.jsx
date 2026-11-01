import React, { useState, useEffect, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { AgentGrid } from './components/AgentGrid';
import { VoiceBriefing } from './components/VoiceBriefing';
import { QuickScanner } from './components/QuickScanner';
import { CryptoVault } from './components/CryptoVault';
import { IsolatedSandbox } from './components/IsolatedSandbox';
import { EmergencyLockdown } from './components/EmergencyLockdown';
import { AuditLedger } from './components/AuditLedger';
import { AndroidCompanion } from './components/AndroidCompanion';
import { api } from './services/api';
import { voice } from './services/voice';
import { useTheme } from './theme/ThemeProvider';
import { useAuth } from './services/AuthProvider';
import { LoginScreen } from './components/LoginScreen';

function DashboardApp() {
  const auth = useAuth();
  const { preference: themePreference, setPreference: setThemePreference } = useTheme();
  const [agents, setAgents] = useState([]);
  const [briefing, setBriefing] = useState(null);
  const [emergencyStatus, setEmergencyStatus] = useState(null);
  const [isMuted, setIsMuted] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [privacyMode, setPrivacyMode] = useState(null);
  const [backendAvailable, setBackendAvailable] = useState(null);
  const [vaultStatus, setVaultStatus] = useState(null);
  const [auditStatus, setAuditStatus] = useState(null);
  const [freshness, setFreshness] = useState({});
  const [telemetryDegraded, setTelemetryDegraded] = useState(false);
  const [activeTab, setActiveTab] = useState('dashboard'); // 'dashboard', 'scanner', 'vault', 'sandbox', 'emergency', 'audit', 'android'
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [threatCount, setThreatCount] = useState(null);
  const telemetryRequest = useRef(0);

  useEffect(() => {
    fetchSystemState();
    const interval = setInterval(fetchSystemState, 6000);
    return () => clearInterval(interval);
  }, []);

  const fetchSystemState = async () => {
    const requestId = ++telemetryRequest.current;
    setBackendAvailable(null); setAgents([]); setBriefing(null); setEmergencyStatus(null);
    setPrivacyMode(null); setThreatCount(null); setVaultStatus(null); setAuditStatus(null);
    try {
      const [healthRes, agentsRes, briefingRes, emergRes, threatsRes, vaultRes, auditRes] = await Promise.allSettled([
        api.getHealth(),
        api.getAgents(),
        api.getVoiceBriefing(),
        api.getEmergencyStatus(),
        api.getThreats(),
        api.getVaultStatus(),
        api.verifyAuditLedger(),
      ]);

      if (requestId !== telemetryRequest.current) return;
      const updatedAt = new Date();
      const nextFreshness = {};

      if (healthRes.status === 'fulfilled') {
        setBackendAvailable(healthRes.value.status === 'OPERATIONAL');
        setPrivacyMode(healthRes.value.privacy_mode || 'UNKNOWN');
      } else {
        setBackendAvailable(false);
      }
      if (healthRes.status === 'fulfilled') nextFreshness.backend = updatedAt;
      if (agentsRes.status === 'fulfilled' && Array.isArray(agentsRes.value?.agents)) { setAgents(agentsRes.value.agents); nextFreshness.agents = updatedAt; }
      if (briefingRes.status === 'fulfilled' && briefingRes.value) { setBriefing(briefingRes.value); nextFreshness.briefing = updatedAt; }
      if (emergRes.status === 'fulfilled' && typeof emergRes.value?.is_active === 'boolean') { setEmergencyStatus(emergRes.value); nextFreshness.emergency = updatedAt; }
      if (threatsRes.status === 'fulfilled' && Number.isFinite(threatsRes.value?.count)) { setThreatCount(threatsRes.value.count); nextFreshness.threats = updatedAt; }
      if (vaultRes.status === 'fulfilled' && typeof vaultRes.value?.is_locked === 'boolean' && typeof vaultRes.value?.algorithm === 'string') { setVaultStatus(vaultRes.value); nextFreshness.vault = updatedAt; }
      if (auditRes.status === 'fulfilled' && typeof auditRes.value?.valid === 'boolean' && Number.isFinite(auditRes.value?.block_count)) { setAuditStatus(auditRes.value); nextFreshness.audit = updatedAt; }
      setFreshness(nextFreshness);
      setTelemetryDegraded([healthRes, agentsRes, briefingRes, emergRes, threatsRes, vaultRes, auditRes].some((result) => result.status !== 'fulfilled'));
    } catch (err) {
      if (requestId === telemetryRequest.current) {
        setBackendAvailable(false); setAgents([]); setBriefing(null); setEmergencyStatus(null);
        setThreatCount(null); setVaultStatus(null); setAuditStatus(null); setFreshness({}); setTelemetryDegraded(true);
      }
    }
  };

  const handleToggleMute = () => {
    const muted = voice.toggleMute();
    setIsMuted(muted);
  };

  const handleSpeak = (text) => {
    if (!text) return;
    if (isSpeaking) {
      voice.stop();
      setIsSpeaking(false);
      return;
    }
    voice.speak(
      text,
      () => setIsSpeaking(true),
      () => setIsSpeaking(false)
    );
  };

  const handleThreatDetected = (scanResult) => {
    fetchSystemState();
    // Speak automatically if Informer voice is unmuted
    if (!isMuted && scanResult.hybrid_explanation?.ai_summary) {
      handleSpeak(scanResult.hybrid_explanation.ai_summary);
    }
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Cyber Navigation */}
      <Navbar
        isMuted={isMuted}
        onToggleMute={handleToggleMute}
        isSpeaking={isSpeaking}
        emergencyStatus={emergencyStatus}
        privacyMode={privacyMode}
        themePreference={themePreference}
        onThemeChange={setThemePreference}
        username={auth.username}
        onLogout={() => auth.logout().catch(() => {})}
      />

      <main className={`app-layout${sidebarCollapsed ? ' sidebar-collapsed' : ''}`}>
        <aside className="app-sidebar" aria-label="Main navigation">
          <div className="sidebar-heading"><span className="eyebrow">COMMAND MENU</span><button className="sidebar-toggle" type="button" onClick={() => setSidebarCollapsed(!sidebarCollapsed)} aria-label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}>{sidebarCollapsed ? '›' : '‹'}</button></div>
          <nav className="view-tabs" aria-label="Guard AI screens">
            {[
              { id: 'dashboard', label: 'Command center' },
              { id: 'scanner', label: 'Threat scanner' },
              { id: 'vault', label: 'Cryptographic vault' },
              { id: 'sandbox', label: 'Security sandbox' },
              { id: 'emergency', label: 'Emergency response' },
              { id: 'audit', label: 'Audit ledger' },
              { id: 'android', label: 'Android companion' },
            ].map((tab, index) => (
              <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)} className={`view-tab${activeTab === tab.id ? ' is-active' : ''}`} aria-current={activeTab === tab.id ? 'page' : undefined} title={tab.label}>
                <span className="view-tab-index">{String(index + 1).padStart(2, '0')}</span><span className="view-tab-label">{tab.label}</span>
              </button>
            ))}
          </nav>
          <div className="sidebar-footnote"><span className={`connection-dot ${backendAvailable && !telemetryDegraded ? 'is-online' : ''}`} />{backendAvailable === null ? 'Checking API' : !backendAvailable ? 'API unavailable' : telemetryDegraded ? 'API degraded' : 'API connected'}</div>
        </aside>

        <section className="app-content">
        {auth.permissionError && <div role="alert" className="status-notice status-notice-error">The backend denied a request for this account (HTTP 403). Your session remains active, but the requested operation is not permitted. <button className="btn btn-outline" type="button" onClick={auth.clearPermissionError}>Dismiss</button></div>}
        {/* Real-time Telemetry Bar */}
        {telemetryDegraded && <div role="status" className="status-notice status-notice-warning">Some live status requests failed. Affected capabilities are shown as unavailable until the backend responds again.</div>}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '14px',
          marginBottom: '24px',
        }}>
          <div className="glass-panel telemetry-tile" title={`Source: Guard AI API · Last successful update: ${freshness.agents?.toLocaleString() || 'Never'}`} style={{ padding: '14px 18px' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Registered Agents</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '24px', fontWeight: '800', color: 'var(--cyan-primary)', fontFamily: 'var(--font-mono)' }}>
                {agents.length}
              </span>
              <span style={{ fontSize: '12px', color: backendAvailable === false ? 'var(--crimson-danger)' : 'var(--text-dim)' }}>
                {backendAvailable === null ? 'Checking backend' : backendAvailable ? 'Reported by backend' : 'Backend unavailable'}
              </span>
            </div>
          </div>

          <div className="glass-panel telemetry-tile" title={`Source: Guard AI API · Last successful update: ${freshness.threats?.toLocaleString() || 'Never'}`} style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Incidents Detected</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '24px', fontWeight: '800', color: threatCount > 0 ? 'var(--amber-warning)' : 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {threatCount ?? '—'}
              </span>
              <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{threatCount === null ? 'Unavailable' : `Updated ${freshness.threats?.toLocaleTimeString() || 'unknown'}`}</span>
            </div>
          </div>

          <div className="glass-panel telemetry-tile" title={`Source: Guard AI API · Last successful update: ${freshness.vault?.toLocaleString() || 'Never'}`} style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Cryptographic Vault</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '16px', fontWeight: '700', color: 'var(--text-main)' }}>
                {vaultStatus?.algorithm || 'Unverified'}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{vaultStatus ? `${vaultStatus.is_locked ? 'Locked' : 'Unlocked'} · ${freshness.vault?.toLocaleTimeString() || ''}` : 'Unverified'}</span>
            </div>
          </div>

          <div className="glass-panel telemetry-tile" title={`Source: Guard AI API · Last successful verification: ${freshness.audit?.toLocaleString() || 'Never'}`} style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Audit Ledger</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '16px', fontWeight: '700', color: auditStatus?.valid ? 'var(--emerald-success)' : 'var(--text-muted)' }}>
                {auditStatus ? (auditStatus.valid ? 'Integrity verified' : 'Integrity issue') : 'Unverified'}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>{auditStatus ? `${auditStatus.block_count} entries · ${freshness.audit?.toLocaleTimeString() || ''}` : 'Unverified'}</span>
            </div>
          </div>
        </div>

        {/* Informer AI Voice Briefing Card */}
        <VoiceBriefing
          briefing={briefing}
          onSpeak={handleSpeak}
          isSpeaking={isSpeaking}
          isMuted={isMuted}
        />

        {/* Active Tab View */}
        {activeTab === 'dashboard' && (
          <div>
            <AgentGrid agents={agents} stateReceived={backendAvailable} updatedAt={freshness.agents} />
            <QuickScanner onThreatDetected={handleThreatDetected} />
          </div>
        )}

        {activeTab === 'scanner' && (
          <QuickScanner onThreatDetected={handleThreatDetected} />
        )}

        {activeTab === 'vault' && (
          <CryptoVault onVaultUpdated={fetchSystemState} />
        )}

        {activeTab === 'sandbox' && (
          <IsolatedSandbox />
        )}

        {activeTab === 'emergency' && (
          <EmergencyLockdown onStatusChanged={fetchSystemState} />
        )}

        {activeTab === 'audit' && (
          <AuditLedger />
        )}

        {activeTab === 'android' && (
          <AndroidCompanion />
        )}
        </section>
      </main>

      {/* Footer */}
      <footer style={{
        textAlign: 'center',
        padding: '20px',
        borderTop: '1px solid var(--line-subtle)',
        fontSize: '12px',
        color: 'var(--text-dim)',
      }}>
        Guard AI &bull; Local rule-based security prototype &bull; Native device protection is not included
      </footer>
    </div>
  );
}

export default function App() {
  const auth = useAuth();
  if (!auth.isAuthenticated) return <LoginScreen auth={auth} />;
  return <DashboardApp />;
}
