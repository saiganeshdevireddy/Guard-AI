import React, { useState, useEffect } from 'react';
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

export default function App() {
  const [agents, setAgents] = useState([]);
  const [briefing, setBriefing] = useState(null);
  const [emergencyStatus, setEmergencyStatus] = useState(null);
  const [isMuted, setIsMuted] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);
  const [localPrivacyMode, setLocalPrivacyMode] = useState(true);
  const [activeTab, setActiveTab] = useState('dashboard'); // 'dashboard', 'scanner', 'vault', 'sandbox', 'emergency', 'audit', 'android'
  const [threatCount, setThreatCount] = useState(0);

  useEffect(() => {
    fetchSystemState();
    const interval = setInterval(fetchSystemState, 6000);
    return () => clearInterval(interval);
  }, []);

  const fetchSystemState = async () => {
    try {
      const [agentsRes, briefingRes, emergRes, threatsRes] = await Promise.allSettled([
        api.getAgents(),
        api.getVoiceBriefing(),
        api.getEmergencyStatus(),
        api.getThreats(),
      ]);

      if (agentsRes.status === 'fulfilled') setAgents(agentsRes.value.agents || []);
      if (briefingRes.status === 'fulfilled') setBriefing(briefingRes.value);
      if (emergRes.status === 'fulfilled') setEmergencyStatus(emergRes.value);
      if (threatsRes.status === 'fulfilled') setThreatCount(threatsRes.value.count || 0);
    } catch (err) {
      console.error('Error polling system telemetry:', err);
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
        localPrivacyMode={localPrivacyMode}
        onTogglePrivacy={() => setLocalPrivacyMode(!localPrivacyMode)}
      />

      <main style={{ flex: 1, maxWidth: '1280px', width: '100%', margin: '0 auto', padding: '24px 20px' }}>
        {/* Real-time Telemetry Bar */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '14px',
          marginBottom: '24px',
        }}>
          <div className="glass-panel" style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Active Defense Grid</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '24px', fontWeight: '800', color: '#00f2fe', fontFamily: 'var(--font-mono)' }}>
                {agents.length || 10}
              </span>
              <span style={{ fontSize: '12px', color: '#10b981' }}>Agents Synchronized</span>
            </div>
          </div>

          <div className="glass-panel" style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Incidents Detected</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '24px', fontWeight: '800', color: threatCount > 0 ? '#f59e0b' : '#10b981', fontFamily: 'var(--font-mono)' }}>
                {threatCount}
              </span>
              <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>Lifetime Events</span>
            </div>
          </div>

          <div className="glass-panel" style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Cryptographic Vault</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '18px', fontWeight: '700', color: '#10b981' }}>
                AES-256-GCM
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>600K PBKDF2</span>
            </div>
          </div>

          <div className="glass-panel" style={{ padding: '14px 18px' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', textTransform: 'uppercase' }}>Audit Ledger</span>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginTop: '4px' }}>
              <span style={{ fontSize: '18px', fontWeight: '700', color: '#8b5cf6' }}>
                SHA-256 Chain
              </span>
              <span style={{ fontSize: '11px', color: '#10b981' }}>Immutable</span>
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

        {/* Main View Navigation Tabs */}
        <div style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '8px',
          marginBottom: '22px',
          paddingBottom: '12px',
          borderBottom: '1px solid rgba(0, 242, 254, 0.15)',
        }}>
          {[
            { id: 'dashboard', label: '⚡ Multi-Agent Matrix' },
            { id: 'scanner', label: '🎯 Threat Scanner' },
            { id: 'vault', label: '🔐 Cryptographic Vault' },
            { id: 'sandbox', label: '🧪 Isolated Sandbox' },
            { id: 'emergency', label: '🚨 Emergency Response' },
            { id: 'audit', label: '⛓️ Blockchain Ledger' },
            { id: 'android', label: '📱 Android Companion' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`btn ${activeTab === tab.id ? 'btn-primary' : 'btn-outline'}`}
              style={{ fontSize: '13px', padding: '8px 16px' }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Active Tab View */}
        {activeTab === 'dashboard' && (
          <div>
            <AgentGrid agents={agents} />
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
      </main>

      {/* Footer */}
      <footer style={{
        textAlign: 'center',
        padding: '20px',
        borderTop: '1px solid rgba(255, 255, 255, 0.05)',
        fontSize: '12px',
        color: 'var(--text-dim)',
      }}>
        Guard AI &bull; Intelligent Multi-Agent Cybersecurity Platform &bull; Windows & Android Ready
      </footer>
    </div>
  );
}
