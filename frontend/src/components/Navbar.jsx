import React from 'react';
import { ShieldIcon, VolumeIcon, VolumeMuteIcon, AlertIcon } from './Icons';

export function Navbar({ isMuted, onToggleMute, isSpeaking, emergencyStatus, localPrivacyMode, onTogglePrivacy }) {
  const isEmergency = emergencyStatus?.is_active;

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '16px 28px',
      borderBottom: '1px solid rgba(0, 242, 254, 0.2)',
      background: 'rgba(10, 13, 20, 0.85)',
      backdropFilter: 'blur(16px)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
    }}>
      {/* Brand Title */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div style={{
          width: '42px',
          height: '42px',
          borderRadius: '10px',
          background: isEmergency ? 'linear-gradient(135deg, #ef4444, #991b1b)' : 'linear-gradient(135deg, #00f2fe, #4facfe)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: isEmergency ? '0 0 20px rgba(239, 68, 68, 0.6)' : '0 0 20px rgba(0, 242, 254, 0.5)',
        }}>
          <ShieldIcon size={24} color="#050b14" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '0.05em', color: '#ffffff' }}>GUARD AI</span>
            <span className="badge badge-cyan" style={{ fontSize: '10px' }}>v1.0 MIL-SPEC</span>
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Multi-Agent Cyber Defence & Privacy Platform</p>
        </div>
      </div>

      {/* Center Emergency Badge (if active) */}
      {isEmergency && (
        <div className="badge badge-critical" style={{ padding: '6px 14px', fontSize: '12px', cursor: 'pointer' }}>
          <AlertIcon size={16} /> EMERGENCY LOCKDOWN: {emergencyStatus.lockdown_level}
        </div>
      )}

      {/* Right Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Privacy Mode Toggle */}
        <button
          onClick={onTogglePrivacy}
          className="btn btn-outline"
          title="Toggle between 100% Local Offline Intelligence and Cloud AI Assistance"
          style={{ padding: '6px 12px', fontSize: '12px' }}
        >
          <span style={{
            display: 'inline-block',
            width: '8px',
            height: '8px',
            borderRadius: '50%',
            backgroundColor: localPrivacyMode ? '#10b981' : '#8b5cf6',
            boxShadow: localPrivacyMode ? '0 0 8px #10b981' : '0 0 8px #8b5cf6',
          }} />
          {localPrivacyMode ? 'Privacy: 100% Local' : 'Mode: Hybrid Cloud'}
        </button>

        {/* Informer Voice Control */}
        <button
          onClick={onToggleMute}
          className={`btn ${isMuted ? 'btn-outline' : 'btn-primary'}`}
          style={{ padding: '6px 14px', fontSize: '12px' }}
          title={isMuted ? 'Unmute Informer AI Voice Briefings' : 'Mute Informer AI Voice'}
        >
          {isMuted ? <VolumeMuteIcon size={16} /> : <VolumeIcon size={16} />}
          <span>Informer AI</span>
          {isSpeaking && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '2px', marginLeft: '6px' }}>
              <div className="voice-wave-bar" style={{ animationDelay: '0s' }} />
              <div className="voice-wave-bar" style={{ animationDelay: '0.2s' }} />
              <div className="voice-wave-bar" style={{ animationDelay: '0.4s' }} />
            </div>
          )}
        </button>
      </div>
    </header>
  );
}
