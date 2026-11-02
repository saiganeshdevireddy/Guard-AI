import React from 'react';
import { ShieldIcon, VolumeIcon, VolumeMuteIcon, AlertIcon } from './Icons';

function ThemeIcon({ mode }) {
  if (mode === 'dark') return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M20.5 15.5A8.5 8.5 0 0 1 8.5 3.5 8.5 8.5 0 1 0 20.5 15.5Z" /></svg>;
  if (mode === 'light') return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42" /></svg>;
  return <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2" /><path d="M8 21h8m-4-4v4" /></svg>;
}

export function Navbar({ isMuted, onToggleMute, isSpeaking, emergencyStatus, privacyMode, themePreference, onThemeChange, username, onLogout }) {
  const isEmergency = emergencyStatus?.is_active;

  return (
    <header className="app-navbar">
      {/* Brand Title */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div className={`brand-mark ${isEmergency ? 'brand-mark-emergency' : ''}`}>
          <ShieldIcon size={24} color="var(--icon-on-brand)" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '0.05em', color: 'var(--text-main)' }}>GUARD AI</span>
            <span className="badge badge-cyan" style={{ fontSize: '10px' }}>v1.0 LOCAL</span>
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
      <div className="nav-controls">
        <div className="theme-switcher" role="group" aria-label="Color theme">
          {[
            ['dark', 'Dark'],
            ['light', 'Light'],
            ['system', 'System'],
          ].map(([mode, label]) => (
            <button
              key={mode}
              type="button"
              className={`theme-option ${themePreference === mode ? 'is-selected' : ''}`}
              aria-label={`${label} theme`}
              aria-pressed={themePreference === mode}
              title={`${label} theme`}
              onClick={() => onThemeChange(mode)}
            >
              <ThemeIcon mode={mode} />
              <span>{label}</span>
            </button>
          ))}
        </div>
        <span className="badge badge-cyan privacy-badge" title="Privacy mode reported by backend">
          Privacy: {privacyMode || 'Unknown'}
        </span>
        <div className="nav-session" aria-label={`Signed in as ${username}`}>
          <span className="nav-session-user">{username}</span>
          <button className="btn btn-outline nav-logout" type="button" onClick={onLogout}>Sign out</button>
        </div>

        {/* Informer Voice Control */}
        <button
          onClick={onToggleMute}
          className={`btn ${isMuted ? 'btn-outline' : 'btn-primary'} voice-control`}
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
