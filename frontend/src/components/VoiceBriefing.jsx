import React from 'react';
import { VolumeIcon, VolumeMuteIcon, AlertIcon, CheckIcon } from './Icons';

export function VoiceBriefing({ briefing, onSpeak, isSpeaking, isMuted }) {
  if (!briefing) return null;

  const isUrgent = briefing.urgency === 'CRITICAL' || briefing.urgency === 'HIGH';

  return (
    <div
      className="glass-panel"
      style={{
        padding: '20px',
        marginBottom: '28px',
        borderLeft: `4px solid ${isUrgent ? 'var(--crimson-danger)' : 'var(--purple-accent)'}`,
        background: isUrgent ? 'var(--surface-emphasis)' : 'var(--surface-emphasis)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '16px', marginBottom: '14px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span className={`badge ${isUrgent ? 'badge-critical' : 'badge-low'}`}>
              Informer AI Voice Briefing
            </span>
            <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Plain-Language Security Translation
            </span>
          </div>
          <h3 style={{ fontSize: '17px', fontWeight: '700', color: 'var(--text-main)' }}>
            {briefing.title || 'Security Posture Briefing'}
          </h3>
        </div>

        {/* Speak / Stop Button */}
        <button
          onClick={() => onSpeak(briefing.spoken_text)}
          className="btn btn-primary"
          style={{
            padding: '8px 16px',
            fontSize: '13px',
            background: isUrgent ? 'linear-gradient(135deg, var(--crimson-danger), var(--crimson-danger))' : undefined,
          }}
        >
          <VolumeIcon size={16} />
          {isSpeaking ? 'Speaking...' : 'Play Voice Briefing'}
        </button>
      </div>

      {/* Spoken Text Display */}
      <div style={{
        background: 'var(--surface-subtle)',
        padding: '12px 16px',
        borderRadius: '8px',
        marginBottom: '16px',
        fontStyle: 'italic',
        fontSize: '13px',
        color: 'var(--text-main)',
        border: '1px solid var(--line-subtle)',
      }}>
        "{briefing.spoken_text}"
      </div>

      {/* 3-Part Beginner-Friendly Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '12px' }}>
        {/* Part 1: What was detected */}
        <div style={{
          background: 'var(--surface-subtle)',
          padding: '12px',
          borderRadius: '8px',
          border: '1px solid var(--line-subtle)',
        }}>
          <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--cyan-primary)', marginBottom: '4px' }}>
            1. WHAT WAS DETECTED
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: '1.4' }}>
            {briefing.plain_explanation || 'All incoming signals conform to expected safe operating baselines.'}
          </p>
        </div>

        {/* Part 2: Why it matters */}
        <div style={{
          background: 'var(--surface-subtle)',
          padding: '12px',
          borderRadius: '8px',
          border: '1px solid var(--line-subtle)',
        }}>
          <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--amber-warning)', marginBottom: '4px' }}>
            2. WHY IT MATTERS
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: '1.4' }}>
            {briefing.impact_summary || 'Prevents credential leaks, malware execution, or network eavesdropping.'}
          </p>
        </div>

        {/* Part 3: Recommended action */}
        <div style={{
          background: 'var(--surface-subtle)',
          padding: '12px',
          borderRadius: '8px',
          border: '1px solid var(--line-subtle)',
        }}>
          <div style={{ fontSize: '11px', fontWeight: '700', color: 'var(--emerald-success)', marginBottom: '4px' }}>
            3. RECOMMENDED ACTION
          </div>
          <p style={{ fontSize: '12px', color: 'var(--text-main)', lineHeight: '1.4' }}>
            {briefing.recommended_action || 'No manual action is required at this time.'}
          </p>
        </div>
      </div>
    </div>
  );
}
