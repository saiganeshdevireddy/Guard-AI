import React, { useState } from 'react';
import { CpuIcon, ShieldIcon, AlertIcon, VolumeIcon, WifiIcon, ActivityIcon, GlobeIcon, LockIcon } from './Icons';

export function AgentGrid({ agents = [] }) {
  const [selectedAgent, setSelectedAgent] = useState(null);

  // Map agents by ID or prefix
  const primaryIds = ['controller_ai', 'finder_ai', 'defence_ai', 'offence_ai', 'informer_ai'];
  const primaryAgents = agents.filter(a => primaryIds.includes(a.id));
  const specializedAgents = agents.filter(a => !primaryIds.includes(a.id));

  const getAgentTheme = (id) => {
    switch (id) {
      case 'controller_ai': return { color: '#00f2fe', icon: <CpuIcon size={24} color="#00f2fe" />, label: 'Central Coordinator' };
      case 'finder_ai': return { color: '#f59e0b', icon: <ActivityIcon size={24} color="#f59e0b" />, label: 'Threat Discovery' };
      case 'defence_ai': return { color: '#10b981', icon: <LockIcon size={24} color="#10b981" />, label: 'Cryptographic Maze' };
      case 'offence_ai': return { color: '#ef4444', icon: <AlertIcon size={24} color="#ef4444" />, label: 'Emergency Containment' };
      case 'informer_ai': return { color: '#8b5cf6', icon: <VolumeIcon size={24} color="#8b5cf6" />, label: 'Voice Informant' };
      default: return { color: '#38bdf8', icon: <GlobeIcon size={24} color="#38bdf8" />, label: 'Specialized Agent' };
    }
  };

  return (
    <div style={{ marginBottom: '28px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: '700', color: '#ffffff', letterSpacing: '0.02em' }}>
            Multi-Agent Command Matrix
          </h2>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Coordinated autonomous agents exchanging intelligence over real-time event bus
          </p>
        </div>
        <span className="badge badge-cyan">{agents.length || 10} Agents Active & Synced</span>
      </div>

      {/* Primary 5 Agents Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '14px',
        marginBottom: '16px',
      }}>
        {primaryAgents.map((agent) => {
          const theme = getAgentTheme(agent.id);
          const isSelected = selectedAgent?.id === agent.id;

          return (
            <div
              key={agent.id}
              onClick={() => setSelectedAgent(agent)}
              className="glass-panel"
              style={{
                padding: '16px',
                cursor: 'pointer',
                borderColor: isSelected ? theme.color : undefined,
                background: isSelected ? 'rgba(26, 35, 56, 0.95)' : undefined,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <div style={{
                  width: '38px',
                  height: '38px',
                  borderRadius: '8px',
                  background: 'rgba(10, 15, 26, 0.8)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  border: `1px solid ${theme.color}40`,
                }}>
                  {theme.icon}
                </div>
                <span className="badge badge-low" style={{ fontSize: '10px' }}>
                  {agent.status}
                </span>
              </div>

              <h3 style={{ fontSize: '15px', fontWeight: '700', color: '#fff', marginBottom: '3px' }}>
                {agent.name}
              </h3>
              <p style={{ fontSize: '11px', color: theme.color, fontWeight: '600', marginBottom: '10px' }}>
                {theme.label}
              </p>
              
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                fontSize: '11px',
                color: 'var(--text-dim)',
                paddingTop: '8px',
                borderTop: '1px solid rgba(255, 255, 255, 0.06)',
                fontFamily: 'var(--font-mono)',
              }}>
                <span>Tasks: {agent.task_count || 0}</span>
                <span style={{ color: '#10b981' }}>Heartbeat: OK</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Specialized Detection Sub-Agents Strip */}
      <div className="glass-panel" style={{ padding: '12px 18px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Specialized Neural Detection Agents:
          </span>
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
          {specializedAgents.map((sub) => (
            <div
              key={sub.id}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '5px 12px',
                background: 'rgba(10, 15, 26, 0.6)',
                borderRadius: '6px',
                border: '1px solid rgba(0, 242, 254, 0.1)',
                fontSize: '12px',
              }}
            >
              <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00f2fe' }} />
              <span style={{ color: '#fff', fontWeight: '500' }}>{sub.name}</span>
              <span style={{ fontSize: '10px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                ({sub.task_count} ops)
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
