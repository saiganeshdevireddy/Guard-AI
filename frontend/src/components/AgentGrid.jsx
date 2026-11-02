import React, { useState } from 'react';
import { CpuIcon, ShieldIcon, AlertIcon, VolumeIcon, ActivityIcon, GlobeIcon, LockIcon } from './Icons';

const coreRoles = [
  { id: 'controller_ai', name: 'Controller AI', label: 'Orchestration', color: 'var(--cyan-primary)', Icon: CpuIcon },
  { id: 'finder_ai', name: 'Finder AI', label: 'Threat discovery', color: 'var(--amber-warning)', Icon: ActivityIcon },
  { id: 'defence_ai', name: 'Defence AI', label: 'Protection', color: 'var(--emerald-success)', Icon: LockIcon },
  { id: 'offence_ai', name: 'Offence AI', label: 'Response analysis', color: 'var(--crimson-danger)', Icon: AlertIcon },
  { id: 'informer_ai', name: 'Informer AI', label: 'Briefings', color: 'var(--purple-accent)', Icon: VolumeIcon },
];

export function AgentGrid({ agents = [], stateReceived = false, updatedAt = null }) {
  const [selectedAgent, setSelectedAgent] = useState(null);
  const byId = new Map(agents.map((agent) => [agent.id, agent]));
  const coreIds = new Set(coreRoles.map(({ id }) => id));
  const specialized = agents.filter((agent) => !coreIds.has(agent.id));
  const heartbeatLabel = (value) => {
    if (!value) return 'No heartbeat';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown heartbeat' : `Seen ${date.toLocaleTimeString()}`;
  };

  return (
    <section className="agent-command" aria-labelledby="agent-command-title">
      <div className="section-heading">
        <div>
          <p className="eyebrow">GUARD AI · OPERATIONS</p>
          <h2 id="agent-command-title">Agent command network</h2>
          <p className="section-description">Agent availability and activity are read from the connected backend.</p>
        </div>
        <span className={`badge ${agents.length ? 'badge-cyan' : 'badge-medium'}`}>{agents.length} reported</span>
      </div>

      <div className="agent-network" aria-label="Connected agent network">
        <svg className="agent-network-lines" viewBox="0 0 1000 430" preserveAspectRatio="none" aria-hidden="true">
          <path d="M500 215 L180 95 M500 215 L820 95 M500 215 L180 335 M500 215 L820 335" />
        </svg>
        <div className="agent-core">
          <div className="agent-core-orbit agent-core-orbit-one" />
          <div className="agent-core-orbit agent-core-orbit-two" />
          <span className="agent-core-icon"><ShieldIcon size={32} /></span>
          <strong>GUARD AI CORE</strong>
          <span>Autonomous Controller · {stateReceived === null ? 'checking' : stateReceived ? `${agents.length} states` : 'unavailable'}</span>
        </div>
        {coreRoles.map(({ id, name, label, color, Icon }) => {
          const agent = byId.get(id);
          const selected = selectedAgent?.id === id;
          return (
            <button
              type="button"
              key={id}
              className={`agent-network-node agent-node-${id.replace('_ai', '')}${selected ? ' is-selected' : ''}`}
              onClick={() => setSelectedAgent(agent || { id, name, status: 'UNAVAILABLE' })}
              aria-pressed={selected}
              style={{ '--agent-color': color }}
            >
              <span className="agent-node-icon"><Icon size={19} /></span>
              <span className="agent-node-copy"><strong>{agent?.name || name}</strong><small>{label}</small></span>
              <span className={`agent-state ${agent ? (agent.status === 'ACTIVE' ? 'is-active' : 'is-idle') : 'is-unknown'}`}>
                <i />{!stateReceived ? (stateReceived === null ? 'LOADING' : 'UNAVAILABLE') : agent?.status || 'NOT REPORTED'}
              </span>
              {agent && stateReceived && <span className="agent-node-meta">{agent.task_count ?? 0} tasks · {heartbeatLabel(agent.last_heartbeat)}</span>}
              {stateReceived && updatedAt && <span className="agent-node-meta">API update {updatedAt.toLocaleTimeString()}</span>}
            </button>
          );
        })}
      </div>

      {selectedAgent && (
        <p className="agent-selection" role="status">
          {selectedAgent.name}: {selectedAgent.status === 'UNAVAILABLE' ? 'no status received from the backend.' : `backend status ${selectedAgent.status}.`}
        </p>
      )}

      <div className="specialized-agents">
        <span className="eyebrow">SPECIALIZED DETECTION</span>
          {stateReceived && specialized.length ? specialized.map((agent) => (
          <span className="specialized-agent" key={agent.id}><GlobeIcon size={14} />{agent.name}<small>{agent.status || 'UNKNOWN'}</small></span>
        )) : <span className="specialized-empty">{stateReceived === null ? 'Checking agent states…' : stateReceived ? 'No specialized agent status reported.' : 'Agent status unavailable.'}</span>}
      </div>
    </section>
  );
}
