import React from 'react';

const steps = [
  { id: 'scanner', index: '01', title: 'Detect', detail: 'Review URLs, files, messages, and supplied Wi-Fi details.', action: 'Open scanner' },
  { id: 'emergency', index: '02', title: 'Protect', detail: 'Use approval-gated, in-app defensive response controls.', action: 'Open response' },
  { id: 'vault', index: '03', title: 'Encrypt', detail: 'Protect selected secrets with the local cryptographic vault.', action: 'Open vault' },
  { id: 'dashboard', index: '04', title: 'Inform', detail: 'Read the latest risk briefing and use browser voice alerts.', action: 'View briefing' },
  { id: 'audit', index: '05', title: 'Verify', detail: 'Check the local tamper-evident audit chain and optional anchor status.', action: 'Open audit' },
];

function StatePill({ tone = 'neutral', children }) {
  return <span className={`core-state core-state-${tone}`}>{children}</span>;
}

export function CoreWorkflow({
  backendAvailable,
  vaultStatus,
  auditStatus,
  blockchainStatus,
  onNavigate,
}) {
  const chainAvailable = blockchainStatus?.available === true;
  const chainMessage = blockchainStatus?.available === false
    ? 'Local fallback active'
    : blockchainStatus?.available === true
      ? `Local Hardhat · chain ${blockchainStatus.chain_id}`
      : 'Status unavailable';

  return (
    <section className="core-workflow" aria-labelledby="core-workflow-title">
      <div className="core-workflow-heading">
        <div>
          <p className="eyebrow">THE GUARD AI CORE</p>
          <h2 id="core-workflow-title">Detect · Defend · Secure</h2>
          <p className="section-description">A working prototype workflow, coordinated by Controller AI. Each status comes from the backend or is explicitly marked unavailable.</p>
        </div>
        <StatePill tone={backendAvailable ? 'good' : 'neutral'}>
          {backendAvailable === null ? 'Checking API' : backendAvailable ? 'API connected' : 'API unavailable'}
        </StatePill>
      </div>

      <div className="core-workflow-steps">
        {steps.map((step) => (
          <button className="core-workflow-step" type="button" key={step.id} onClick={() => onNavigate(step.id)}>
            <span className="core-step-index">{step.index}</span>
            <strong>{step.title}</strong>
            <span className="core-step-detail">{step.detail}</span>
            <span className="core-step-action">{step.action} <span aria-hidden="true">→</span></span>
          </button>
        ))}
      </div>

      <div className="core-foundations" aria-label="Security foundation status">
        <div className="core-foundation">
          <span className="core-foundation-icon" aria-hidden="true">◈</span>
          <span><strong>Cryptographic Maze</strong><small>{vaultStatus?.algorithm || 'Vault status unavailable'}</small></span>
          <StatePill tone={vaultStatus ? 'good' : 'neutral'}>{vaultStatus ? (vaultStatus.is_locked ? 'Locked' : 'Unlocked') : 'Unknown'}</StatePill>
          <button className="core-foundation-action" type="button" onClick={() => onNavigate('vault')}>Open vault</button>
        </div>
        <div className="core-foundation">
          <span className="core-foundation-icon" aria-hidden="true">⌁</span>
          <span><strong>Tamper-evident audit</strong><small>{auditStatus ? `${auditStatus.block_count} local records` : 'Verification unavailable'}</small></span>
          <StatePill tone={auditStatus?.valid ? 'good' : 'neutral'}>{auditStatus ? (auditStatus.valid ? 'Verified locally' : 'Integrity issue') : 'Unknown'}</StatePill>
          <button className="core-foundation-action" type="button" onClick={() => onNavigate('audit')}>View ledger</button>
        </div>
        <div className="core-foundation">
          <span className="core-foundation-icon" aria-hidden="true">⬡</span>
          <span><strong>Blockchain anchor</strong><small>{chainAvailable ? 'Optional local development network' : 'No on-chain verification active'}</small></span>
          <StatePill tone={chainAvailable ? 'good' : 'neutral'}>{chainMessage}</StatePill>
          <button className="core-foundation-action" type="button" onClick={() => onNavigate('audit')}>Blockchain status</button>
        </div>
        <div className="core-foundation core-foundation-limited">
          <span className="core-foundation-icon" aria-hidden="true">◇</span>
          <span><strong>Isolated browser</strong><small>Suspicious content is reviewed locally and is not opened.</small></span>
          <StatePill>Not implemented</StatePill>
          <button className="core-foundation-action" type="button" onClick={() => onNavigate('sandbox')}>Safe URL review</button>
        </div>
        <div className="core-foundation">
          <span className="core-foundation-icon" aria-hidden="true">▤</span>
          <span><strong>Sandbox Lab</strong><small>Static URL and file inspection; files are not executed.</small></span>
          <StatePill tone={backendAvailable ? 'good' : 'neutral'}>{backendAvailable ? 'Static inspection' : 'Unavailable'}</StatePill>
          <button className="core-foundation-action" type="button" onClick={() => onNavigate('scanner')}>Inspect content</button>
        </div>
        <div className="core-foundation core-foundation-limited">
          <span className="core-foundation-icon" aria-hidden="true">◫</span>
          <span><strong>Private browser tabs</strong><small>No private browser engine, profiles, or per-tab storage is provided.</small></span>
          <StatePill>Not implemented</StatePill>
          <button className="core-foundation-action" type="button" disabled title="A separate isolated browser is not available in this prototype.">Unavailable</button>
        </div>
      </div>
      <p className="core-workflow-note">A low heuristic score is not proof of safety. Wi-Fi posture analysis uses details supplied by the user; native device-wide protection, live browser isolation, and always-on monitoring are not included.</p>
    </section>
  );
}
