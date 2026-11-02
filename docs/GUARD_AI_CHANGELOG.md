# Guard AI Architecture Consolidation Changelog

## 2026-11-02 — Architecture decision resolution

- Recorded Defence AI as policy/product owner for isolated browsing, URL protection, sandbox/private-session policy, readiness and defensive session enforcement; preserved Defence vault/Cryptographic Maze responsibilities and separated execution service privileges.
- Defined one disposable VM per browsing session, shared tabs/profile within a session, separate profiles/environments across sessions, verified cleanup requirement, and ordinary incognito mode as insufficient isolation.
- Added Wi-Fi Analysis AI explicitly to target diagrams and communication/integration contracts while retaining its current Finder-specialized source status.
- Added the component ownership/interface matrix and implementation readiness checklist to the canonical master architecture.
- Designated `GUARD_AI_MASTER_ARCHITECTURE.md`, `ISOLATED_BROWSER_ARCHITECTURE.md`, and `SECURITY_AUDIT_FINDINGS.md` as canonical. Added cross-references to preserve older research and audit summaries without deleting them.
- Updated roadmap, readiness audit, findings register/fallback crosswalk, agent contracts, communication protocol, security extensions, browser MVP integration plan, and application architecture references. Added canonical-reference notices to infrastructure feasibility and historical research/audit summaries.
- All runtime controls remain proposed/unimplemented; no source, test, dependency, configuration, blockchain, infrastructure, or Git history changes were made. No tests were executed.

### Files updated in this decision pass

- `docs/GUARD_AI_MASTER_ARCHITECTURE.md` — decision record, six-role architecture, component matrix and readiness checklist.
- `docs/ISOLATED_BROWSER_ARCHITECTURE.md` — Defence ownership, one-VM-per-session semantics, execution component interfaces and six-agent diagrams.
- `docs/GUARD_AI_AGENT_SPECIFICATIONS.md` — consistent six-role names/responsibilities and current-vs-target status.
- `docs/GUARD_AI_COMMUNICATION_PROTOCOL.md` — six-role message authorities and Defence execution-service contract.
- `docs/GUARD_AI_SECURITY_EXTENSIONS.md` — Defence-owned policy and canonical risk cross-reference.
- `docs/GUARD_AI_IMPLEMENTATION_ROADMAP.md` — aligned dependencies, role integration and remaining decisions.
- `docs/BROWSER_RUNTIME_MVP_IMPLEMENTATION_PLAN.md` — Defence/Wi-Fi roles and Phase G validation scope.
- `docs/SECURITY_AUDIT_FINDINGS.md` — canonical register, resolved architecture decisions and SA-01–SA-12 fallback/validation crosswalk.
- `docs/PRE_IMPLEMENTATION_SECURITY_AUDIT.md` — canonical references and explicit readiness checklist.
- `docs/BROWSER_ISOLATION_ARCHITECTURE.md` — historical-research designation and canonical links.
- `docs/INFRASTRUCTURE_FEASIBILITY.md` — canonical decision and findings references; feasibility assumptions retained.
- `docs/GUARD_AI_LOPWHole_AUDIT.md` — canonical findings and ownership references.
- `docs/ROADMAP.md` — canonical-document references and six-agent Phase G scope.
- `docs/ARCHITECTURE.md` — canonical architecture and findings references.
- `docs/GUARD_AI_CHANGELOG.md` — this dated change record.

## 2026-11-01 — Master architecture documentation

- Added the consolidated target architecture, six agent role specifications, security extension register, loophole audit, proposed communication protocol, roadmap, validation strategy and this changelog.
- Preserved the six primary roles as target architecture; documented current source evidence of five primary agents and Wi-Fi Analysis as a nested Finder specialist.
- Preserved existing Defence vault/Cryptographic Maze functions. At the time of this entry browser policy ownership was unresolved; the 2026-11-02 decision above resolves that documentation question in Defence's favor without claiming runtime implementation.
- Preserved Transmitter, Transformer/blockchain, Rollback and emergency safe-mode concepts as design subjects without representing unverified modules or controls as implemented.
- No application source, tests, dependencies, blockchain artifacts or cache were changed. No application or security tests were run; no deployment, commit or push occurred.
