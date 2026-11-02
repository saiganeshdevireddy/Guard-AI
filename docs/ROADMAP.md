# Guard AI implementation status

For the consolidated six-role target architecture and security extension proposal, see [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md). Its six-agent model and supporting infrastructure are proposed; current source has five primary agents, with Wi-Fi Analysis registered as a Finder specialist. The consolidation is documentation only.

Canonical records: [master architecture and ownership matrix](GUARD_AI_MASTER_ARCHITECTURE.md), [browser-isolation architecture](ISOLATED_BROWSER_ARCHITECTURE.md), and [security findings register](SECURITY_AUDIT_FINDINGS.md). Earlier browser research and readiness audits remain preserved as evidence and summaries.

Milestone 5 scope, evidence, and closure criteria are governed by [MILESTONE_5_ACCEPTANCE_FRAMEWORK.md](MILESTONE_5_ACCEPTANCE_FRAMEWORK.md). **Software Acceptance: PARTIALLY VERIFIED. Infrastructure and Operational Acceptance: BLOCKED. Overall Milestone 5: not accepted.** These are separate gates; neither has been accepted.

This table describes what this repository currently contains. It does not claim complete endpoint or operating-system protection.

| Area | Current state | Limits |
| --- | --- | --- |
| React dashboard | Implemented with Dark, Light, and System themes, saved preference, responsive styles, and backend status polling. | Some pages depend on a running local API; browser speech depends on browser support. |
| Controller and agents | Implemented in one FastAPI process with an in-memory event bus and persisted threat events. Includes URL, file, Wi-Fi-input, text, and caller-supplied process-metadata analyzers. | No background heartbeat service or direct OS/browser/network monitoring. The app monitor starts IDLE. |
| SQLite persistence | Threat events, vault items, agent state, emergency state, and audit records use SQLAlchemy models. | SQLite is the default; no migration framework or multi-user model is included. |
| URL and message analysis | Local deterministic heuristics with an uncertainty disclaimer. | Not a reputation service or a proof that an item is safe. No cloud threat intelligence. |
| File analysis | Uploaded files get bounded static byte inspection and heuristic checks. | No disk-wide scanning, malware execution sandbox, or automatic quarantine from the scan endpoint. |
| Cryptographic vault | AES-GCM encryption and passphrase-derived keys are implemented. | Passphrases are caller-supplied; this is not an OS-backed keystore. Application memory and local database access are not protected from a compromised host. |
| Audit ledger | SHA-256 hash chain with verification endpoint. | Local database chain is tamper-evident, not immutable. Deleting a final suffix cannot be detected without an external anchor. |
| Emergency response | Explicit confirmation gates local incident mode; containment demonstration endpoints are labelled simulations. | No process termination or network isolation is implemented. |
| Isolated browser | Not implemented. URL Review does not fetch or render remote content. A proposed Firecracker microVM design is documented; implementation is approval-gated. | Requires a dedicated Linux/KVM worker, enforced egress gateway, remote display service, session management, and security verification. See [ISOLATED_BROWSER_ARCHITECTURE.md](ISOLATED_BROWSER_ARCHITECTURE.md). |
| Android companion | A labelled in-memory demonstration workflow is available. | No native application, pairing/authentication protocol, live telemetry, or device lock command. |
| Cloud AI | Not configured; summaries remain local. | No provider integration or outbound AI request is implemented. |

## Genuine isolated browser project milestones

Research, feasibility assessment and the implementation plan are complete as **documentation only**. The architecture and hosting recommendation remain **proposed**. No hosting decision is approved, no worker has been identified or provisioned, and all runtime milestones remain incomplete. See [ISOLATED_BROWSER_ARCHITECTURE.md](ISOLATED_BROWSER_ARCHITECTURE.md), [INFRASTRUCTURE_FEASIBILITY.md](INFRASTRUCTURE_FEASIBILITY.md), and [BROWSER_RUNTIME_MVP_IMPLEMENTATION_PLAN.md](BROWSER_RUNTIME_MVP_IMPLEMENTATION_PLAN.md).

### Preparation and decision gates

| Milestone | Status | Required outcome |
| --- | --- | --- |
| Research and architecture | **Complete (documentation only)** | Existing implementation assessment, architecture comparison, threat model, data flows, network/session policy, and security strategy recorded. Nothing was built or security-tested. |
| Infrastructure feasibility | **Complete (assessment only)** | Windows development laptop assessed as unsuitable for local Firecracker hosting; no Linux/KVM worker identified. Cost figures are assumptions/examples, not quotes. |
| MVP implementation plan | **Complete (proposed, documentation only)** | Hosting framework, interfaces, lifecycle, controls, agent boundaries, phase dependencies, and acceptance criteria documented. |
| Pre-implementation security audit | **Complete (documentation/source review only)** | Detailed finding register and source evidence in [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md); dependency and readiness decision in [PRE_IMPLEMENTATION_SECURITY_AUDIT.md](PRE_IMPLEMENTATION_SECURITY_AUDIT.md). No runtime or security tests were executed; Phase A is not ready. |
| Hosting and user decisions | **Pending user approval** | Confirm existing Linux server/owner or cloud acceptance, monthly budget, region, privacy/retention, concurrency, and local-versus-remote MVP. No provisioning or spending authorized. |
| Worker infrastructure | **Not started; depends on hosting approval** | Establish supported Linux/KVM worker, private connectivity, gateway/display hosting, health/monitoring, image process, ownership and cost alerts. The assessed Windows Home laptop cannot host this runtime; hardware virtualization exposure was unverified. |

### Browser runtime implementation phases

Runtime phases A and D–G are **not started** and depend on approved hosting, budget, region/privacy requirements, and assigned operational ownership. Phase B and the metadata-only part of Phase C have application-side foundations, but their production/runtime scopes remain incomplete. Detailed Milestone 5 gates are in [MILESTONE_5_ACCEPTANCE_FRAMEWORK.md](MILESTONE_5_ACCEPTANCE_FRAMEWORK.md); runtime deliverables remain in [BROWSER_RUNTIME_MVP_IMPLEMENTATION_PLAN.md](BROWSER_RUNTIME_MVP_IMPLEMENTATION_PLAN.md).

| Phase | Status | Scope |
| --- | --- | --- |
| A. Worker infrastructure and health checks | **Not started** | Harden Linux/KVM host, pinned Firecracker/jailer and signed guest image, health checks, resource limits, operations and patch ownership. |
| B. Secure worker communication | **In progress — application-side foundation implemented and tested; production deployment unverified** | Certificate identity, signed health evidence, session-bound tickets, issue/redemption reauthorization, replay controls and fail-closed checks exist in source. Private worker networking, production mTLS, broker operations, key operations and PostgreSQL concurrency validation remain incomplete. See [Milestone 5 acceptance](MILESTONE_5_ACCEPTANCE_FRAMEWORK.md). |
| C. Session manager | **In progress — metadata authorization foundation implemented and tested; runtime lifecycle unavailable** | Authenticated metadata-only authorization, ownership, persisted state and deterministic policy checks exist. Quotas, worker provisioning, active runtime/stop, watchdog/reconciliation and verified cleanup remain unavailable. |
| D. Disposable browser runtime | **Not started** | One ephemeral Firecracker VM/profile per session, signed fixed image, resource caps, no shared state or host access. |
| E. Remote display and input | **Not started** | HTTPS/WSS remote display, short-lived session-bound tickets, restricted keyboard/pointer input, no clipboard or file/device transfer. |
| F. Security validation | **Not started; baseline after E, final gate after G** | Establish and run isolation, egress, SSRF/DNS, session separation, authorization, cleanup, failure and privacy tests after E; rerun full regression after agent integration in G. Any critical containment/cleanup failure blocks release. |
| G. Guard AI agent integration | **Not started; after Phase F baseline** | Integrate Autonomous Controller AI, Finder AI, Defence AI, Offence AI, Informer AI and Wi-Fi Analysis AI; Wi-Fi stays nested under Finder in current source pending separately authorized promotion. Defence owns browser/security policy; execution services are separately bounded. Maintain FastAPI authorization and explicit user intent; no heuristic auto-launch or safety declaration; no external attack or automatic authority reporting; no unauthorized Wi-Fi scans. Run final Phase F gate after G. |

## Verification status

The latest recorded full backend run passed 134 tests on the baseline in [Milestone 5 acceptance](MILESTONE_5_ACCEPTANCE_FRAMEWORK.md). This point-in-time result is not a production-security claim. Frontend tests were not run in that backend verification; see [GETTING_STARTED.md](GETTING_STARTED.md) and run `npm test` from `frontend` for the frontend suite.
