# Guard AI — Milestone 5 Acceptance Framework

**Authority:** This document is the authoritative scope, status, evidence, and closure record for **Milestone 5 — Secure Worker Communication**. It does not replace the master architecture, isolated-browser architecture, infrastructure feasibility assessment, or security findings register; those remain authoritative for their broader topics.

**Repository baseline reviewed:** `codex-working-core`, commit `4a577161580cfeeecaab5383045f1b35439d532c`.

## 1. Purpose and scope

Milestone 5 establishes software and operational capability to authenticate a worker and authorize a browser session through a secure worker channel. It has two independent acceptance gates: **Software Acceptance** and **Infrastructure and Operational Acceptance**. Overall Milestone 5 is not accepted until both gates are accepted.

Software scope covers worker identity, certificates, signed health, Defence authorization, ticket issue/redemption, persistence, audit, and automated tests. Infrastructure scope covers a real Linux/KVM worker and the operational trust, network, runtime, display, cleanup, recovery, privacy, and ownership controls needed to use those software capabilities.

The agreed target browser model remains one disposable isolated VM per browsing session. Tabs within one session share that session's browser profile; separate sessions use separate environments and profiles. Ordinary incognito/private mode is not an isolation boundary. This is a proposed runtime requirement, not an implemented capability.

### Exclusions

The repository does not establish a deployed Linux/KVM worker, Firecracker runtime, browser process, remote display service, egress gateway, production mTLS deployment, production CA/CRL operation, independent watchdog, or cleanup verifier. Ticket redemption authorizes a worker/session only; it does not start a VM or browser. URL review remains local heuristic analysis. No browser-isolation, production-readiness, or cleanup-success claim follows from this milestone document.

## 2. Architecture ownership

Preserve all six target agents and their established duties:

| Agent | Milestone 5 boundary |
|---|---|
| Autonomous Controller AI | Coordinates authorized work; cannot substitute for independent deterministic policy or worker authorization. |
| Finder AI | Preliminary Safe/Suspicious/Malicious/Unknown analysis; never guarantees safety or launches a session from a score. |
| Defence AI | Owns browser-isolation and worker authorization policy; default-deny; retains vault and Cryptographic Maze duties. |
| Offence AI | Defensive emergency containment only; no retaliation or external attacks. |
| Informer AI | User-facing status and risk notices; no automatic reporting to authorities. |
| Wi-Fi Analysis AI | Target primary role with authorized scope; currently remains implemented under Finder, not independently promoted. |

Session Manager owns session metadata/lifecycle authorization. Worker identity/ticket services perform bounded communication checks. Future worker supervisor, egress gateway, display gateway, watchdog, and cleanup verifier remain separate execution components under Defence policy; none is established by a policy decision alone.

## 3. Status definitions

Use only the following status values in status fields:

- **NOT STARTED** — no implementation or validation work is evidenced.
- **IN PROGRESS** — work is underway but required implementation/evidence is incomplete.
- **IMPLEMENTED — NOT VERIFIED** — code/configuration exists, but adequate tests or evidence are missing.
- **PARTIALLY VERIFIED** — some required behavior is evidenced, but coverage or deployment evidence remains incomplete.
- **VERIFIED** — the stated technical criteria have implementation evidence and required tests passed in the named environment; this does not mean production acceptance.
- **BLOCKED** — an external dependency, approval, or infrastructure prevents progress.
- **ACCEPTED** — an authorized reviewer has accepted all criteria and residual risks for the gate.

Documentation is not implementation evidence. A passing local test is not production deployment evidence. “PARTIAL” in prose means incomplete and not accepted; the status value remains **PARTIALLY VERIFIED** where applicable.

## 4. Gate A — Software Acceptance

Evidence references below are repository paths and symbols, not claims about a deployed worker.

| ID / requirement | Status | Existing implementation and test evidence | Missing validation / next action | Acceptance condition |
|---|---|---|---|---|
| SW-01 Worker identity enrollment | VERIFIED | `backend/app/services/worker_communication.py`: `register_worker`; admin route in `backend/app/routers/workers_api.py`; worker tests exercise trusted enrollment, duplicate rejection, and audit failure. | Validate operational enrollment procedure at Gate B. | Trusted cert only; unique identity; audit failure cannot silently authorize; enrollment tests pass. |
| SW-02 Certificate renewal and revocation | VERIFIED | `renew_worker_certificate`, `revoke_worker`; tests cover renewal, old fingerprint rejection, worker revocation. | Production key custody/rotation and revocation propagation are Gate B. | Renewed identity is bound to new cert; revoked worker and its tickets are denied; tests pass. |
| SW-03 Chain, validity, and CRL validation | VERIFIED | `_verify_client_certificate`, `_verify_certificate_revocation`, `_check_registered_certificate`; tests cover invalid/expired/untrusted certs and CRL failures/revocation. | Production CA and CRL distribution/refresh is Gate B. | Expired/untrusted/revoked cert or unavailable/invalid CRL fails closed; tests pass. |
| SW-04 Ticket issuance and secure delivery | VERIFIED | `issue_session_ticket`; internal mTLS ticket route in `workers_api.py`; local TLS integration tests cover delivery retry and response behavior. | Production transport and access-log controls are Gate B. | Ticket is short-lived, session/worker/subject bound, retry-safe only for the same delivery ID, and secret-free from logs/errors. |
| SW-05 Ticket expiry and revocation | VERIFIED | Ticket claims include expiry; `revoke_ticket`; tests cover expired and revoked tickets. | Validate clock synchronization and operational revocation after deployment. | Expired or revoked ticket never redeems; tests pass. |
| SW-06 Ticket redemption and replay protection | VERIFIED | `redeem_session_ticket`; atomic conditional update; tests cover replay, identity mismatch, and concurrent redemption under SQLite. | PostgreSQL execution and concurrency remains SW-17. | A ticket is consumed once only; wrong binding, expiry, revocation, or replay denies. |
| SW-07 Ticket-time Defence reauthorization | VERIFIED | `_reauthorize_session_worker` invokes `controller_ai.defence.authorizes_browser_worker` during both issue and redemption; regression test disables Defence at each point. | Durable/synchronized policy updates remain SW-16. | Disabled/unavailable Defence denies both operations; Controller cannot bypass it. |
| SW-08 Current signed worker-health verification | VERIFIED | `verify_health_evidence`, persisted payload/signature in `WorkerHealthRecord`, and `DatabaseWorkerRegistry.get_registration` reverify the signature; tests cover missing/tampered evidence. | Real health reporter and independent worker monitor are Gate B. | Only registered worker's valid signed evidence can qualify; unknown/malformed evidence denies. |
| SW-09 Health freshness and sequence validation | VERIFIED | 30-second health age enforced by service and Defence; sequence/nonce checks in evidence intake; tests cover stale, replayed, conflicted and mismatched reports. | Deployment clock and freshness monitoring is Gate B. | Future, stale, replayed, or mismatched evidence denies issuance and redemption. |
| SW-10 Concurrent redemption protection | PARTIALLY VERIFIED | SQLite `BEGIN IMMEDIATE`, database conditional update, PostgreSQL `with_for_update`; two-thread test proves exactly one SQLite redemption succeeds. | PostgreSQL service/job and interleaving tests have not run. | Supported databases demonstrate exactly one winner and consistent revocation/health behavior. |
| SW-11 Database failure handling | PARTIALLY VERIFIED | Reauthorization query errors and issue/redemption storage errors fail closed; test injects a DB error during issuance. | Add injected database failure specifically during redemption; assert no redeemed record or success result. | Failures at issue and redeem produce denial, rollback, and no false state transition. |
| SW-12 Database migration safety | PARTIALLY VERIFIED | `backend/app/database.py::init_db` applies narrow additive updates; storage tests check data preservation, idempotence, interruption recovery and duplicate refusal. | No versioned migration framework, production backup/restore rehearsal, or PostgreSQL migration test. | Reviewed versioned schema evolution preserves legacy data and recovers safely from interruption on each supported DB. |
| SW-13 Audit-event coverage and integrity | PARTIALLY VERIFIED | Worker/ticket/health/key-ID events use `AuditChainService`; tests check ticket events and bearer-token absence. | Audit DB failure, cross-process chain concurrency, protected retention, and production log review remain. | Required events are durable, ordered, privacy-minimal; failures deny protected operations; no secrets in API/audit/logs. |
| SW-14 Fail-closed authorization | VERIFIED | Session, owner, worker, cert, Defence, health and ticket checks run on issue/redeem; missing/unhealthy/stale/revoked cases are tested. | Production trust chain and outage behavior are Gate B. | Every unknown or failed authorization prerequisite denies without transitioning ticket to redeemed. |
| SW-15 Supported database compatibility | PARTIALLY VERIFIED | SQLite is the exercised test database; PostgreSQL row locks are present in code. | Confirm supported DB/version and run integration/migration suite there. | Every declared supported database passes migration, transaction, concurrency, failure, and restart tests. |
| SW-16 Automated regression testing | VERIFIED | Latest recorded complete backend run at this commit: 134 passed; four relevant focused suites also passed. | Re-run after code changes; separate runtime/infrastructure validation is Gate B. | Defined suite passes in CI/reproducible environment with no masked skips or collection errors. |
| SW-17 PostgreSQL concurrency validation | NOT STARTED | No PostgreSQL test execution evidence. | Assign PostgreSQL service/version and run parallel ticket redemption, worker revocation, health-update races, and schema tests. | On actual supported PostgreSQL, exactly one redemption succeeds and checks/state updates serialize as specified. |

### Gate A decision

**Status: PARTIALLY VERIFIED.** The local implementation has substantial passing test evidence. Gate A is not accepted because redemption-side injected database failure coverage, PostgreSQL execution/concurrency, migration practice, audit limitations, and synchronized policy-update semantics remain outstanding.

## 5. Gate B — Infrastructure and Operational Acceptance

| ID / requirement | Status | Owner/dependency | Required evidence and acceptance condition |
|---|---|---|---|
| INF-01 Linux/KVM worker availability | BLOCKED | User/operator: identify host and ownership; host specification approval. | Demonstrate approved Linux host, hardware virtualization, usable `/dev/kvm`, restricted supervisor access, patching and rebuild procedure. |
| INF-02 Firecracker compatibility | BLOCKED | Infrastructure operator; INF-01. | Pinned Firecracker/jailer runs on selected host, signed fixed guest boots, limits and failure handling are verified. |
| INF-03 Worker ownership and operations | BLOCKED | User/operator approval. | Named responsible party, maintenance/on-call, escalation, access control and incident ownership. |
| INF-04 Production mTLS deployment | BLOCKED | Security/infrastructure operator; private endpoint and TLS topology approval. | Real private endpoint requires client certificates; peer identity reaches app only across a trusted, tested TLS boundary. |
| INF-05 Trusted TLS termination | BLOCKED | Infrastructure operator; INF-04. | Prove backend cannot be reached around terminator; spoofable certificate headers are stripped/rejected; only server-authenticated evidence is passed. |
| INF-06 CA/CRL distribution and refresh | BLOCKED | Security operator; CA ownership and worker enrollment procedure. | Demonstrate issuance, renewal, revocation propagation, CRL expiry monitoring, refresh and fail-closed outage behavior. |
| INF-07 Signing-key custody and rotation | BLOCKED | Security/key operator; approved secret manager/HSM or equivalent. | Demonstrate separated access, rotation overlap, retirement, revocation, recovery, audit and secret-free logs. |
| INF-08 Worker authorization and private connectivity | BLOCKED | Infrastructure/security operator; worker, broker, service identity and topology. | Real worker can perform only session-bound allowed actions over private authenticated channel; no public management route or user JWT forwarding. |
| INF-09 Network and egress controls | NOT STARTED | Network operator; approved routes, DNS/proxy, IPv4/IPv6 and egress policy. | Guest packet tests prove default-deny, private/metadata denial, redirect/DNS-rebinding defenses, no alternate transport bypass, and fail-closed gateway outage. |
| INF-10 Monitoring and health reporting | PARTIALLY VERIFIED | Application implements signed report intake; operator must provide independent liveness/readiness monitoring. | Demonstrate independent checks for KVM, image, supervisor, policy routes, gateway/display, resource headroom, clock and cleanup backlog; failures fence new sessions. |
| INF-11 Disposable VM provisioning | NOT STARTED | Worker/runtime engineering; INF-01/02/08/09 and policy approval. | One disposable VM per authorized session using pinned signed artifacts and quotas; no launch on any readiness uncertainty. |
| INF-12 Isolated browser runtime | NOT STARTED | Worker/runtime engineering; INF-11. | Separate browser profile/environment per session, multiple tabs only within that session, no shared guest state; adversarial isolation tests. |
| INF-13 Remote display gateway | NOT STARTED | Display/network operator; transport, origin, ports and client scope decisions. | Session-bound display access, bounded keyboard/pointer input, no clipboard/file/device transfer, cross-session denial, prompt revocation. |
| INF-14 Session cleanup verification | NOT STARTED | Cleanup operator/component; runtime, storage and trusted verifier. | Confirm VM/process termination, network detach, ticket/credential invalidation, profile/key handling and restart reconciliation; uncertainty quarantines. No physical sanitization claim without proof. |
| INF-15 Backup and recovery | NOT STARTED | Operations/security owner; storage and key-recovery design. | Restore test, worker rebuild, ticket invalidation, state reconciliation and safe-mode recovery without resurrecting sessions. |
| INF-16 Incident response | NOT STARTED | Named incident owner/user approvals. | Exercise worker compromise, key/CA compromise, egress failure and cleanup uncertainty; define authorization and escalation. |
| INF-17 Privacy, consent and retention | BLOCKED | User approval and privacy owner. | Approved data inventory, explicit launch consent, URL/metadata retention and deletion settings verified on deployment. |
| INF-18 Hosting region and budget approval | BLOCKED | User approval; provider quote/owned hardware evidence. | Record selected location, owner, approved monthly ceiling and alerts; no implied approval from estimates. |
| INF-19 Concurrency and resource limits | BLOCKED | User target plus operator capacity benchmark; INF-01. | Approved concurrent-session target and measured CPU/RAM/storage/bandwidth ceilings; overload denies safely. |
| INF-20 Android scope | BLOCKED | User product decision; remote control/display and client threat model. | Explicitly defer Android for MVP or approve supported client, auth, stream and privacy requirements with validation evidence. |

### Gate B decision

**Status: BLOCKED.** No Linux/KVM worker, production TLS boundary, operational owner, gateway/runtime/display/cleanup service, or infrastructure approval has been evidenced. The Phase A Decision Register is not present as a standalone file in the current repository inventory; the pending decisions recorded there in prior project work remain unapproved and are restated as dependencies here. **Phase A provisioning and worker configuration remain NOT READY.**

## 6. Current implementation inventory

Verified in the source at the baseline commit:

- `backend/app/services/worker_communication.py` implements worker certificate enrollment/renewal/revocation and peer validation, signed health intake and persisted-evidence reverification, and short-lived session-bound ticket issuance/revocation/redemption.
- Both ticket issuance and redemption recheck authorized session state, owner and worker binding, active identity, certificate/CRL validity, fresh signed healthy evidence, and Defence policy. Redemption uses a conditional one-time state update. SQLite obtains an immediate write reservation; PostgreSQL row-lock calls exist but lack execution evidence.
- `backend/app/agents/defence.py` owns the browser-worker policy check; policy defaults to disabled.
- Browser-session API and metadata storage exist, but they record authorization only. They do not launch a browser or provision a VM.
- Lifecycle transitions require supervisor evidence for provisioning and a cleanup verifier for closure; no real supervisor or verifier is configured.
- Local test certificates and a test TLS server exercise application-side certificate behavior. `backend/run_backend.py` starts loopback HTTP; it is not a production mTLS deployment.
- Source has five primary agent implementations; Wi-Fi Analysis remains nested under Finder. The six-agent target remains preserved in architecture documents; it is not six independently implemented agents.

## 7. Test evidence and verification date

Evidence was recorded on **2026-11-02** from the `backend` directory using the existing `backend\.venv` at the commit in the header:

| Command | Result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest -q tests\test_worker_communication.py` | 38 passed |
| `.\.venv\Scripts\python.exe -m pytest -q tests\test_browser_session_storage.py` | 13 passed |
| `.\.venv\Scripts\python.exe -m pytest -q tests\test_browser_sessions_api.py` | 17 passed |
| `.\.venv\Scripts\python.exe -m pytest -q tests\test_browser_session_manager.py` | 27 passed |
| `.\.venv\Scripts\python.exe -m pytest -q` | 134 passed in 18.72s |
| Four-module `--collect-only -q` | 95 collected on each of three separate runs |

`git diff --check` was clean at that verification point. The earlier intermittent SQLite `OperationalError: unable to open database file` did not reproduce in these runs; its root cause remains unresolved and it is **not fixed by non-reproduction**. `backend/tests/conftest.py` creates a per-process temporary directory, configures the database URL before application imports, disposes the engine at session end, then removes the directory. These facts do not identify the original failure cause.

These are backend application tests. They do not validate production mTLS deployment, PostgreSQL, real worker infrastructure, network egress, VM provisioning, browser isolation, remote display, or cleanup.

## 8. Outstanding engineering task register

| Task ID | Task / logical owner | Dependencies | Priority | Blocking condition | Required evidence and acceptance condition | Status / locus |
|---|---|---|---|---|---|---|
| ENG-01 | Add redemption-side database failure regression / Backend Engineering | Fault-injection fixture | High | Current DB-error test covers issuance only. | Inject failure during redemption reauthorization; prove denial, rollback, no redeemed timestamp, and no success response; rerun focused and full suites. | IN PROGRESS — local software |
| ENG-02 | PostgreSQL integration and concurrency job / Backend + CI Engineering | Select DB version and provide test service | High | No PostgreSQL execution evidence. | Migration, worker revoke/health update interleavings, ticket expiry/replay, and concurrent redemption pass on selected PostgreSQL. | NOT STARTED — engineering plus service dependency |
| ENG-03 | Diagnose intermittent SQLite collection error / Backend Engineering | Traceback and environment from recurrence | Medium | Root cause remains unknown. | Capture command, cwd, resolved DB URL (without secrets), temp directory existence/lifecycle, connection state and full traceback; reproduce or record bounded non-reproduction. | IN PROGRESS — investigation only |
| ENG-04 | Durable synchronized Defence policy updates / Defence + Platform Engineering | Policy owner and configuration/state design | High | In-memory switch has no durable update or coordination contract with ticket transaction. | Define atomic policy update semantics; test concurrent policy disable against issue and redemption; unknown state denies. | NOT STARTED — local implementation after decision |
| ENG-05 | Versioned migration and recovery rehearsal / Database + Operations | Database selection and backup owner | High | No versioned migration framework or production backup/restore evidence. | Versioned migration, legacy-data rehearsal, interruption/rollback plan and tested backup/restore. | NOT STARTED — technical/operator dependency |
| ENG-06 | Deploy private worker channel and scoped broker / Security + Infrastructure Operator | Approved host, ownership, network, CA/CRL, keys and budget | Critical | No real worker, broker, or trusted production TLS boundary. | End-to-end real-worker tests for peer identity, per-operation/session authorization, revocation, outages, logs and replay. | BLOCKED — external infrastructure |

## 9. Ownership and responsibility matrix

| Responsibility | Accountable logical owner | Current state | Evidence/approval required |
|---|---|---|---|
| Browser security policy | Defence AI product/security owner | Application policy exists, default deny | Approved policy authority and synchronized configuration semantics |
| User/session authorization | FastAPI auth boundary and Session Manager | Metadata authorization exists | User ownership tests; later end-to-end lifecycle tests |
| Worker certificate identity/tickets | Worker Communication Service; operational owner not assigned | Application foundation exists | Operator-owned CA, keys, private endpoint, real-worker validation |
| VM/browser execution | Worker Supervisor / runtime operator (not assigned) | Not implemented | Approved host, runtime, signed image, quotas and isolation tests |
| Egress | Egress Gateway / network operator (not assigned) | Not implemented | Approved topology and guest packet evidence |
| Display/input | Display Gateway / client-security owner (not assigned) | Not implemented | Transport, client scope, origin/input and isolation tests |
| Cleanup | Cleanup Manager / worker operator (not assigned) | No verifier | Independent cleanup receipts, quarantine/recovery evidence |
| Monitoring, keys, incident response, privacy | Named platform/security/privacy/incident owners (pending) | Not operationally established | Approved ownership, runbooks, rotation/retention and exercises |
| Six-agent integration | Existing logical agent owners; Wi-Fi remains under Finder in source | Target roles documented, integration incomplete | Preserve permissions and prove no agent bypass or untrusted-content instruction path |

No individual, organization, provider, budget, region, or infrastructure owner is inferred by this matrix.

## 10. Infrastructure dependencies and approvals

The following remain pending and must not be invented or inferred: worker ownership; host specification; hosting region; budget; privacy, consent and retention; local versus remote hosting; concurrency target; network and display topology; worker authorization/deployment boundary; and Android scope. Certificate authority, key custody, database support, monitoring, incident response, and backup ownership also require technical/operator decisions. Cost examples in feasibility documentation are not quotes or approvals.

The prior Phase A readiness decision remains in force: **provisioning and worker configuration are NOT READY**. Phase A may start only after required ownership/host, region/budget, privacy, concurrency, and network decisions are approved and the selected host is evidenced as compatible. This framework does not authorize spending or provisioning.

## 11. Risk and blocker register

| Risk | Status | Required response |
|---|---|---|
| Intermittent SQLite collection error, cause unknown | IN PROGRESS | Preserve failure evidence; do not suppress; a successful later run is not a fix. |
| PostgreSQL row-lock/migration behavior untested | NOT STARTED | Complete ENG-02 before claiming cross-database concurrency. |
| Defence policy switch is in-memory and unsynchronized | NOT STARTED | Complete ENG-04 before enabling live policy mutation. |
| No production mTLS trust boundary or worker owner | BLOCKED | Complete INF-01 through INF-08 with operator evidence. |
| No guest egress, browser runtime, display or cleanup verifier | NOT STARTED | Complete INF-09 through INF-14 and security validation before any isolation claim. |
| Migration/audit durability limitations | PARTIALLY VERIFIED | Adopt versioned migrations and protect/validate operational audit and recovery. |
| Hosting/privacy/budget/region/concurrency approvals missing | BLOCKED | Obtain user/operator decisions in §10; do not provision before approval. |

## 12. Acceptance criteria and gate decisions

**Software gate:** remains **PARTIALLY VERIFIED**. Accept only after SW-01–SW-17 satisfy their individual acceptance conditions; ENG-01, ENG-02, ENG-04, and ENG-05 are resolved or explicitly handled through a recorded authorized exception; all required tests pass; and an authorized reviewer accepts residual software risks.

**Infrastructure and operational gate:** remains **BLOCKED**. Accept only after required INF-01–INF-20 work is implemented on approved infrastructure, operational owners are assigned, production security boundaries are deployed, and end-to-end validation evidence is reviewed and accepted.

**Overall Milestone 5:** **PARTIALLY VERIFIED — NOT ACCEPTED.** No completion percentage is assigned. Both gates must reach **ACCEPTED** before overall milestone closure.

## 13. Conditions for the next milestone

The next local engineering work remains Milestone 5 software acceptance: add the redemption-side database-failure regression, establish PostgreSQL integration/concurrency testing, and define synchronized Defence policy update semantics. In parallel, obtain the pending Phase A approvals. Do not begin Phase A provisioning until those approvals and host compatibility evidence exist. Once both Milestone 5 gates are accepted, the next runtime milestone can begin with the approved Linux/KVM worker foundation and independent health/readiness checks.

## 14. Existing documentation reconciliation

- [ROADMAP.md](ROADMAP.md) summarizes milestone status and links here as the authority. Its previous “B” and “C” not-started statuses predate the current tested application foundations; they are updated to show local software progress while preserving infrastructure/runtime blockers.
- [INFRASTRUCTURE_FEASIBILITY.md](INFRASTRUCTURE_FEASIBILITY.md) remains authoritative for host feasibility and confirms that no production worker/TLS deployment or runtime has been evidenced.
- [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md) remains the threat register. SA-03/SA-04 implementation snapshots are older than current source and must not be used as current inventory; detailed reconciliation is captured here without removing their risks or test requirements.
- [README.md](../README.md) and [ARCHITECTURE.md](ARCHITECTURE.md) correctly state that genuine isolated browser preview is unavailable. No statement here changes that.
- The Phase A Decision Register is not present as a standalone file in the current repository file inventory. Its previously recorded pending approvals and “not ready” decision are preserved above; no approval is inferred.
