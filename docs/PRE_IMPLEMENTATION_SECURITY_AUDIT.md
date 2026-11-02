# Guard AI Pre-Implementation Security Audit

**Readiness summary; defer architecture decisions to canonical records:** [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md), [ISOLATED_BROWSER_ARCHITECTURE.md](ISOLATED_BROWSER_ARCHITECTURE.md), and [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md). This file preserves the earlier readiness audit and source evidence.

## Conclusion

**Phase A is not ready to begin.** This is a documentation and source review, not a penetration test or validation of a deployed browser system. No browser worker/runtime, broker, egress gateway, remote display service, or browser-session API is implemented. No hosting owner, Linux/KVM host, budget, region, privacy/retention policy, concurrency target, or local-versus-remote MVP choice is approved. Do not provision or claim a verified security boundary until those gates are resolved.

The proposed one-Firecracker-microVM-per-session design remains a reasonable direction for evaluation, but several security controls need testable interfaces and exact network paths before implementation. The updated [MVP plan](BROWSER_RUNTIME_MVP_IMPLEMENTATION_PLAN.md) records those corrections; the existing architecture and research remain proposals.

## Source facts verified

Read-only source review confirmed:

- `backend/app/main.py` starts Uvicorn on `127.0.0.1`, configures CORS without credentials, and reports isolated preview as disabled. It has no browser-session router or worker service.
- `backend/app/routers/sandbox_api.py` exposes `/preview-url`, requiring `sandbox:write`; the handler delegates to local review and does not fetch/render remote content. `backend/app/services/sandbox_engine.py` describes this limitation.
- `backend/app/security/auth.py` enforces JWT bearer authentication and role permission in FastAPI. The configured `operator` role has `sandbox:write`; Controller AI itself is not the API authorization layer. The default token TTL is 900 seconds in configuration, and auth supports revocation through the current database.
- `frontend/src/services/api.js` keeps the current API token in the client module's JavaScript memory and sends it as a bearer header. This remains exposed to same-origin script compromise; current architecture documentation says the prototype is not suitable for public/shared exposure.
- `backend/app/agents/finder.py` includes the submitted URL and report details in `THREAT_REPORT_SUBMITTED`; `backend/app/agents/controller.py` persists the indicator and details JSON into `ThreatEvent`. Raw session URLs must not be sent through this existing persistence/event path without a privacy design.
- `backend/app/agents/specialized/browser_agent.py` returns `sandbox_ready: true` whenever `inspect_destination()` receives a headers dictionary. `handle_message()` defaults missing headers to `{}` and passes it, so `POST /api/v1/agents/message` can return `sandbox_ready: true` without live headers, a worker, VM or session. The normal URL review path calls the inspector with `None` and returns false. The field must never gate or imply runtime isolation.
- `backend/app/agents/base.py` uses a synchronous in-process event bus that retains recent event payloads in memory. It is not a durable session queue or watchdog.
- `backend/app/database.py` uses SQLAlchemy with SQLite by default and has no browser-session model or migration framework. The existing hash-chain audit ledger is not immutable storage.
- `frontend/src/components/IsolatedSandbox.jsx` is a local URL Review interface and explicitly states content is not fetched or rendered.

These observations were not application tests; no tests were executed for this audit.

## Architecture consistency and readiness findings

| ID / priority | Finding and evidence | Required correction before the relevant phase | Residual risk |
| --- | --- | --- | --- |
| **R0 — Readiness blocker** | Hosting recommendation is hybrid, while host availability, owner, region, budget, privacy, concurrency, and local/remote scope are undecided. The assessed Windows Home laptop is not the target KVM worker. | Obtain explicit decisions listed below before Phase A procurement or system changes. Phase A must begin with a named owner and approved host specification. | A supported host can still fail capacity, availability, or KVM exposure checks. |
| **H1 — Worker authorization** | The plan previously named mTLS but did not fully separate peer authentication from authorization. A valid FastAPI service certificate alone must not imply permission to create/destroy any session or choose arbitrary images/resources. | Define broker operation/resource authorization, signed/integrity-protected owner context, per-user and global quotas, fixed image/policy allowlists, hard worker caps, identity issuance/rotation/revocation and emergency disable. Reject unknown/overbroad operations. | A compromised authorized control plane may still consume its bounded allocation or act for users if its own authorization is compromised. |
| **H2 — Egress enforcement** | Firecracker's network path uses host TAP/routing; Firecracker does not itself filter guest traffic. The design describes policy, but exact interfaces, routes, ports, IPv4/IPv6 and gateway failure behavior were not an enforceable network-flow specification. Upstream Firecracker documents host-side filtering requirements ([production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md), [network setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/network-setup.md)). | Before navigation, install default-deny host forwarding and route only guest HTTP(S) proxy traffic to the egress gateway. Gateway validates each connection-time DNS result and destination, rechecks each redirect/retry, rejects private/loopback/link-local/reserved/multicast/metadata/NAT64 and IPv4-mapped/IPv6 ranges, and pins allowed addresses. Disable browser DoH and block direct DNS, UDP/QUIC, WebRTC/STUN and unapproved ports; prove with packet/canary tests. | Firewall/gateway or host compromise can defeat network boundaries. Public sites can still receive information deliberately entered by the user. HTTPS proxying without TLS interception limits content visibility; URL-level policy must be explicit. |
| **H3 — Raw URL privacy** | Finder events persist the full submitted URL and report details. URLs often carry credentials-like values, identifiers, search terms or tokens in query/fragment fields. | Keep session URL out of generic agent events, threat descriptions, metrics, exception text and audit logs. If Finder context is required, pass only a reviewed redacted origin/indicator. Define retention/access for any required host metadata. | DNS, gateway and provider logs can still reveal destination and timing. Redaction can miss sensitive data in paths or unusual encodings. |
| **H4 — Display capability replay/leakage** | “Short-lived, single-use ticket” is not yet a complete protocol. Browser WebSocket APIs do not offer general custom-header control, and URL tickets can leak into access logs, analytics and referrers. | Define ticket issuance and browser-compatible exchange. Prefer an opaque, high-entropy capability whose hash is stored and atomically redeemed once, with user/session/audience/origin/expiry binding and revocation. Avoid URL secrets; use a reviewed same-origin HTTPS handshake/session cookie or another mechanism with logging protections. Address concurrent redemption, gateway replicas, logout/stop, clock skew and key rotation. | A compromised same-origin script or display gateway can still capture an active stream; revocation races and browser cookie constraints require testing. |
| **H5 — Display network and input path** | The docs gave an ambiguous direction for VM/display traffic and had not selected Guacamole/VNC topology or port-level connectivity. “Keyboard/pointer only” is not an input validation specification. | Select a display transport and define direction, per-session endpoint, interface, exact port and ACL. Permit only the display gateway to the session's display endpoint on an isolated display network. Validate message type, dimensions/ranges, rate/size, close handling and WebSocket origin; disable clipboard, file/device channels and protocol extensions. Test malformed frames and input floods. | A compromised browser or guest may attack its display service; display gateway/client parser remains part of the trusted attack surface. |
| **H6 — Ephemeral storage claims** | Plans treated deleting overlays as cleanup verification. Unlinking an SSD file does not prove physical erasure; swap, crash dumps, snapshots, backups and host page cache can retain data. | Use unique per-session encrypted writable storage and destroy its data-encryption key; keep guest data out of snapshots/backups, assess swap/crash-dump policy, and reconcile key/VM/network teardown. State that cryptographic erasure reduces remanence risk but does not prove physical-media sanitization. | Host compromise or key capture before destruction; residual copies may persist in unreviewed storage paths. |
| **H7 — Readiness, restart and gateway loss** | A health endpoint can report process liveness while firewall, image, route or display policy is wrong. A worker/API restart can leave an unknown VM; a gateway outage can race with a new connection. | Separate liveness from readiness. Readiness checks must verify KVM, image digest/signature, supervisor/jailer version/config, resource headroom, actual host firewall/rules/routes, gateway and display path, clock, disk, stale-session/cleanup backlog and configuration freshness. A local host firewall must continue blocking egress if the gateway fails. On uncertainty revoke streams, fence/quarantine affected guest networking, stop/reconcile tagged sessions and deny new ones. | Host-level control compromise may falsify health; network partition can delay cleanup and leave resources running until the watchdog/owner responds. |
| **H8 — Control-plane exposure and abuse** | The app is loopback-bound and prototype bearer auth; auth docs identify same-origin script exposure and missing MFA/rate limiting/account lifecycle controls. Remote hosting would widen the attack surface. | Keep API private behind an approved TLS/identity edge; decide origin/CORS, user identity, explicit consent, rate limits, session quotas, spend caps, account protection and operational access before remote launch. Worker-side global caps must remain effective if FastAPI is compromised. | API or identity compromise can launch bounded malicious sessions; endpoint XSS can steal the user's current bearer token. |
| **H9 — Untrusted content to agents** | The proposed pixel stream avoids putting website DOM in React, but display frames, titles/errors and user-controlled URLs remain untrusted. Existing agent bus accepts arbitrary payloads and stores history. | Pass agents only allowlisted lifecycle events and opaque session IDs. Never send page DOM, scripts, text, display frames, URLs with secrets, or user-controlled page messages as agent instructions/tools. Add adversarial event-injection tests proving page content cannot invoke an agent, API or worker operation. | Human users can be socially engineered by rendered content; the stream client still parses attacker-influenced data. |
| **H10 — Misleading existing readiness field** | `BrowserSecurityAgent.handle_message()` defaults headers to `{}`, and `inspect_destination()` treats any dictionary as supplied headers, so direct agent messages can emit `sandbox_ready: true` without live header retrieval or worker/session readiness. The normal URL review path returns false. | Treat this field only as legacy heuristic output; do not use it in runtime launch or health decisions. Any future session readiness must come from authenticated worker checks with independently tested host policy. | Existing API consumers with `agents:write` may misinterpret the direct-agent response; correction requires a separate source-code task. |
| **H11 — VM escape and resource abuse** | Per-session VMs reduce shared guest state, but the trusted computing base includes host Linux/kernel, KVM, Firecracker/jailer, image builder, broker and privileged network config. Resource settings are still estimates. | Patch host/kernel/VMM/guest; use jailer/default seccomp, per-VM identity, cgroups and storage/network limits; reserve capacity; rate-limit session creation; test hostile pages and crash paths; independently review multi-tenant exposure before broader use. | VM escape, side channels, host zero-days and bounded-cost denial of service cannot be eliminated. Do not claim absolute isolation or production readiness. |

## Seven-milestone audit and corrected dependencies

The plan now includes per-phase input/output and fail-closed contracts, required work, dependencies, deliverables, test scenarios, completion criteria and risks. Numeric limits that depend on unknown host/concurrency remain proposed and must be approved before testing; the existing 15-minute session, 5-minute idle and RPC/provision deadlines are planning assumptions, not verified performance targets.

| Phase | Audit result and required gate |
| --- | --- |
| **A. Worker infrastructure and health** | Prerequisites are not met. Host/owner/budget/region and network ownership must be approved. Define fresh liveness vs readiness, exact policy/route checks, negative readiness tests and operational ownership before declaring complete. A metadata-only authenticated browser-session API exists; browser/runtime sessions remain unavailable. Current milestone evidence is in [MILESTONE_5_ACCEPTANCE_FRAMEWORK.md](MILESTONE_5_ACCEPTANCE_FRAMEWORK.md). |
| **B. Secure worker communication** | Depends on A. Add explicit authorization beyond mTLS, owner/session scope, resource ceilings, replay/idempotency, rotation/revocation, deadlines and failure behavior. |
| **C. Session manager** | Depends on B and decisions on persistent store, user identity, retention, consent and quotas. Current SQLite/in-process event bus are not a distributed session service. Define canonical transitions and owner checks; no raw URLs in existing threat storage. |
| **D. Disposable browser runtime** | Depends on A–C. Verify signed image and per-session encrypted overlay/key; apply network restrictions before boot/navigation; define browser/profile ephemeral policy and cleanup/remanence evidence. |
| **E. Remote display/input** | Depends on B–D plus selected transport and network-flow ports. Define ticket atomic redemption and browser-compatible handshake; validate keyboard/pointer protocol and disable side channels. |
| **F. Security validation** | Split into a **baseline harness/gate after E but before G**, then **full regression/release gate after G**. A final gate before agent integration alone cannot validate agent event boundaries. Any critical network/isolation/cleanup failure is a no-go. |
| **G. Guard AI integration** | Depends on C and passing Phase F baseline; final F regression follows G. FastAPI authenticates/authorizes and checks explicit intent; Controller coordinates only authorized lifecycle events; Finder never certifies safety/auto-launches; Defence applies defensive policy; Offence never attacks externally; Informer reports status without automatic authority reporting. |

Corrected dependency sequence: **user decision gate → A → B → C → D → E → F baseline → G → F final security/regression gate**. Failures in any phase block the dependent phase or release as described in the plan.

## Remaining user decisions before Phase A

All remain **pending**; none are inferred from this audit:

1. Is a separate Linux/KVM server available, and who owns, patches and responds to it?
2. If not, is cloud bare metal acceptable, and who owns the account and cloud operations?
3. What is the maximum monthly budget, pilot duration, spend-alert threshold and shutdown authority?
4. Which region/jurisdiction is preferred or prohibited?
5. What browser/session metadata may be retained, by whom, and for how long? What consent/notice is required?
6. How many simultaneous sessions and users are expected? What session duration and latency are acceptable?
7. Should the first MVP be local-only or remote? Is Windows control plane plus remote Linux worker the chosen shape?
8. Are Android browser access and mobile streaming in MVP scope?
9. Who owns host patching, gateway operation, display operation, alerts, cleanup failures and incident response?
10. Is Guacamole/VNC acceptable after license, maintenance and network-path review? What websites/protocols must be supported?

## Implementation readiness

**Not ready for Phase A.** A documentation plan exists, but the prerequisite host, ownership, budget, region/privacy, concurrency and local/remote decisions are absent. The readiness indicators from the development laptop do not establish a suitable Linux/KVM worker. There is no cloud quote or user spending approval. Continue only with documentation and decision gathering until these answers are recorded. After approval, Phase A may validate a selected host; it must not be treated as approval to expose a browser session or skip Phases B–F.

### Updated readiness checklist (all pending)

- [ ] Worker owner and on-call/maintenance responsibility.
- [ ] Host specification and verified Linux/KVM/Firecracker compatibility.
- [ ] Hosting region and legal/privacy jurisdiction.
- [ ] Maximum monthly budget, spend alerts and shutdown authority.
- [ ] Privacy, consent, collection, retention and deletion policy.
- [ ] Local versus remote execution and control-plane exposure decision.
- [ ] Expected users/concurrent sessions and resource quotas.
- [ ] Display transport, capability handshake, topology, ports and ACLs.
- [ ] Egress gateway placement, DNS behavior, routes, protocols and allowed destinations.
- [ ] User/service authorization model, stable subject ID, identity issuer and recovery authority.
- [ ] Android scope and client requirements.
- [ ] Named owners for worker, gateway, display, keys, audit, updates, privacy and incidents.

The component owners and interface contracts are in [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md); canonical decisions and findings are [ISOLATED_BROWSER_ARCHITECTURE.md](ISOLATED_BROWSER_ARCHITECTURE.md) and [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md).

## Scope and validation performed

Reviewed the six requested architecture, feasibility, plan, application architecture and roadmap documents plus the relevant FastAPI routers, auth dependency, main app, sandbox engine, Finder, Controller, event bus, database, phishing/browser posture helpers, hybrid explanation and React URL Review component. Documentation links and Mermaid fences were checked; diagrams were reviewed for node/flow consistency but not parsed/rendered by a Mermaid engine. This audit did not execute application tests, provision a host, or verify any proposed security control in runtime.
