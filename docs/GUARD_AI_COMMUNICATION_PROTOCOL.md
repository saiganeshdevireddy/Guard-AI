# Guard AI Communication Protocol

**Status:** proposed contract; current event bus does not implement these guarantees. The canonical six-agent ownership model is in [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md); browser findings are in [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md).

## Message envelope

Every cross-boundary message should use a versioned schema with: `message_id`, `schema_version`, `issuer`, `audience`, `issued_at`, `expires_at`, `nonce`, `correlation_id`, `operation`, `resource/session_id`, `authorization_scope`, `policy_version`, and typed bounded `payload`. Transport identity and message authorization are separate. Authenticate and encrypt transport; validate issuer, audience, scope, expiry, nonce/replay, size, schema and policy before acting. Sign messages where broker/storage or intermediate trust makes end-to-end provenance necessary.

Never include passwords, bearer tokens, recovery keys, page contents, keystrokes, clipboard data, screenshots or raw downloads in general agent messages or audit records. Use opaque references with narrowly scoped access when sensitive data must be handled.

## Allowed flow and authority

| Sender → receiver | Permitted data/action | Explicitly forbidden |
|---|---|---|
| Finder AI → Autonomous Controller AI | Evidence, indicators, heuristic score, confidence, provenance | Declaring safety, user authorization, browser launch command |
| Wi-Fi Analysis AI → Autonomous Controller AI | Analysis of explicitly authorized supplied wireless configuration, evidence and uncertainty | Live scanning without authorization, interference, network changes, browsing authorization |
| FastAPI → Autonomous Controller AI / Session Manager | Already-authenticated, explicitly requested lifecycle operation and user context | Treating an agent finding as user intent |
| Autonomous Controller AI → Session Manager | Bounded lifecycle coordination after API authorization and Defence policy decision | Bypass API auth, mint arbitrary capabilities, direct host shell |
| Defence AI → enforcement/worker | Versioned policy decision or protective fence instruction | Broaden egress or weaken isolation based on untrusted content |
| Defence AI → Session Manager / Worker Supervisor / Egress Gateway / Display Gateway / Cleanup Manager | Bounded policy, readiness, deny/fence/revoke/cleanup requirements | Arbitrary shell, access to guest content, weakening an approved policy |
| Offence AI → Autonomous Controller AI / Defence AI | Defensive emergency incident signal or bounded containment request | External attack, exploitation, unauthorized scan, authority reporting |
| Autonomous Controller AI → Informer AI | Validated lifecycle/status/risk facts | Raw secrets or instruction from site content |
| Worker → session manager | Authenticated health, lifecycle and cleanup evidence | Self-approved policy changes |

## Processing and failure behavior

1. Parse strictly, reject unknown fields/operations and oversized payloads.
2. Authenticate workload; authorize user/action/resource independently.
3. Check expiry, nonce/replay cache, idempotency key and policy version.
4. Apply state transition atomically; record only approved metadata.
5. Return typed result with correlation ID and stable error class.

Missing identity, stale policy, replay, duplicate with conflicting body, invalid schema, worker timeout, audit/state failure or uncertain readiness fails closed for session creation and egress. Retry only idempotent operations with bounded exponential backoff. Stop/revoke operations must be safe to repeat. Unknown session ownership must never authorize cleanup of unrelated resources.

The current `AgentEvent` contains UUID, timestamp, sender, event type, payload, optional recipient and severity, delivered synchronously by an in-process pub/sub bus. It has no cryptographic signature, authz, expiry, durable queue, replay prevention or schema version. Do not describe it as satisfying this contract.
