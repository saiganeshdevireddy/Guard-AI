# Guard AI Security Extensions

**Status:** proposed security extensions, not implemented or verified. Defence AI owns browser/security policy decisions; the execution-component ownership matrix is in [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md). Existing local vault encryption and hash-chain behavior is not a substitute for the controls below.

Use [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md) as the canonical source for identified risks and required fallback/validation evidence.

## Independent infrastructure

1. **Policy Decision Engine (PDP):** Defence AI owns policy; the engine evaluates default-deny, versioned rules, authenticates requester/workload and authorizes user, action, resource, session and context. It returns bounded decision, reason, expiry and policy version. Enforcement points reject missing/stale decisions.
2. **Agent/workload identity:** distinct service identities, least privilege, short-lived credentials, rotation, revocation, audience-bound requests and explicit authorization separate from transport authentication.
3. **Secure communications:** authenticated encrypted channels; typed/versioned schemas, size limits, request IDs, timestamps, nonce/replay cache, idempotency, deadlines and signed provenance where messages cross trust boundaries.
4. **Watchdog and state:** durable lifecycle state; independent worker reconciliation; readiness attestation; quotas; startup reconciliation; fail closed on stale policy or health. No reliance on synchronous in-process bus for cleanup.
5. **Keys and recovery:** external protected key custody for production, rotation, scoped access, backup/recovery drills and no secrets in source, logs, browser guest or audit payloads. Current passphrase-derived vault keys do not provide host-resistant custody.
6. **Update and supply chain:** pinned versions, reviewed build inputs, signed immutable guest images, provenance, vulnerability response, staged rollout, rollback and revocation.
7. **Privacy and audit:** minimize event fields; keep sensitive values out; define purpose, access, retention, deletion and jurisdiction; protect audit access and integrity. Local hash chaining is tamper-evident only under its storage assumptions.
8. **Safe mode and incidents:** independently deny new sessions, revoke tickets, fence sessions, preserve bounded metadata, notify operator, and require documented recovery checks.
9. **Resources and monitoring:** admission control; CPU/RAM/disk/network/session quotas; alerts for policy drift, orphan resources, cleanup failure, abuse and saturation.

## Browser isolation enforcement

Use one disposable VM per session, a hardened/pinned hypervisor and minimal guest, separate control/display/data networks, host-enforced default-deny firewall, mandatory policy gateway, DNS/IP validation at connect time, redirect revalidation, IPv4/IPv6 private and metadata blocking, and no direct egress fallback. Restrict protocols and ports; explicitly decide allowed domains. Gateway failure must not restore direct guest routing. Browser profiles, writable overlays and downloads are ephemeral; cleanup status is verified and failures quarantine capacity.

Remote display tickets must be short lived, session/user/audience bound, single-purpose, revocable and protected against replay. Input accepts only bounded keyboard/pointer events; clipboard, file transfer, device redirection and arbitrary browser debugging interfaces are disabled by default. Do not log page contents or input.

## Retained limitations

VMs do not eliminate hypervisor escape, worker compromise or side-channel risk. Network filtering cannot guarantee safety from permitted hostile content. Resource limits do not eliminate shared-worker denial of service. A compromised Windows control plane may misuse its allowed worker authority; constrain that authority, require explicit user intent, audit it and make worker policy independently enforceable. Privacy and retention choices need owner approval before data-bearing deployment.
