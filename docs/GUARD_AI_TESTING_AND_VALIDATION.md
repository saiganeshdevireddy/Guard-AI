# Guard AI Testing and Validation

**Status:** proposed test strategy. No tests were run for this architecture consolidation; no security control is verified by this document.

## Architecture and agent validation

- Verify six target roles and permissions, while current implementation is accurately shown as five primary agents plus nested Wi-Fi specialist.
- Test Finder false-positive/negative messaging, uncertainty, and that findings cannot authorize or create sessions.
- Verify user/API authorization independently from Controller coordination; test cross-user denial.
- Test Defence preserves vault protections and browser policy fails closed; test Offence only requests defensive, bounded containment; Informer never reports externally automatically.
- Fuzz message schemas, spoofed issuer, stale/expired messages, audience mismatch, replay, duplicate/idempotency conflict, oversized payload and prompt-injection content.
- Confirm browser-originated text remains inert data and cannot change policy, invoke tools or generate privileged agent messages.

## Browser runtime security gates (future)

1. **Isolation:** parallel users/sessions cannot see profiles, storage, processes, network or display; guest cannot reach host, control plane, LAN, another VM or metadata endpoint.
2. **Egress:** test IPv4/IPv6 loopback/private/link-local/reserved/metadata ranges, DNS rebinding and mixed DNS answers, redirects, alternate ports, proxy bypass, direct DNS, DoH, QUIC and gateway failure. Capture packet evidence at worker boundary.
3. **Identity:** wrong user/session/audience, expired or replayed ticket, revoked ticket and guessed IDs fail. Authorization is checked at create/status/stop/display operations.
4. **Lifecycle:** create/stop/timeout/crash/restart/partition/storage failure; cleanup idempotence; worker reconciliation; no unrelated resource deletion; failed cleanup quarantines worker/session.
5. **Display/input:** origin/CSRF, ticket theft/replay, malformed input, rate/size bounds, clipboard/file/device/debug disabled, revocation latency.
6. **Privacy:** canary credentials and page content do not appear in API logs, agent events, audit DB, crash report, metrics or retained profile. Define and verify retention/deletion before production use.
7. **Availability:** concurrency, CPU/memory/disk/network exhaustion, slow clients, browser crash, queue pressure and cost/quota controls.
8. **Supply chain and recovery:** verify signature/provenance, pinning, revocation, rollback, key rotation, backup/restore and safe-mode recovery.

## Evidence and release criteria

Each test records versioned setup, exact policy/image/config digest, expected result, observed result, packet/log evidence with secrets removed, owner and date. Separate unit, integration, fault-injection and independent security assessment evidence. Release is blocked by any unauthorized session, cross-session data/control access, direct egress, metadata access, unrevoked display path, cleanup uncertainty without quarantine, or privacy leakage. Re-run the full security gate after agent integration and material worker/image/gateway changes.

Existing test counts in the repository roadmap are definitions, not execution results. This task did not execute application tests.
