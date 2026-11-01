# Guard AI System Architecture & Security Specifications

Guard AI is an autonomous, multi-agent cybersecurity and privacy platform engineered for Windows computers and Android companion devices.

---

## 1. Multi-Agent Ecosystem

```
                          ┌──────────────────────┐
                          │    Controller AI     │
                          │(Central Orchestrator)│
                          └──────────┬───────────┘
                                     │ Event Bus
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
┌────────┴────────┐         ┌────────┴────────┐         ┌────────┴────────┐
│    Finder AI    │         │   Defence AI    │         │   Offence AI    │
│(Threat Discovery│         │ (Crypto Vault)  │         │ (Emergency Res) │
└────────┬────────┘         └─────────────────┘         └─────────────────┘
         │
         ├── Phishing & Typosquatting Agent
         ├── Static File Security Agent (Entropy & YARA)
         ├── Wi-Fi & Rogue AP Detection Agent
         ├── Browser Security & Isolated Preview Agent
         ├── Application Behaviour Monitoring Agent
         └── Spam & Social Engineering Detection Agent
```

### Agent Roles & Guardrails:
1. **Controller AI**:
   - Central coordinator maintaining agent heartbeats, routing messages, and calculating normalized threat scores (0–100 -> LOW, MEDIUM, HIGH, CRITICAL).
   - Enforces role-based permissions matrix before executing operations.
2. **Finder AI**:
   - Manages the 6 specialized detection agents. Synthesizes composite risk evaluations.
3. **Defence AI**:
   - Oversees the Cryptographic Maze vault.
   - Seals the vault and flushes plaintext credentials from volatile memory when threats escalate.
4. **Offence AI (Strictly Defensive)**:
   - Activates heightened or full containment mode.
   - Manages quarantined files in `data/quarantine/`.
   - Mandatory human approval for high-impact actions (simulated network cut-off / process termination).
5. **Informer AI**:
   - Generates natural, spoken briefings for the frontend Web Speech API.
   - Translates raw technical indicators into a 3-part plain-language summary:
     * *What was detected*
     * *Why it matters*
     * *Recommended action*
   - Strictly does not auto-report incidents to external authorities.

---

## 2. Cryptographic Maze Security

The Cryptographic Maze is a multi-tier layered defense system relying on established cryptographic primitives:

- **Key Derivation**: Passphrase + 16-byte cryptographic salt passed through PBKDF2-HMAC-SHA256 with **600,000 iterations** (exceeding OWASP minimums).
- **Key Separation (HKDF)**: Uses RFC 5869 Extract-and-Expand to derive distinct compartmentalized sub-keys:
  * `K_header`: For encrypting metadata and access-control tags.
  * `K_body`: For encrypting sensitive payload.
  * `K_recovery`: For emergency escrow envelopes.
- **Authenticated Encryption**: `AES-256-GCM` with a 96-bit unique nonce and 128-bit authentication tag.
- **Tamper Rejection**: Any alteration to ciphertext or tag raises an immediate authentication exception.

---

## 3. Blockchain-Style Tamper-Evident Audit Ledger

- Every system event (scans, logins, threat escalations, vault access) is recorded in a cryptographic hash chain:
  $$\text{Block Hash} = \text{SHA-256}(\text{Prev Hash} \parallel \text{Timestamp} \parallel \text{Actor} \parallel \text{Event Type} \parallel \text{Payload Hash})$$
- Modifying, deleting, or injecting an event retroactively breaks the mathematical chain.
- The `verify_integrity()` engine validates the ledger from Genesis to tip.

---

## 4. Isolated Browsing & File Sandbox

- Renders untrusted web destinations with all `<script>` tags, inline event handlers (`onload`, `onerror`), and `javascript:` URIs stripped.
- Restricts iframes with `sandbox="allow-same-origin"` to prevent drive-by script execution.
- Displays explicit operational disclaimers acknowledging that sandboxing mitigates risks but does not replace complete hardware air-gapping.
