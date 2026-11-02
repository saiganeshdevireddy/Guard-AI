# Guard AI architecture

## Runtime

```text
React + Vite dashboard
        │ local HTTP API
        ▼
FastAPI on 127.0.0.1:8000
  ├─ Controller and in-process event bus
  ├─ Rule-based Finder agents
  ├─ Vault, audit, incident, and demo endpoints
  └─ SQLAlchemy → SQLite (default)
```

The Vite development server proxies `/api` to the local FastAPI service. The backend is bound to loopback. Protected API routes require configured bearer authentication; health and token exchange are public. The frontend signs in, retains the short-lived bearer token in JavaScript memory, and sends it on protected requests. Keep the backend local; this prototype is not ready to expose on a shared or public network.

## Agent roles

- **Controller AI** stores scan events, normalizes the severity score, locks the vault session for elevated findings, and marks critical findings for operator review. It does not self-approve emergency mode.
- **Finder AI** calls local URL, file-byte, Wi-Fi-input, and text heuristics.
- **Application Behaviour Agent** accepts process metadata from a caller. It starts IDLE and does not observe Windows processes itself.
- **Defence AI** encrypts vault items and records vault events.
- **Offence AI** changes local incident state and exposes labelled simulations. It does not terminate processes or isolate network adapters.
- **Informer AI** creates plain-language summaries; the browser may speak them using Web Speech.

The event bus and agent objects exist in one Python process. SQLite stores threat and audit records, but not a durable distributed queue or a separate agent service.

## Data protection

- The vault uses AES-256-GCM with PBKDF2-HMAC-SHA256 and HKDF-derived keys. Each vault item stores its own salt and nonce with ciphertext/tag.
- The audit ledger hashes payloads and links records using the previous block hash. It detects changes in retained history; it is not immutable storage and cannot detect removal of a trailing suffix without a trusted external checkpoint.
- The API limits uploaded file inspections to the configured byte limit. Scans inspect bytes only and do not execute or move the original file.
- Local rules and explanatory text run without cloud requests. The optional cloud provider shown in older documentation was a mock and is not implemented.
- Genuine isolated browser preview is not implemented. URL Review does not fetch or render remote pages or inspect live response headers; the URL endpoint returns local heuristic review only. Avoiding backend URL fetching also prevents the preview feature from becoming an SSRF path to local network resources.

## Integrations not included

- No hardened isolated browser runtime, Windows service, process enumeration, browser extension, file-system watcher, or network adapter controller exists.
- No Android app, pairing flow, authentication protocol, background service, or real remote lock exists. The API offers explicitly labelled in-memory demo values only.
- No threat-intelligence feed, cloud AI provider, external blockchain, or OS-backed key store is configured.
- Native OS integration would require separately designed permissions, signing, update, pairing, and failure-handling workflows.

The proposed genuine browser-isolation design, deployment comparison, and approval gate are documented in [ISOLATED_BROWSER_ARCHITECTURE.md](ISOLATED_BROWSER_ARCHITECTURE.md). The existing URL Review remains a local heuristic check; no genuine isolated browser runtime is implemented.

The consolidated target roles and component ownership matrix are in [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md), with current security findings in [SECURITY_AUDIT_FINDINGS.md](SECURITY_AUDIT_FINDINGS.md). These are documentation decisions and plans, not implemented controls.
# API authentication boundary

The FastAPI service issues HS256 JWTs using PyJWT and verifies passwords with
pwdlib's recommended Argon2id implementation. There are no default users or
default signing keys. Users and their hashes are provisioned out of band;
short-lived token IDs are stored in the database for persistent revocation.
Agent, scanner, Vault, Audit Ledger, emergency, sandbox, and Android routes
require server-side role permissions. Health and credential exchange are the
only public routes. CORS is a browser-origin policy and is not authentication.

The frontend signs in through `POST /api/auth/token`, keeps the short-lived JWT
in JavaScript memory only, sends it in the `Authorization: Bearer` header, and
calls `POST /api/auth/revoke` at sign-out. Reloading clears the token and
requires sign-in. An API 401 clears the local session; a 403 keeps the session
and displays a permission denial. Tokens and passwords are not written to
localStorage, sessionStorage, URLs, or application logs.

HttpOnly cookie authentication was evaluated but is not supported by the
current FastAPI contract: it returns a bearer token in JSON, accepts bearer
headers, sets no session cookie, and has no CSRF token or origin-bound CSRF
validation. The current integration therefore uses transient in-memory bearer
tokens, which remain exposed to same-origin script compromise. A cookie design
requires a coordinated backend change to set Secure/HttpOnly/SameSite cookies,
validate CSRF tokens and request origins, configure credentialed CORS for
explicit origins, and revoke/expire sessions. Do not enable credentialed CORS
alone as a substitute for CSRF protection.

The API CORS allowlist permits the `Authorization` request header for
configured origins. CORS remains a browser-origin control, never
authentication. This prototype does not yet include MFA, delegated identity,
automated account lifecycle, login rate limiting, refresh-token rotation, or a
distributed revocation store. Do not expose it as production-ready on the basis
of this prototype authentication layer alone.
