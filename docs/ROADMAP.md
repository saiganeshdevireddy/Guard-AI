# Guard AI implementation status

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
| Isolated browser | Not implemented. URL Review does not fetch or render remote content. | Use a disposable VM or separately isolated browser for suspicious pages. |
| Android companion | A labelled in-memory demonstration workflow is available. | No native application, pairing/authentication protocol, live telemetry, or device lock command. |
| Cloud AI | Not configured; summaries remain local. | No provider integration or outbound AI request is implemented. |

## Verification status

The repository contains 24 pytest cases for scanners, agent decisions, API workflows, vault crypto, and audit integrity. They must be run locally with the instructions in [GETTING_STARTED.md](GETTING_STARTED.md). Do not treat the README's earlier test badge or historical pass claims as current test results.
