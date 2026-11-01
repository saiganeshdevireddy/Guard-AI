# Guard AI Agent Specifications

**Status:** target responsibilities. Current implementation notes are explicitly distinguished; specifications are not deployed or tested controls. Canonical roles and ownership decisions are in [GUARD_AI_MASTER_ARCHITECTURE.md](GUARD_AI_MASTER_ARCHITECTURE.md); this is the six-role contract summary.

| Primary role | Responsibility and trust boundary | Current repository state |
|---|---|---|
| Autonomous Controller AI | Coordinate authorized tasks and lifecycle; request policy decisions; correlate validated findings; preserve human approval for consequential actions. It cannot grant its own API/user authority. | `ControllerAI` coordinates findings, severity, audit, Defence vault locking and Informer. FastAPI dependencies, not Controller, enforce API authorization. |
| Finder AI | Analyze submitted URLs, files, text and indicators; return evidence, uncertainty and provenance. Never assert guaranteed safety, authorize, or auto-launch browser sessions. | Local heuristic URL/file/text analysis exists; no remote URL fetch. |
| Defence AI | **Policy and product owner** for isolated browsing, URL protection, sandbox/private-session policy, isolation readiness and defensive session enforcement; preserve cryptographic vault protection. | Current `DefenceAI` is primarily vault encryption, key/session and lock handling. Browser policy functions are proposed and unimplemented. Session Manager, Worker Supervisor, Egress Gateway, Display Gateway and Cleanup Manager execute bounded operations under Defence policy. |
| Offence AI | Defensive incident containment, safe-mode request and local simulation; bounded actions with authorization and audit. | Local simulation/incident behavior exists. No external attack, exploitation, unauthorized scanning, or actual OS/network containment should be inferred. |
| Informer AI | Give the authorized user clear status, uncertainty, risk and action options. | Threat and vault briefings exist. No automatic authority reporting; that prohibition remains. |
| Wi-Fi Analysis AI | Analyze explicitly supplied/authorized wireless configuration and provide defensive recommendations. Live collection requires consent, platform capability and a separately approved design. It cannot authorize browser sessions or network changes. | `WifiSecurityAgent` is a specialized component registered through Finder, not yet an independent primary source-code agent. It analyzes supplied values; live monitoring is not established. |

## Message lifecycle

An agent finding is untrusted, typed evidence with source, timestamp, schema version, correlation ID and confidence. The policy layer validates it; Controller coordinates; FastAPI independently authenticates/authorizes user operations; Defence owns browser/security policy; session and worker services perform only bounded authorized operations; Offence may request bounded defensive containment; Informer communicates status; Wi-Fi Analysis returns authorized supplied-data findings only. Rejection, timeout, duplicate, stale version and partial failure are explicit outcomes. See the protocol document.

## Preserved supporting concepts

Transmitter (delivery), Transformer/blockchain (audit transformation/anchoring), Rollback/recovery, Cryptographic Maze Security, audit ledger, and emergency-safe-mode concepts are retained as design subjects. This repository audit did not establish complete independent Transmitter, Transformer, or Rollback implementations. `crypto_maze.py` and the local hash-chain/optional Hardhat audit adapter are existing code, with documented limitations.
