# Guard AI — Autonomous Multi-Agent Cyber Defence & Privacy Platform

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI_0.110-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React_18_+_Vite-61DAFB?logo=react&logoColor=black)](https://react.dev)
[![Cryptography](https://img.shields.io/badge/Security-AES--256--GCM_+_PBKDF2-blueviolet)](https://cryptography.io)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-21_Passed-brightgreen)](docs/ROADMAP.md)

**Guard AI** is a multi-agent cybersecurity and privacy platform built for Windows computers and Android mobile devices. It autonomously detects threats, secures sensitive data with layered authenticated encryption, coordinates defensive incident responses, and explains security alerts through voice and visual interfaces.

---

## Key Highlights

- **Autonomous Multi-Agent Architecture**:
  * **Controller AI**: Central coordinator, threat severity calculator (0–100 -> LOW, MEDIUM, HIGH, CRITICAL), permissions engine.
  * **Finder AI**: Discovers threat vectors across URLs, files, network profiles, and text communications.
  * **Defence AI**: Oversees the Cryptographic Maze vault and enforces auto-locking policies upon elevated threat detection.
  * **Offence AI (Strictly Defensive)**: Rapid containment, quarantine management, and simulated network/process isolation with human approval gating.
  * **Informer AI**: Voice-based security briefing generator (Web Speech API) translating technical events into 3 plain-language explanations: *What happened*, *Why it matters*, *Recommended action*.
  * **6 Specialized Detection Agents**: Wi-Fi Security, Browser Safety, Phishing/Typosquatting, File Entropy & Signatures, Application Behavior, and Spam/Scam Detection.

- **Cryptographic Maze Security**:
  * Authenticated Encryption with Associated Data (AEAD) using `AES-256-GCM`.
  * `PBKDF2-HMAC-SHA256` key derivation with **600,000 iterations** (exceeding OWASP baselines).
  * `HKDF` key separation: independent sub-keys for metadata, body payload, and disaster recovery.
  * Offline disaster recovery envelope via Fernet dual-wrapping.

- **Tamper-Evident Blockchain Audit Ledger**:
  * Every scan, encryption, lock, and incident is sealed in a continuous SHA-256 hash chain:
    $$\text{Block Hash} = \text{SHA-256}(\text{Prev Hash} \parallel \text{Timestamp} \parallel \text{Actor} \parallel \text{Event Type} \parallel \text{Payload Hash})$$
  * Built-in integrity verification engine flags any modified or deleted database records.

- **Isolated Browsing Environment**:
  * Safe preview container stripping executable `<script>` tags, inline event handlers, and active payloads.
  * Security header audit (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).

- **Hybrid AI Architecture with Strict Local Privacy**:
  * Default 100% offline local rule and heuristic evaluation.
  * Zero sensitive file or credential transmission to the cloud.
  * Automatic PII redaction (email, IPs, tokens) before any optional cloud intelligence query.

- **Cross-Platform Boundaries**:
  * Windows native APIs & process monitoring.
  * Android companion synchronization API without claiming silent, unrestricted OS monitoring.

---

## Project Structure

```
Guard AI/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI application entry & lifespans
│   │   ├── config.py                   # Settings & privacy mode configuration
│   │   ├── database.py                 # SQLite ORM models & session
│   │   ├── core/
│   │   │   ├── crypto_maze.py          # Layered AES-256-GCM AEAD encryption
│   │   │   ├── audit_chain.py          # Tamper-evident blockchain hash ledger
│   │   │   └── permissions.py          # Role matrix & human approval gating
│   │   ├── agents/
│   │   │   ├── base.py                 # Base agent & pub/sub event bus
│   │   │   ├── controller.py           # Central orchestrator
│   │   │   ├── finder.py               # Threat discovery coordinator
│   │   │   ├── defence.py              # Vault security & data segmentation
│   │   │   ├── offence.py              # Defensive emergency containment
│   │   │   ├── informer.py             # Voice briefings & plain English summaries
│   │   │   └── specialized/            # 6 specialized neural detectors
│   │   ├── routers/                    # Clean modular REST API routers
│   │   └── services/                   # Hybrid AI & isolated sandbox engine
│   ├── tests/                          # 21 automated pytest test suites
│   ├── requirements.txt                # Python backend dependencies
│   └── run_backend.py                  # Backend startup launcher
├── frontend/
│   ├── src/
│   │   ├── App.jsx                     # Dashboard coordinator & telemetry bar
│   │   ├── index.css                   # Cyber glassmorphic design system
│   │   ├── components/                 # UI panels (AgentGrid, Scanner, Vault, etc.)
│   │   └── services/                   # API client & Web Speech voice engine
│   └── package.json                    # React + Vite configuration
├── docs/                               # Architecture, Roadmap & Beginner Guide
└── README.md
```

---

## Quickstart

### 1. Launch Backend:
```powershell
.venv\Scripts\python.exe backend\run_backend.py
```
*API running at `http://127.0.0.1:8000` (Swagger docs at `/docs`)*

### 2. Launch Frontend:
```powershell
cd frontend
npm run dev
```
*Dashboard running at `http://localhost:5173`*

### 3. Run Automated Tests:
```powershell
.venv\Scripts\pytest.exe backend\tests -v
```

---

## Development Roadmap (V0.1 — V1.0)

All phases from V0.1 to V1.0 have been fully implemented, integrated, and verified through automated test suites. Review [docs/ROADMAP.md](docs/ROADMAP.md) for detailed breakdown.
