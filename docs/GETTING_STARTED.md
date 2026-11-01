# Getting Started with Guard AI

Welcome to **Guard AI**! This guide is written in beginner-friendly language to help you run and test the complete system on your Windows machine.

---

## 1. Quick Requirements

- **Python 3.11+**
- **Node.js 18+** & npm

---

## 2. Running the Backend Server (FastAPI)

1. Open PowerShell in your project folder (`C:\Users\Administrator\Desktop\Guard AI`).
2. Run the backend startup script using the virtual environment:

```powershell
.venv\Scripts\python.exe backend\run_backend.py
```

The backend starts at:
- **API Server:** `http://127.0.0.1:8000`
- **Interactive Swagger Documentation:** `http://127.0.0.1:8000/docs`

---

## 3. Running the Frontend Dashboard (React + Vite)

1. Open a second PowerShell window in your project folder.
2. Change directory into `frontend`:

```powershell
cd frontend
npm run dev
```

3. Open your browser and navigate to:
```
http://localhost:5173
```

---

## 4. Running the Automated Test Suite

Guard AI includes 21 automated tests covering every agent, cryptographic encryption, tamper detection, and API endpoints.

To run the test suite:

```powershell
.venv\Scripts\pytest.exe backend\tests -v
```

All tests should pass with code 0!

---

## 5. Exploring Features in the Dashboard

- **⚡ Multi-Agent Matrix**: Observe Controller AI, Finder AI, Defence AI, Offence AI, Informer AI, and the 6 specialized neural detectors.
- **🎯 Threat Scanner**: Test a URL (e.g. `http://paypal-security-update.xyz`), a file, or text for phishing and malware heuristics.
- **🔐 Cryptographic Vault**: Enter a master passphrase to encrypt and seal confidential credentials using AES-256-GCM.
- **🧪 Isolated Sandbox**: Enter any URL to safely view its rendered layout with scripts and active trackers blocked.
- **🚨 Emergency Response**: Test defensive containment activation with human operator approval gating.
- **⛓️ Blockchain Ledger**: Click **"Verify Cryptographic Integrity"** to validate the SHA-256 hash chain.
- **📱 Android Companion**: View device pairing telemetry and test the remote defensive lock command.
