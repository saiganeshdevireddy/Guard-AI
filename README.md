# Guard AI

Guard AI is a local cybersecurity prototype with a React dashboard, FastAPI service, SQLite event history, heuristic scanners, and an encrypted vault. Its agent modules coordinate in one backend process. It is not a complete antivirus product, and it does not currently provide native Windows or Android protection.

## What works in this prototype

- Rule-based URL, message, file-byte, and user-submitted Wi-Fi posture analysis.
- SQLite persistence for threat events, vault metadata, and the tamper-evident audit chain.
- Vault encryption using AES-256-GCM, PBKDF2-HMAC-SHA256, and separated HKDF keys.
- Local incident review, explicit operator confirmation, and reversible in-app incident mode.
- Static file byte preview and local URL review. Remote pages are not fetched or rendered.
- Genuine isolated browser preview is not implemented; URL review does not fetch or render remote pages.
- Informer summaries and browser speech synthesis when supported by the browser.
- A three-way Dark, Light, and System theme selector that remembers the user's choice.
- A clearly labelled Android demo workflow. Its telemetry and lock flag are in-memory examples only.

The scanners use heuristics. A low score does not prove that a URL, file, message, or network is safe. The audit chain can reveal changes within retained records; it is not immutable storage and cannot independently prove that its latest records were not deleted.

## Requirements

- Windows 10/11, Python 3.11+, and Node.js 18+.
- PowerShell for the commands below.
- No Android SDK is needed because there is no native Android application in this repository.

## Install and run

From the Guard AI repository root:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
```

Start the backend in one PowerShell window:

```powershell
.venv\Scripts\python.exe backend\run_backend.py
```

Start the frontend in a second window:

```powershell
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`. The API and interactive documentation are at `http://127.0.0.1:8000` and `http://127.0.0.1:8000/docs`.

To run the backend tests:

```powershell
Push-Location backend
..\.venv\Scripts\python.exe -m pytest tests -q
Pop-Location
```

The latest recorded full backend run passed 134 tests; see the [Milestone 5 acceptance framework](docs/MILESTONE_5_ACCEPTANCE_FRAMEWORK.md) for the command, date, scope, and limitations. This is a point-in-time application test result, not a production-security claim. Frontend tests were not run in that backend verification; run them with `npm test` from `frontend`.

## Configuration

`backend/app/config.py` uses these optional process environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `GUARD_AI_DATABASE_URL` | SQLite file under `backend/app/data` | Select a SQLAlchemy database URL. |
| `GUARD_AI_CORS_ORIGINS` | Local Vite and preview origins | Comma-separated frontend origins allowed by CORS. |
| `GUARD_AI_MAX_UPLOAD_BYTES` | 10 MiB | Maximum uploaded file size for static inspection. |

`.env.example` is a reference template. The application does not load `.env` files automatically; set variables in the process environment before starting the backend. Cloud inference is not configured or available. Do not add passwords, tokens, or production credentials to the repository.

## API areas

- `/api/health`: backend and database connection status.
- `/api/v1/agents`: in-process agent status and event bus history.
- `/api/v1/scan`: URL, file, text, and supplied network-data analysis.
- `/api/v1/vault`: encrypted item lifecycle and recovery envelope creation.
- `/api/v1/audit`: audit entries and chain verification.
- `/api/v1/emergency`: local incident mode, operator approval, and simulated containment.
- `/api/v1/sandbox`: local URL review and static file-byte preview.
- `/api/v1/android`: labelled demonstration telemetry and simulated lock state.

## Security and platform limits

- The backend binds to `127.0.0.1`; keep it local. Protected API routes use configured short-lived bearer tokens and role checks. Authentication fails closed until an administrator provisions a signing secret and active user; the API is not suitable for deployment on a public or shared network.
- CORS is restricted to the local development and preview origins by default.
- File scans inspect uploaded bytes only; they do not scan the whole disk or move the original file.
- URL checks are local heuristics. The prototype does not fetch remote pages, inspect live response headers, or provide a genuine isolated browser preview.
- The Windows process agent analyzes caller-supplied process metadata; it does not monitor Windows processes.
- Wi-Fi checks analyze values supplied by the user; they do not enumerate nearby networks.
- Emergency mode changes Guard AI's local state and audit history. OS, process, adapter, and network containment are simulations and require native integrations that are not included.
- Android information is marked demonstration data; no pairing, Android app, background service, or remote lock channel exists.
- Cloud AI and external threat-intelligence providers are not connected. Detection and explanation stay local.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/ISOLATED_BROWSER_ARCHITECTURE.md](docs/ISOLATED_BROWSER_ARCHITECTURE.md), [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md), and [docs/ROADMAP.md](docs/ROADMAP.md) for implementation details and limitations. Genuine isolated browser preview is a proposed, approval-gated feature and is not available in the current prototype.
