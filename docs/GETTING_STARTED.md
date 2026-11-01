# Run Guard AI on Windows

## Install dependencies

Open PowerShell in the repository root:

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt
```

In another PowerShell window, install frontend packages:

```powershell
cd frontend
npm ci
```

## Start the app

From the repository root, start the backend:

```powershell
.venv\Scripts\python.exe backend\run_backend.py
```

Start the frontend in the second window:

```powershell
npm run dev
```

Open `http://127.0.0.1:5173`. The API health response is at `http://127.0.0.1:8000/api/health`; interactive endpoint docs are at `http://127.0.0.1:8000/docs`.

## Run tests

From the repository root:

```powershell
Push-Location backend
..\.venv\Scripts\python.exe -m pytest tests -q
Pop-Location
```

## Configuration

See `.env.example` for the supported backend environment variable names. The app does not read `.env` files automatically. For example, set a custom CORS list in PowerShell before starting the backend:

```powershell
$env:GUARD_AI_CORS_ORIGINS = 'http://127.0.0.1:5173'
```

The default database is created beneath `backend/app/data`. Cloud inference, Windows OS monitoring, and a real Android companion are not enabled.

## Themes and device notes

Choose **Dark**, **Light**, or **System** in the top navigation. The selected preference is saved in local storage; System follows Windows/browser appearance settings. Both themes apply across dashboard panels.

The Android screen uses sample values labelled as a demonstration; its lock control changes only backend memory. The emergency response buttons change local Guard AI state or display simulations, not Windows or network state.
# API authentication (required for protected routes)

Guard AI has no default account. Protected API routes return `503` until an
authentication secret and at least one active Argon2id account are configured.
Generate a random signing secret out of band (at least 32 random bytes), then
provision an account interactively from the backend directory:

```powershell
python -m app.security.auth --provision-user
```

Store the generated JSON user entry in the secret environment variable
`GUARD_AI_AUTH_USERS`, and set `GUARD_AI_AUTH_TOKEN_SECRET` and
`GUARD_AI_AUTH_TOKEN_TTL_SECONDS` (60–3600 seconds). Do not put real values in
`.env.example`, source control, frontend `VITE_*` variables, or build output.
The token endpoint is `POST /api/auth/token`; send its short-lived bearer token
in the `Authorization` header. `POST /api/auth/revoke` revokes that token
persistently. Roles (`admin`, `operator`, `analyst`, `viewer`) are enforced on
the server. Deactivate a user by setting its configured `active` field to
`false`.

The frontend now provides sign-in and sign-out, holds the short-lived bearer
token in memory only, and clears local authentication on token expiry or an
API `401`. An API `403` is shown as a permission denial while keeping the
session active. Reloading the page requires a new sign-in. The current backend
does not support HttpOnly cookie sessions or CSRF tokens, so the frontend does
not pretend to use them; see the authentication boundary in
`docs/ARCHITECTURE.md` for the tradeoff and required backend work.
