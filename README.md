# USB File Locker API

This repo contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, security notes, and plan tiers
- API-backed licensing with signed license keys and machine-bound activation receipts
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`

## What it is not

- It does not unlock files remotely
- It does not expose USB secrets, PINs, vault contents, or private file access
- It does not move the Windows desktop security logic onto the public internet
- It does not yet do strict seat counting or revocation history because that needs a real database

## Railway setup

1. Push this repo to GitHub.
2. In Railway, connect the repo.
3. Leave the Railway `Root Directory` as `/`.
4. Deploy.

Recommended Railway environment variables:

- `LICENSE_SIGNING_SECRET` = a long random secret used to sign license keys and receipts
- `LICENSE_ADMIN_TOKEN` = a long random admin token used only for `/api/v1/licenses/issue`

Railway will start the service with:

`python main.py`

## Local run

```powershell
cd C:\Users\jonis\OneDrive\Desktop\USBFileLockerAPI-Repo
python main.py
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`

## License endpoints

- `POST /api/v1/licenses/issue`
  - Admin-only. Requires `LICENSE_ADMIN_TOKEN`.
- `POST /api/v1/licenses/activate`
  - Exchanges a valid license key for a machine-bound receipt.
- `POST /api/v1/licenses/verify`
  - Verifies a license key and activation receipt for a specific machine.
