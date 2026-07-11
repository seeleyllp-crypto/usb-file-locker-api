# USB File Locker API

This repo contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, security notes, and all seven license ranks
- API-backed licensing with signed license keys and machine-bound activation receipts
- Privacy-safe audit report upload with signed, expiring downloads
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`
- Ordered rank JSON at `/api/v1/ranks`

## What it is not

- It does not unlock files remotely
- It does not expose USB secrets, PINs, vault contents, or private file access
- It does not move the Windows desktop security logic onto the public internet
- It does not yet do strict seat counting or revocation history because that needs a real database
- It does not accept raw files, file contents, full paths, USB secrets, passwords, or PINs in audit exports

## Railway setup

1. Push this repo to GitHub.
2. In Railway, connect the repo.
3. Leave the Railway `Root Directory` as `/`.
4. Deploy.

Recommended Railway environment variables:

- `LICENSE_SIGNING_SECRET` = a long random secret used to sign license keys and receipts
- `LICENSE_ADMIN_TOKEN` = a long random admin token used only for `/api/v1/licenses/issue`
- `AUDIT_EXPORT_DIR` = optional persistent folder for audit exports; mount a Railway Volume and point this variable at it
- `AUDIT_EXPORT_RETENTION_HOURS` = optional lifetime for downloadable exports, from 1 to 168 hours; default 24

Railway will start the service with:

`python main.py`

The seven ranks run from `$5 Starter` through `$20,000+ Pro Baseline`. Legacy `plus`, `pro`, and `signature` issue requests map to matching current ranks so older issuer builds keep working. Rank descriptions do not claim HIPAA certification, legal approval, guaranteed protection, or completed professional review.

## Local run

```powershell
cd C:\path\to\USBFileLockerAPI-Repo
python main.py
```

Then open:

- `http://127.0.0.1:8000/`
- `http://127.0.0.1:8000/docs`

## License endpoints

- `POST /api/v1/licenses/issue`
  - Admin-only. Requires `LICENSE_ADMIN_TOKEN` in the `X-License-Admin-Token` header.
  - The admin token is never accepted inside the JSON body.
- `POST /api/v1/licenses/activate`
  - Exchanges a valid license key for a machine-bound receipt.
- `POST /api/v1/licenses/verify`
  - Verifies a license key and activation receipt for a specific machine.

## Audit export endpoints

- `POST /api/v1/audit-exports`
  - Requires an active machine-bound license with Audit Log Viewer access.
  - Accepts the app's privacy-safe report and strips every field outside the approved schema.
  - Returns a signed, expiring download path.
- `GET /api/v1/audit-exports/{export_id}/download`
  - Downloads the JSON report while the returned bearer token is valid.
  - Send the token in the `Authorization: Bearer ...` header so it is not exposed in the URL.

Without `AUDIT_EXPORT_DIR`, Railway stores exports on the service's local ephemeral filesystem. Immediate upload-and-download works, but a restart can remove pending exports. For restart-safe retention, mount a Railway Volume and set `AUDIT_EXPORT_DIR` to that mount, such as `/data/audit_exports`.
