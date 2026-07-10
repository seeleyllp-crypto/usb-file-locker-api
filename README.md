# USB File Locker API

This repo contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, and security notes
- A public plan catalog for your USB locker pricing tiers
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`

## What it is not

- It does not unlock files remotely
- It does not expose USB secrets, PINs, vault contents, or private file access
- It does not move the Windows desktop security logic onto the public internet

## Railway setup

1. Push this repo to GitHub.
2. In Railway, connect the repo.
3. Leave the Railway `Root Directory` as `/`.
4. Deploy.

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
