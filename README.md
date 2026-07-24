# USB File Locker API

This repo contains a Railway-ready API service for the USB File Locker app.

## What it is

- A small public API for product info, features, companion apps, security notes, and all seven license ranks
- Support Redactor companion discovery and fixed privacy-safe audit actions without receiving customer text, files, paths, previews, counts, or detected values
- Download Verification Center discovery for hash, local receipt integrity sealing, standalone receipt inspection, bounded receipt-folder audits with a single local review window and scrollable small-screen review surface, bounded row and review-ID consumption, cancellable search debounce, keyboard review controls, a fixed active-view indicator without query text, stable empty and complete states, selection preservation with visible and pending queue positions, priority-level and session-state filtering, fixed four-level triage with privacy-safe fixed guidance and aggregate summary copy, temporary single-row, review-and-next, and bounded bulk-visible review or reopen marks, Ctrl+Enter review-and-next, Ctrl+Z undo, 100-action one-step bulk undo, aggregate completion progress with a determinate bar, an aggregate level breakdown, and visible pending and reviewed counts, failure-first navigation, forward and reverse pending navigation, file/ZIP structure review, prior receipt comparison, and fixed audit actions without receiving selected files, folders, names, search text, active-view state, queue positions, clipboard text, delayed-callback state, review IDs, action history, bulk mark state, session state, progress, selected positions, visible counts, selected rows, navigation, guidance state, summary contents, level filters, result filters, sorting, local results, receipts, receipt keys, paths, archive entry names, hashes, signature details, Defender output, inspection reports, folder-audit reports, or comparison output automatically
- API-backed licensing with signed keys, machine receipts, automatic client heartbeats, device deactivation, and owner revocation
- Encrypted customer accounts at `/account` with one-way `scrypt` password hashes, twelve-hour signed sessions, password changes, and assigned rank/license access
- An owner-only account console at `/owner/accounts` for account inventory, enable/disable, new-rank issuance, existing-license assignment, and explicit transfer
- Persistent anonymous device-seat enforcement using each license's `max_devices` value
- Per-license anonymous device inventory with throttled last-heartbeat/app-version details and one-device removal without resetting every seat
- An owner-only keys and private notes website at `/owner` with 30-second automatic refresh
- A separate 50-point Owner Command Center at `/owner/insights` with live filters and privacy-safe JSON/CSV exports
- An owner-only Maintenance Operations cockpit at `/owner/operations` with exactly forty aggregate checks, six non-overlapping approval gates, five decision-queue review lanes, a current-tab review session, eight scored domains, a daily briefing, severity summary, ten-metric change watch, prioritized runbook, four fixed review windows, eight owner shortcuts, release and storage matrices, customer-surface status, print, and privacy-safe handoff/text/JSON/CSV/SHA-256 exports
- A unified Customer Workspace at `/workspace` with an operational score, composite account overview, prioritized action plan, 30-day success plan, benefit map, unlocked rank tools, safe support and recovery exports, timeline, upgrades, and session-only progress
- A public Customer Answers workspace at `/QNA` with thirty fixed answers across six categories, search, current-tab saved answers, copy, print, fixed guide links, and privacy-safe local export
- A public Recovery Decision Wizard at `/decision` with ten fixed situations, thirty yes-or-no decision points, forty reviewed outcomes, current-tab history, back/restart controls, and privacy-safe action-plan export
- An aggregate Customer Experience Console at `/owner/customers` for experience scoring, customer-journey stages, renewal buckets, rank coverage, service, release adoption, support, public surfaces, shop readiness, and storage health
- A public Security Maintenance workspace at `/maintenance` with eight fixed categories, thirty-two fixed tasks, six routines, four cadence horizons, priority review, coverage bars, calendar reminders, print, and privacy-safe local export
- A public Storage & Retention workspace at `/retention` with eight fixed areas, five policy bands, ten fixed practices, a five-step cleanup boundary, current-tab-only review, print, and privacy-safe local export
- A public Data Control workspace at `/data-control` with fourteen fixed data classes, five scopes, six data-flow stages, retention guidance, current-tab-only review progress, print, and privacy-safe local export
- A public Recovery Kit workspace at `/recovery-kit` with five fixed profiles, ten preparation sections, fifty fixed items, five emergency runbooks, current-tab-only progress, calendar reminders, print, and privacy-safe local export
- A public Backup Verification workspace at `/backup-verification` with twelve fixed plans, sixty restore-order steps, nine categories, five restore-time objectives, one-to-five copy targets, current-tab-only progress, and privacy-safe local export
- A public Recovery Drill Center at `/recovery-drills` with sixteen fixed drills, eighty unique steps, five categories, current-tab-only progress, random selection, fixed-step copy, print, and privacy-safe local export
- A public Incident Response Center at `/incident-response` with twelve fixed playbooks, seventy-two concrete steps, current-tab-only progress, copy-next-step and print controls, and privacy-safe local export
- A public Diagnostics Center at `/diagnostics` with eight fixed problem categories, forty concrete steps, session-only checklist progress, and privacy-safe local export
- A public Trust Center at `/trust` with a privacy-safe 100-point score for service configuration, signed releases, persistent storage, recovery boundaries, and security limitations
- An owner-only Trust Operations console at `/owner/trust` with a 100-point operational score, aggregate security gates, concrete owner actions, and safe JSON export
- An encrypted customer Bug Inbox with owner status actions, private notes, replies, and deletion
- Rank-targeted, scheduled, read-only Owner Announcements with desktop delivery
- Public informational service status with automatic licensed-desktop notices
- A tamper-evident, hash-chained owner activity ledger with scoped JSON downloads
- Anonymous client release-adoption counts and coarse 24-hour sync freshness
- A public customer status page at `/status` with service and signed-release details
- Owner-issued time-limited promotional giveaway licenses
- Draft Terms of Use and Privacy Notice pages with explicit adult/legal review warnings
- Temporary customer LIMITED status for licensed premium controls plus existing whole-license BLOCK/revoke controls
- Customer Hub entitlement included in Starter and therefore every cumulative rank
- Privacy-safe audit report upload with signed, expiring downloads
- Server-calculated breach summaries plus direct admin log downloads on the owner website
- A public seven-rank shop at `/shop` using allowlisted provider-hosted checkout links
- An anonymous Plan Advisor and two-to-three-rank comparison workflow in the shop
- A read-only Customer License Center at `/customer` that checks signed-license status without activating a device seat
- A privacy-safe customer license timeline with local JSON, clipboard, and calendar-reminder exports
- A public Update Center at `/update` with version compatibility decisions, signed release notes, and local ZIP verification
- A Recovery Readiness app at `/readiness` with seven fixed safety checks, hard blockers, scoring, and local action-plan exports
- A homepage at `/`
- A route index at `/docs`
- A health endpoint at `/health`
- Ordered rank JSON at `/api/v1/ranks`
- Signed Windows update manifest and package delivery
- Server-side Ed25519, SHA-256, package-size, and app-data-preservation release verification

## What it is not

- It does not unlock files remotely
- It does not expose USB secrets, PINs, vault contents, or private file access
- It does not move the Windows desktop security logic onto the public internet
- It does not store PC names or raw machine identifiers in the device-seat ledger
- It does not accept raw files, file contents, full paths, USB secrets, passwords, or PINs in audit exports
- It never stores readable account passwords and never returns password hashes to customers or the owner console
- Public diagnostics accepts no free text or files and cannot inspect, scan, install, remove, execute, lock, or unlock anything on a customer PC
- Public Security Maintenance accepts no progress, schedule score, snapshot, local result, completion history, reminder, maintenance command, identity, free text, file, or path; it cannot inspect, scan, update, schedule, launch, complete, or control anything on a customer PC
- Public Data Control accepts no inventory, free text, contacts, customer progress, files, paths, local results, license proof, keys, PINs, filenames, or file contents; it stores no review state in browser storage
- Public Storage & Retention accepts no inventory, progress, cleanup command, local result, free text, file, or path; it cannot inspect or delete anything on a customer PC and stores no review state in browser storage
- Public recovery kits accept no free text, files, paths, filenames, keys, PINs, customer records, local results, or progress uploads; suspected-malware guidance is defensive and tabletop only
- Public backup verification accepts no free text, files, paths, filenames, keys, PINs, file contents, customer records, or progress uploads; ransomware guidance is tabletop only and never runs malware or destructive simulations
- Public recovery drills accept no free text or files, collect no customer progress, and never run malware, suspicious code, destructive scripts, or file-encryption simulations
- Bug reports never attach local files or logs automatically, and raw machine ids are not stored
- Announcements cannot run commands, access customer files, or change customer settings
- Service status is informational and cannot remotely control or disable customer PCs
- API activity records exclude keys, tokens, notes, messages, customer labels, file data, and full paths
- Client health never exposes PC names or raw machine ids; it reports only anonymous counts, app versions, and coarse freshness
- Giveaway tooling does not select winners, collect entries, process payments, or provide contest-law compliance
- LIMITED status never remotely locks a PC, deletes files, runs commands, or disables unlock/recovery access
- Draft legal pages are not legal advice and require adult business-owner approval before commercial use
- It does not collect card numbers, store payment secrets, or treat a checkout receipt as a license key
- Owner Maintenance Operations cannot control customer PCs and returns no customer maintenance history, license proof, identity, device identifiers, files, paths, PINs, or USB secrets

## Account Workspace 0.65

`GET /account` provides registration, sign-in, live username availability, password-strength feedback, assigned-rank access, automatic twenty-second refresh, session-expiry status, a privacy-safe account-summary download, password-verified username changes, sign-out, sign-out-all, and password change. The page displays only the masked license key. The browser stores only a signed session token in `sessionStorage`; passwords are never persisted by the page. Remembering the username is an explicit browser-local choice. Usernames are encrypted in server storage, account filenames contain no username, and each password uses a unique salt with `scrypt`.

`GET /owner/accounts` lists accounts without password hashes or full license keys. The owner admin token stays in `sessionStorage` and is sent only through `X-License-Admin-Token`. The owner can issue one of the seven ranks, assign an existing license, explicitly transfer a license from another account, or disable an account and invalidate its sessions.

Account sessions last twelve hours and include a server-checked session version. Password changes, account disabling, license transfer away from an account, and the authenticated sign-out-all action invalidate prior sessions. Registration and failed sign-in attempts are bounded in memory per connection. This account layer does not replace signed license verification or device-seat enforcement.

Every new customer license requires an existing active `account_id`. The issue endpoint, main owner console, giveaway controls, and dedicated account console bind each new license to that account. Arbitrary labels and email fields can no longer create unattached licenses. Existing legacy licenses can still be deliberately assigned or transferred from `/owner/accounts`.

## Owner Maintenance Operations 0.39

`GET /owner/operations` opens the responsive owner cockpit. The admin token stays only in current page memory and is sent only in `X-License-Admin-Token`.

`GET /api/v1/admin/maintenance-operations` returns exactly forty fixed checks across eight categories of five. Schema three divides those checks exactly once across six approval gates and derives a decision queue from failed checks only. Five review lanes provide all-action, urgent, release-and-service, customer-and-support, and evidence-and-governance views. Every queued item includes fixed priority, suggested review timing, action, and owner-surface navigation.

The browser review session can focus the next action, mark one lane reviewed, clear the session, and export a fixed-field handoff. Review marks, lane selection, comparison baseline, planner, search, and filters stay only in the current tab. A reviewed mark does not resolve an action or prove remediation. The schema-two SHA-256 receipt can include fixed gate results and reviewed action IDs, but never the owner token. The response and local exports contain aggregate fixed results only. They exclude license keys, license ids, customer labels, email, owner notes, receipts, machine identifiers, report contents, files, paths, PINs, USB secrets, and customer maintenance history. The score is operational guidance, not certification, legal advice, antivirus proof, or a guarantee.

## Security Maintenance 0.36

`GET /api/v1/maintenance-guide` now also returns four fixed cadence horizons and the public reminder-coverage weight definition. `GET /maintenance` adds priority ordering, a five-item priority review action, category and routine coverage bars, and a sixteen-field privacy-safe receipt. Every calculation remains in the current tab and disappears on reload.

The separate Windows center adds fixed attention, 7-day, 30-day, and 90-day planning windows, a priority queue, coarse hash-chained snapshots, comparison, and a verified non-destructive archive export. Schedule scores measure reminder coverage only. They are not antivirus, backup, key, recovery, compliance, or security-health results. The API accepts no progress, schedule score, snapshot, history, reminder, local result, file, path, or maintenance command.

## Security Maintenance 0.35

`GET /api/v1/maintenance-guide` returns exactly eight fixed categories, thirty-two fixed tasks, six fixed routines, and five allowed cadence values. It is a public catalog endpoint, not a PC-control or progress endpoint. It receives no request body and returns no customer, license, device, maintenance-history, audit-export, support, or owner record.

`GET /maintenance` renders the catalog as a responsive customer workspace. Review state lives only in the current page's JavaScript memory and disappears on reload. Copy, print, calendar, and JSON export happen locally in the browser. The downloaded receipt has exactly twelve fixed fields and contains only public service metadata plus reviewed fixed task IDs.

The separate Windows Security Maintenance Center stores append-only complete or reopen events in an exact ten-field SHA-256 hash chain capped at 500 records and 2 MiB. It records no names, contacts, keys, PINs, paths, filenames, file contents, scan results, customer records, screenshots, process lists, or free-form notes. Completion is a reminder record, not proof that Defender, Windows, a key, a backup, an update, or recovery is healthy.

## Storage & Retention 0.34

`GET /api/v1/retention-guide` returns exactly eight fixed storage areas, five policy bands, ten fixed practices, and five cleanup-boundary steps. It is a public catalog endpoint, not a cleanup endpoint. It receives no request body and returns no customer, license, device, storage inventory, cleanup result, audit-export, support, or owner record.

`GET /retention` renders the catalog as a responsive customer workspace. Review state lives only in the current page's JavaScript memory and disappears on reload. Copy, print, and JSON export happen locally in the browser. The downloaded receipt has exactly eleven fixed fields and contains only public service metadata plus reviewed fixed practice IDs.

The separate Windows Storage & Retention Center can inspect stat metadata only inside the exact `%LOCALAPPDATA%\USBFileLocker\temp` workspace. It previews at most 5,000 entries, rejects links and junctions, requires a visible warning plus exact `CLEAN TEMP` text, and revalidates age and scope before ordinary deletion. It never targets keys, vault data, audit evidence, histories, settings, licenses, owner data, update rollback, `.locked` files, backups, Downloads, Documents, USB drives, or arbitrary folders. This is not secure erasure.

## Data Control 0.33

`GET /api/v1/data-map` returns exactly five fixed scopes, fourteen fixed data classes, and six fixed data-flow stages. It is a public catalog endpoint, not a submission endpoint. It receives no request body and returns no customer, license, device, support, audit-export, or owner record.

`GET /data-control` renders the catalog as a responsive customer workspace. Review state lives only in the current page's JavaScript memory and disappears on reload. Copy, print, and JSON export happen in the browser. The downloaded receipt has eleven fixed fields and contains only public service metadata plus reviewed fixed class IDs.

The separate Windows Local Data Control Center may read coarse presence, count, size, and age bands from exact known VaultLink app-data sources. It never sends those local results to this API and never searches Downloads, Documents, removable drives, locked-container locations, arbitrary backup folders, browser history, or process lists.

## Railway setup

1. Push this repo to GitHub.
2. In Railway, connect the repo.
3. Leave the Railway `Root Directory` as `/`.
4. Deploy.

Recommended Railway environment variables:

- `LICENSE_SIGNING_SECRET` = a long random secret used to sign license keys and receipts
- `LICENSE_ADMIN_TOKEN` = a long random admin token used for owner-only license and audit routes
- `LICENSE_STATE_DIR` = persistent folder for revocations, device deactivations, encrypted keys, private owner notes, and support tickets
- `LICENSE_RECORDS_SECRET` = a separate long secret used to derive separate encryption keys for saved license data and support-ticket text; retain it across deployments
- `AUDIT_EXPORT_DIR` = optional persistent folder for audit exports; mount a Railway Volume and point this variable at it
- `AUDIT_EXPORT_RETENTION_HOURS` = optional lifetime for stored exports, from 1 to 2160 hours; default 168
- `SHOP_CHECKOUT_STARTER_URL`, `SHOP_CHECKOUT_HOME_URL`, `SHOP_CHECKOUT_PERSONAL_PLUS_URL`, `SHOP_CHECKOUT_FAMILY_SAFETY_URL`, `SHOP_CHECKOUT_SMALL_OFFICE_URL`, `SHOP_CHECKOUT_FAMILY_OFFICE_URL`, and `SHOP_CHECKOUT_PRO_BASELINE_URL` = optional provider-hosted HTTPS links for each tier
- `SHOP_CHECKOUT_ALLOWED_HOSTS` = optional comma-separated host allowlist; defaults to `buy.stripe.com,checkout.stripe.com`

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
- `http://127.0.0.1:8000/shop`
- `http://127.0.0.1:8000/customer`
- `http://127.0.0.1:8000/workspace`
- `http://127.0.0.1:8000/recovery-kit`
- `http://127.0.0.1:8000/backup-verification`
- `http://127.0.0.1:8000/recovery-drills`
- `http://127.0.0.1:8000/incident-response`
- `http://127.0.0.1:8000/diagnostics`
- `http://127.0.0.1:8000/update`
- `http://127.0.0.1:8000/readiness`
- `http://127.0.0.1:8000/trust`
- `http://127.0.0.1:8000/owner`
- `http://127.0.0.1:8000/owner/insights`
- `http://127.0.0.1:8000/owner/customers`
- `http://127.0.0.1:8000/owner/trust`
- `http://127.0.0.1:8000/owner/operations`

## Trust Center

- `GET /trust` opens the public scored Trust Center without requiring a license or returning customer records.
- `GET /api/v1/trust-center` returns exactly ten weighted checks totaling 100 points, signed-release status, storage and cryptography descriptions, data boundaries, recovery steps, and honest limitations.
- `GET /owner/trust` opens Trust Operations. The admin token stays in page memory and is sent only in the `X-License-Admin-Token` header.
- `GET /api/v1/admin/trust-center` returns exactly fourteen weighted operational checks totaling 100 points plus aggregate actions and category summaries.
- Trust responses never return license keys, customer labels, receipts, private notes, machine identity, paths, PINs, USB secrets, filenames, or file contents.
- These scores are operational readiness indicators, not certification, legal advice, guaranteed protection, or a replacement for independent security review.

## Diagnostics Center

- `GET /diagnostics` opens the public guided troubleshooting app.
- `GET /api/v1/diagnostics-guide` returns eight fixed categories and exactly forty steps for app startup, USB keys, unlock failures, licensing, signed updates, performance, audit warnings, and backup preparation.
- Checklist completion stays in the current browser tab. The page uses neither `localStorage` nor `sessionStorage`, and it uploads no progress.
- The safe browser export contains only public API/service/release metadata, the selected category id, and completed fixed step ids.
- The desktop companion performs eighteen local read-only checks and creates a separately reviewed privacy-safe report. The public API never receives that report automatically.
- Diagnostics does not accept free text, files, license proof, machine identity, PINs, USB secrets, paths, filenames, vault data, or file contents.

## Recovery Kit

- `GET /recovery-kit` opens the public fixed-profile preparation workspace.
- `GET /api/v1/recovery-kit` returns five profiles, ten sections, exactly fifty preparation items across eight categories, five emergency runbooks with exactly thirty ordered steps, and five fixed review intervals.
- Browser completion stays only in the current tab. The page uses no browser storage, uploads no progress, and accepts no free-form text, files, paths, or local results.
- Customers can select a profile and section, mark the next item or a whole section, choose a section with cryptographic randomness, copy a fixed runbook or privacy-safe summary, print, export safe JSON, and create an `.ics` review reminder.
- The desktop companion adds ten coarse local checks totaling 100 points plus exact-schema tamper-evident snapshots that compare fixed completed IDs and readiness scores.
- Browser and desktop output exclude names, contacts, license proof, receipts, keys, PINs, paths, filenames, file contents, screenshots, process lists, private diagnostics, and free-form notes.
- Suspected-malware guidance is defensive and tabletop only. VaultLink does not run malware, suspicious code, destructive scripts, or file-encryption simulations.

## Backup Verification Center

- `GET /backup-verification` opens the public fixed-plan backup and restore workspace.
- `GET /api/v1/backup-verification` returns twelve plans and exactly sixty fixed restore-order steps across nine backup and continuity categories, plus five fixed restore-time objectives and one-to-five copy targets.
- Browser checklist progress stays only in the current tab. The page uses no browser storage, uploads no progress, and accepts no free-form text, files, or paths.
- Customers can filter plans, mark the next or every step, choose a plan with cryptographic randomness, copy a fixed restore order or privacy-safe summary, print, and export reviewed safe JSON.
- The desktop companion adds twelve coarse local checks totaling 100 points, local 7, 14, 30, 60, or 90-day review schedules, recognized app-data backup creation and verification, and tamper-evident hash-chained checkpoints that compare score changes and fixed check IDs.
- Browser and desktop reports exclude backup paths, filenames, keys, PINs, file contents, customer or machine identity, license proof, receipts, screenshots, process lists, private diagnostic details, and free-form notes.
- Ransomware guidance is tabletop only. VaultLink never runs malware, suspicious code, destructive scripts, or file-encryption simulations for backup testing.

## Recovery Drill Center

- `GET /recovery-drills` opens the public fixed-drill practice workspace.
- `GET /api/v1/recovery-drills` returns sixteen drills and exactly eighty unique steps across backup, continuity, evidence, recovery, and security.
- Checklist completion stays only in the current browser tab. The page uses no browser storage, uploads no progress, and accepts no free-form text or files.
- Customers can filter drills, mark the next or every step, select a drill with cryptographic randomness, copy the next fixed step, print, and export reviewed privacy-safe JSON.
- The desktop companion adds ten coarse local checks totaling 100 points, five local review intervals, a next-due date, and hash-chained complete or partial result history.
- Browser and desktop reports exclude license proof, customer or machine identity, receipts, passwords, PINs, USB secrets, paths, filenames, screenshots, process lists, private file contents, local diagnostic details, and free-form notes.
- Ransomware exercises are tabletop guidance only. VaultLink never runs malware, suspicious code, destructive scripts, or file-encryption simulations for training.

## Incident Response Center

- `GET /incident-response` opens the public fixed-playbook response workspace.
- `GET /api/v1/incident-guide` returns twelve playbooks and exactly seventy-two steps for Defender alerts, possible account theft, a lost master USB, unlock failures, unknown PC behavior, update integrity problems, device loss, phishing, ransomware warnings, exposed secrets, browser changes, and backup failures.
- Checklist completion stays only in the current browser tab. The page uses neither `localStorage` nor `sessionStorage`, uploads no progress, and accepts no free-form incident text or files.
- The safe browser export contains only public API/service/release metadata, the selected fixed playbook id, and completed fixed step ids.
- The desktop companion adds eight coarse local readiness checks totaling 100 points and trusted shortcuts to Windows Security and existing VaultLink tools. It never quarantines, deletes, uploads, scans, or remotely controls a PC.
- Incident output excludes license proof, customer or machine identity, passwords, PINs, USB secrets, paths, filenames, screenshots, process lists, private file contents, and customer records.

## Shop

- `GET /shop` shows all seven ranks and their cumulative features.
- `GET /api/v1/shop` returns the same catalog plus checkout readiness.
- `POST /api/v1/shop/recommend` recommends the lowest matching rank from audience, priority, and optional budget inputs without accepting identity or payment data.
- `POST /api/v1/shop/compare` compares two or three ranks and returns a cumulative entitlement matrix.
- A tier has a buy button only when its environment variable contains a valid HTTPS URL on the checkout-host allowlist. Missing, insecure, spoofed, credential-bearing, or malformed URLs leave that tier marked `NOT ON SALE YET`.
- Payment happens entirely on the checkout provider's page. VaultLink does not receive or store card numbers.
- License delivery is manual and account-first: the customer creates an account, then after independently confirming payment in the provider dashboard, the owner assigns the matching license to that account from `/owner` or `/owner/accounts`.

Use an adult-owned merchant account and follow the payment provider's age, identity, tax, refund, and business requirements. This release does not include webhook-based payment verification or automatic license fulfillment.

## Customer License Center

- `GET /customer` opens the read-only browser app.
- `POST /api/v1/licenses/preview` validates a signed license and reports its rank, expiration, limited/revoked state, anonymous seat totals, public service status, published release, and status-specific next actions.
- `POST /api/v1/licenses/upgrade-options` returns higher ranks, added entitlements, and validated hosted-checkout availability without returning the key or private license fields.
- `POST /api/v1/licenses/rank-tools` returns five concrete checklist tools per unlocked rank, for 35 cumulative rank-exclusive tools across all seven ranks, with categories and time estimates.
- `POST /api/v1/licenses/customer-checkup` returns six privacy-safe attention checks for license state, anonymous seats, service status, expiration, signed updates, and rank-tool access.
- `POST /api/v1/licenses/support-guide` returns a five-step guide for one fixed category: licensing, update, recovery, security, privacy, or other. It accepts no free-form report text and returns no private license fields.
- `POST /api/v1/licenses/timeline` returns issue, update, limit, expiration, and current-check milestones plus local renewal-reminder metadata without activating a device seat.
- The browser dashboard can copy or export a privacy-safe customer summary and link to the published SHA-256-pinned Windows update package.
- The Signed Update Verifier compares a selected update ZIP with the published package size and SHA-256 entirely inside the browser. The selected file and its contents are never uploaded.
- The License Timeline can be copied or exported as privacy-safe JSON. Expiring licenses can download a local `.ics` calendar event with a 30-day reminder; VaultLink never connects to or modifies a calendar account.
- Active customers can search and filter tools, track checklist progress in page memory, copy their current-rank tools, or export every unlocked checklist and session result as a privacy-safe rank pack. Limited, revoked, and expired licenses keep local unlock and recovery but do not receive premium rank-tool contents.
- The session workspace adds current-rank, incomplete, and favorites filters; next-incomplete focus; and local JSON rank-pack import. Favorites and progress are not uploaded or saved in browser storage.
- Customer Checkup is informational only. It is not an antivirus scan, security certification, compliance determination, or permission to remotely inspect or modify a customer PC.
- Preview never activates a device, consumes a seat, saves the key in browser storage, or returns customer labels, email addresses, private notes, machine identifiers, receipts, paths, PINs, USB secrets, or file contents.

## Customer Workspace

- `GET /workspace` opens the unified customer app.
- `POST /api/v1/licenses/customer-workspace` returns the account summary, six-point checkup, six-factor workspace score, nine-item action center, next-best action, four readiness lanes, five-stage continuity journey, anonymous seat planner, five-check support readiness, seven-day care routine, 30-day success plan, four-phase 90-day plan, categorized benefit map, six help paths, ten-term glossary, privacy guarantees, change digest, timeline, cumulative rank tools, upgrade choices, safe support pack, offline recovery card, and customer routes in one response.
- Checklist progress stays only in the current browser tab and is never uploaded or saved in browser storage.
- Customers can filter actions, search unlocked tools, and export the full safe workspace, a support pack, or an offline recovery card without exporting the license key or customer identity.
- Safe exports exclude the license key, license id, customer identity, owner notes, machine identity, receipts, payment data, paths, PINs, USB secrets, and file contents.
- `GET /owner/customers` and `GET /api/v1/admin/customer-experience` provide the owner a read-only aggregate console with an experience score, journey stages, renewal health, rank percentages, surface readiness, and JSON/CSV exports. The API requires the admin header and never returns customer-level identity or license proof.

## License endpoints

- `POST /api/v1/licenses/issue`
  - Admin-only. Requires `LICENSE_ADMIN_TOKEN` in the `X-License-Admin-Token` header.
  - Requires an existing active `account_id` and binds the new signed license to that account.
  - The admin token is never accepted inside the JSON body.
- `POST /api/v1/licenses/activate`
  - Exchanges a valid license key for a machine-bound receipt.
- `POST /api/v1/licenses/verify`
  - Verifies a license key and activation receipt for a specific machine.
- `POST /api/v1/licenses/sync`
  - Automatic client heartbeat. Returns the current revocation decision, API version, decision ID, bounded next-check timing, device-seat usage, and signed desktop release status.
- `POST /api/v1/licenses/deactivate`
  - Deactivates one machine receipt so the customer can remove the saved license from that PC.
- `POST /api/v1/licenses/revoke`
  - Admin-only. Revokes the whole key so existing and future checks fail.
- `POST /api/v1/licenses/restore`
  - Admin-only. Restores a revoked key; individually deactivated receipts stay deactivated.
- `POST /api/v1/licenses/note`
  - Admin-only. Updates the private owner note without adding it to the signed customer key.
- `POST /api/v1/licenses/reset-devices`
  - Admin-only. Releases every active seat for one license and requires those PCs to activate again.
- `POST /api/v1/licenses/remove-device`
  - Admin-only. Removes one anonymous device seat. Its receipt fails at the next automatic client sync while other devices keep working.
- `GET /api/v1/admin/licenses`
  - Admin-only inventory for the owner website. Includes anonymous active-device counts; stored keys and notes are encrypted at rest.
- `GET /api/v1/admin/licenses/{license_id}/devices`
  - Admin-only anonymous seat inventory. Returns only a one-way machine hash, status, dates, last successful heartbeat, and app version, never a PC name or raw hardware identity. Last-seen writes are throttled to protect the storage volume.
- `GET /api/v1/admin/dashboard`
  - Admin-only license, device-capacity, audit-export, breach-level, shop-readiness, storage, and release totals.
- `GET /api/v1/admin/updates/windows/status`
  - Admin-only read-only test of the currently published Windows manifest signature, package size, SHA-256 hash, and app-data-preservation declaration.
- `GET /api/v1/admin/insights`
  - Admin-only report with exactly 50 aggregate licensing, device, renewal, rank, release, support, messaging, security, and operations insights.
  - Excludes keys, customer labels, email addresses, private notes, machine identifiers, paths, PINs, USB secrets, and file contents.

Open `/owner` to view the API dashboard, issue keys, publish Owner Announcements, enforce device limits, inspect and remove one anonymous device, reset all lost-device seats, copy keys, save private notes, revoke licenses, manage the Bug Inbox, and download privacy-safe audit logs. Open `/owner/insights` for the searchable 50-point report, filtered copy summary, and JSON/CSV exports. Once connected, the main owner page refreshes owner data every 30 seconds unless an input is being edited. The admin token stays in page memory, is sent only in the `X-License-Admin-Token` header, and is not placed in a URL or export.

Without `LICENSE_STATE_DIR`, Railway uses local ephemeral storage and a restart can forget revocations, owner records, and bug reports. Mount a Railway Volume and use paths such as `/data/license_state` and `/data/audit_exports`. Keep `LICENSE_RECORDS_SECRET` stable; changing or losing it makes previously encrypted keys, private notes, and support-ticket text unreadable.

## Support ticket endpoints

- `POST /api/v1/support-tickets`
  - Requires an active machine-bound license. Accepts only the category, subject, description, optional reproduction steps, and app version that the customer explicitly submits.
  - Ticket text is encrypted at rest. No files, logs, PINs, passwords, USB secrets, client names, full paths, PC names, or raw machine ids are attached automatically.
- `POST /api/v1/support-tickets/mine`
  - Returns status and owner replies only for tickets from the same licensed anonymous device.
- `GET /api/v1/admin/support-tickets`
  - Admin-only Bug Inbox listing.
- `POST /api/v1/admin/support-tickets/action`
  - Admin-only status, customer reply, and private owner-note update.
- `POST /api/v1/admin/support-tickets/delete`
  - Admin-only permanent ticket deletion.

The API limits each anonymous licensed device to 10 new support tickets per 24 hours.

## Owner announcement endpoints

- `POST /api/v1/announcements/mine`
  - Requires an active machine-bound license and returns only currently active read-only messages allowed for that rank.
- `GET /api/v1/admin/announcements`
  - Admin-only inventory including active, scheduled, and expired messages.
- `POST /api/v1/admin/announcements/create`
  - Admin-only publishing with severity, minimum rank, optional start time, and optional expiration.
- `POST /api/v1/admin/announcements/delete`
  - Admin-only permanent announcement deletion.

Announcements contain only owner-authored text. They cannot execute code, open files, collect device data, or change app settings. Use `/owner` to publish and remove them without command-line tools.

## Audit export endpoints

- `POST /api/v1/audit-exports`
  - Requires an active machine-bound license with Audit Log Viewer access.
  - Accepts the app's privacy-safe report and strips every field outside the approved schema.
  - Returns a signed, expiring download path.
- `GET /api/v1/audit-exports/{export_id}/download`
  - Downloads the JSON report while the returned bearer token is valid.
  - Send the token in the `Authorization: Bearer ...` header so it is not exposed in the URL.
- `GET /api/v1/admin/audit-exports`
  - Admin-only list of stored report metadata, anonymous machine hashes, and breach levels.
  - Requires `LICENSE_ADMIN_TOKEN` in the `X-License-Admin-Token` header.
- `GET /api/v1/admin/audit-exports/{export_id}/download`
  - Admin-only download of a selected stored privacy-safe report.
  - The admin token is never accepted in the URL.
- `POST /api/v1/admin/audit-exports/download-link`
  - Admin-only exchange for a two-minute, report-scoped browser download link. The temporary signed token is not an admin token and cannot access other owner routes.

To download logs without commands, open `/owner`, connect with the admin token, scroll to **Audit Logs**, and click **DOWNLOAD JSON** beside a report.

Without `AUDIT_EXPORT_DIR`, Railway stores exports on the service's local ephemeral filesystem. Upload, owner listing, and download work, but a restart can remove pending exports. For restart-safe retention, mount a Railway Volume and set `AUDIT_EXPORT_DIR` to that mount, such as `/data/audit_exports`.

## Update endpoints

- `GET /api/v1/updates/windows`
  - Returns the current Ed25519-signed Windows release manifest, compatibility floor, notes, size, and SHA-256 hash.
- `GET /api/v1/updates/windows/download`
  - Returns the exact ZIP package named by the signed manifest.
- `POST /api/v1/updates/windows/check`
  - Accepts only a dot-separated numeric `installed_version` and returns `required`, `available`, `current`, `ahead`, or `unavailable` with verified release metadata.
  - The entered version is not stored. Update Center hashes selected ZIP files locally in the browser and never uploads them.

API `0.24.0` verifies the Ed25519 signature itself before serving release metadata or a package, then verifies package size and SHA-256. The owner console's `Signed Release Test` calls the authenticated read-only status endpoint. It cannot upload or publish a release.

The desktop app embeds the same release public key and will not trust a replacement key from the API. It independently verifies the manifest signature and package hash before staging an update, asks the user before installation, backs up replaced app files, and leaves LocalAppData untouched. The private release-signing key is DPAPI-protected outside both GitHub repositories. Publishing remains a local owner action through pinned GitHub repositories; the public API has no release-upload or publish endpoint.

## Recovery Readiness

- `GET /readiness` opens the anonymous recovery-preparation self-check.
- `POST /api/v1/readiness/check` accepts exactly seven true-or-false readiness fields and returns a score, blocker status, and prioritized action plan.
- Missing backups, an untested master USB, or no disposable-file lock/unlock round trip are hard blockers for important data.
- The service stores nothing from the check. It cannot inspect the PC, verify backups, test keys, run antivirus, certify security, or guarantee recovery.
