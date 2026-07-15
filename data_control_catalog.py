import json


DATA_SCOPES = [
    {
        "id": "windows-user",
        "label": "Windows user profile",
        "summary": "Known VaultLink app-data containers under the current Windows user.",
    },
    {
        "id": "removable-media",
        "label": "Removable media",
        "summary": "Master-key files that remain on customer-controlled removable storage.",
    },
    {
        "id": "customer-selected",
        "label": "Customer-selected storage",
        "summary": "Locked containers and backup copies kept wherever the customer chooses.",
    },
    {
        "id": "explicit-api",
        "label": "API after explicit action",
        "summary": "Limited server records created only by a clear licensing, support, or audit action.",
    },
    {
        "id": "public-service",
        "label": "Public service metadata",
        "summary": "Public release, status, product, plan, and security information with no customer record.",
    },
]


DATA_CLASSES = [
    {
        "id": "settings-preferences",
        "label": "Settings and preferences",
        "scope_id": "windows-user",
        "purpose": "Remember local UI choices, update preferences, recent key locations, and app behavior.",
        "protection": "Windows user permissions. Treat the settings container as private because it can include local locations.",
        "retention": "Until the customer changes settings, resets the local app, or restores an app-data backup.",
        "customer_action": "Review from Local Data Control Center and protect app-data backups like private records.",
        "default_state": "Created during normal desktop use.",
        "desktop_inventory": "Coarse presence, object-count band, size band, and age band only.",
    },
    {
        "id": "protected-license-state",
        "label": "Protected license state",
        "scope_id": "windows-user",
        "purpose": "Keep the signed license receipt, active rank, anonymous seat state, and service sync result available locally.",
        "protection": "Windows DPAPI ciphertext inside the settings container.",
        "retention": "Until the license is removed from this PC, local state is cleared, or app data is restored.",
        "customer_action": "Use License Center to remove or refresh the local license state.",
        "default_state": "Optional; created after a license is saved or activated.",
        "desktop_inventory": "Configured or not configured only. The key, receipt, identity, and ciphertext are never exported.",
    },
    {
        "id": "owner-access-controls",
        "label": "Owner and local-control access",
        "scope_id": "windows-user",
        "purpose": "Remember the owner USB policy and the separate Local Control PIN verifier.",
        "protection": "Owner policy uses Windows DPAPI. The Local Control PIN is stored as a protected salted scrypt verifier, never as the PIN.",
        "retention": "Until the owner policy or Local Control PIN is deliberately changed or removed.",
        "customer_action": "Change these controls only from their local desktop settings and keep the USB separate.",
        "default_state": "Optional; absent until configured.",
        "desktop_inventory": "Configured control count only. No USB identity, PIN, salt, verifier, or policy bytes are exported.",
    },
    {
        "id": "audit-ledger",
        "label": "Audit ledger and integrity key",
        "scope_id": "windows-user",
        "purpose": "Record bounded app actions, UTC times, success or failure, anonymous event IDs, and hash-chain fields.",
        "protection": "HMAC-SHA-256 chain with a Windows DPAPI-protected local integrity key.",
        "retention": "Rotated to a bounded set of local audit files; reviewed exports are separate explicit actions.",
        "customer_action": "Use Audit Log Viewer to verify the chain and review a privacy-safe export before sharing.",
        "default_state": "Created when an auditable desktop action occurs.",
        "desktop_inventory": "Coarse storage bands and chain result only. No event body, path, filename, or content is copied into the data map.",
    },
    {
        "id": "personal-vault",
        "label": "Personal Vault",
        "scope_id": "windows-user",
        "purpose": "Store customer-entered private notes inside the separate local vault.",
        "protection": "AES-256-GCM authenticated encryption derived from the selected master key and optional PIN.",
        "retention": "Until the customer deletes vault items or removes the encrypted vault container.",
        "customer_action": "Back up the encrypted vault container and recovery material separately; never share an unlocked export casually.",
        "default_state": "Optional; created only when the Personal Vault is used.",
        "desktop_inventory": "Encrypted-container presence and coarse storage bands only. No item title or content is read.",
    },
    {
        "id": "recovery-history",
        "label": "Recovery and backup history",
        "scope_id": "windows-user",
        "purpose": "Keep fixed-ID Recovery Kit, Recovery Drill, and Backup Verification results and settings.",
        "protection": "Exact-schema tamper-evident hash chains for results; local Windows user permissions for fixed settings.",
        "retention": "Bounded local histories remain until deliberately removed or replaced during app-data restore.",
        "customer_action": "Verify chain integrity and export only reviewed fixed-ID summaries.",
        "default_state": "Optional; created after a result, checkpoint, or preference is saved.",
        "desktop_inventory": "Coarse storage bands and combined integrity result only.",
    },
    {
        "id": "health-baselines",
        "label": "Health and readiness baselines",
        "scope_id": "windows-user",
        "purpose": "Compare aggregate health counters and readiness state over time without keeping a file inventory.",
        "protection": "Fixed aggregate schema under the current Windows user.",
        "retention": "Until the baseline is replaced or cleared from its local center.",
        "customer_action": "Replace the baseline after a known-good review; investigate unexpected drift before clearing it.",
        "default_state": "Optional; created only after a baseline is saved.",
        "desktop_inventory": "Presence and coarse storage bands only. No locked-file names, paths, or key IDs are read.",
    },
    {
        "id": "temporary-workspace",
        "label": "Temporary unlocked workspace",
        "scope_id": "windows-user",
        "purpose": "Hold a short-lived local working copy only when the customer explicitly opens unlocked content.",
        "protection": "Current Windows user permissions plus bounded cleanup attempts and visible deletion status.",
        "retention": "Designed for deletion after use, on the cleanup timer, or through the explicit cleanup action.",
        "customer_action": "Close files after use and confirm temporary cleanup before leaving the PC unattended.",
        "default_state": "Normally empty; used only during explicit local unlock viewing.",
        "desktop_inventory": "Coarse count, size, and age bands only. No temporary filename or content is read.",
    },
    {
        "id": "app-backups",
        "label": "Customer-created app-data backups",
        "scope_id": "customer-selected",
        "purpose": "Preserve settings, audit records, vault data, and fixed recovery history for restoration.",
        "protection": "Protection depends on the customer-selected destination; master-key files are deliberately excluded.",
        "retention": "Controlled by the customer and any reviewed backup policy.",
        "customer_action": "Keep independent protected copies and verify restore structure without sharing the path here.",
        "default_state": "Created only after an explicit backup action and destination choice.",
        "desktop_inventory": "Not searched or inventoried. The customer may choose storage outside VaultLink app data.",
    },
    {
        "id": "update-owner-lab",
        "label": "Update, rollback, and owner-lab records",
        "scope_id": "windows-user",
        "purpose": "Keep update status, rollback app files, and owner-only candidate verification evidence.",
        "protection": "Local Windows user permissions; signing secrets stay Windows-protected and outside customer packages.",
        "retention": "Rollback and private lab runtimes are bounded by their local maintenance rules.",
        "customer_action": "Use Update Center or Owner Update Lab instead of manually mixing these files with customer data.",
        "default_state": "Created during update checks, installations, or private owner testing.",
        "desktop_inventory": "Coarse storage bands only. Package entries, repository locations, and signing material are excluded.",
    },
    {
        "id": "usb-master-key",
        "label": "USB master-key files",
        "scope_id": "removable-media",
        "purpose": "Provide the secret material required to derive encryption keys for portable locked containers.",
        "protection": "Customer-controlled removable storage and physical custody. VaultLink does not upload key bytes.",
        "retention": "Controlled by the key holder and recovery-custody plan.",
        "customer_action": "Keep independent copies separate from locked data and test only with disposable content.",
        "default_state": "Created only by an explicit key action on a chosen drive.",
        "desktop_inventory": "Never searched. The local receipt records only this fixed boundary description.",
    },
    {
        "id": "locked-containers",
        "label": "Customer-selected locked containers",
        "scope_id": "customer-selected",
        "purpose": "Hold files or folders encrypted into portable authenticated containers where the customer chooses.",
        "protection": "AES-256-GCM authenticated encryption using the master key and optional PIN.",
        "retention": "Controlled by the customer; originals are removed only after a separate explicit confirmation.",
        "customer_action": "Keep verified independent copies and preserve originals during recovery tests.",
        "default_state": "Created only after an explicit local lock action and destination choice.",
        "desktop_inventory": "Never searched by Data Control Center. No path, filename, count, or content is collected.",
    },
    {
        "id": "explicit-api-records",
        "label": "Explicit API records",
        "scope_id": "explicit-api",
        "purpose": "Support licensing, anonymous device seats, owner messages, support tickets, and approved audit exports.",
        "protection": "Signed tokens, encrypted private fields, admin-header controls, scoped downloads, and server retention limits.",
        "retention": "Depends on the record type and configured server storage; public documentation states the current boundary.",
        "customer_action": "Use License Center, Bug Center, and reviewed audit export controls; remove device or local license state when appropriate.",
        "default_state": "Created only by activation, support submission, announcement delivery, or approved audit upload.",
        "desktop_inventory": "No server record is downloaded into this map. Only the fixed public description is shown.",
    },
    {
        "id": "public-service-metadata",
        "label": "Public service and release metadata",
        "scope_id": "public-service",
        "purpose": "Publish product, rank, service, privacy, security, and signed-release status to every customer.",
        "protection": "Public read-only responses with no customer record or license proof.",
        "retention": "Updated with service configuration and signed releases.",
        "customer_action": "Use the public status, trust, privacy, and update pages to verify current claims.",
        "default_state": "Always public while the API is available.",
        "desktop_inventory": "Public metadata only. It cannot inspect or control the customer PC.",
    },
]


DATA_FLOW_STEPS = [
    {"id": "choose-action", "label": "Choose a local action", "detail": "Nothing is locked, unlocked, backed up, or submitted until the customer starts a visible action."},
    {"id": "keep-secrets-local", "label": "Keep secrets local", "detail": "Master-key bytes, optional PINs, vault contents, and unlocked file contents stay in the desktop process."},
    {"id": "store-by-scope", "label": "Store by scope", "detail": "Known app data stays in the Windows user profile; USB keys and locked containers remain where the customer chooses."},
    {"id": "record-coarse-audit", "label": "Record coarse audit evidence", "detail": "The local ledger records bounded action metadata and hash-chain fields, not keystrokes or file contents."},
    {"id": "submit-explicitly", "label": "Submit only explicitly", "detail": "Licensing, support, announcements, and approved audit uploads use separate visible API actions."},
    {"id": "review-before-sharing", "label": "Review before sharing", "detail": "Exports are created locally and should be reviewed because even category presence can be sensitive."},
]


def fixed_data_scopes():
    return json.loads(json.dumps(DATA_SCOPES))


def fixed_data_classes():
    return json.loads(json.dumps(DATA_CLASSES))


def fixed_data_flow_steps():
    return json.loads(json.dumps(DATA_FLOW_STEPS))


if len(DATA_SCOPES) != 5 or len(DATA_CLASSES) != 14 or len(DATA_FLOW_STEPS) != 6:
    raise RuntimeError("The fixed Data Control catalog cardinality changed unexpectedly.")

if len({item["id"] for item in DATA_CLASSES}) != len(DATA_CLASSES):
    raise RuntimeError("Data Control class IDs must be unique.")

if any(item["scope_id"] not in {scope["id"] for scope in DATA_SCOPES} for item in DATA_CLASSES):
    raise RuntimeError("Every Data Control class must use a fixed scope.")
